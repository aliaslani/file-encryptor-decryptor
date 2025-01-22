import base64
import hashlib
import json
import os
from typing import Dict

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from loguru import logger


class SecureFileDecryptor:
    """Handles file decryption with enhanced security measures"""

    CHUNK_SIZE = 64 * 1024  # 64KB chunks for memory efficiency
    IV_SIZE = 12  # GCM recommended IV size
    MIN_KEY_SIZE = 2048  # Minimum RSA key size

    def __init__(self, public_key_path: str):
        """Initialize decryptor with public key validation."""
        self.public_key = self._load_and_validate_public_key(public_key_path)

    @staticmethod
    def _load_and_validate_public_key(key_path: str) -> rsa.RSAPublicKey:
        """Load and validate the public key."""
        try:
            with open(key_path, "rb") as key_file:
                key_data = key_file.read()
                if not key_data:
                    raise ValueError("Empty key file")
                key = serialization.load_pem_public_key(
                    key_data, backend=default_backend()
                )
                if not isinstance(key, rsa.RSAPublicKey):
                    raise ValueError("Key must be RSA public key")
                if key.key_size < SecureFileDecryptor.MIN_KEY_SIZE:
                    raise ValueError(
                        f"RSA key size must be at least {SecureFileDecryptor.MIN_KEY_SIZE} bits"
                    )
                return key
        except Exception as e:
            logger.error(f"Public key loading failed: {str(e)}")
            raise ValueError(f"Invalid public key: {str(e)}")

    def decrypt_file(
        self, encrypted_file_path: str, metadata: Dict, output_file_path: str
    ) -> str:
        try:
            if not os.path.exists(encrypted_file_path):
                raise FileNotFoundError("Encrypted file not found")

            # Use encoded key directly without derivation
            key = base64.b64decode(metadata["encoded_key"])
            iv = base64.b64decode(metadata["iv"])
            tag = base64.b64decode(metadata["tag"])

            with open(encrypted_file_path, "rb") as infile:
                file_iv = infile.read(self.IV_SIZE)
                if file_iv != iv:
                    raise ValueError("IV mismatch")

                encrypted_data = infile.read()
                content = encrypted_data[: -len(tag)]
                file_tag = encrypted_data[-len(tag) :]

                if file_tag != tag:
                    raise ValueError("Tag mismatch")

            cipher = Cipher(
                algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
            )
            decryptor = cipher.decryptor()

            with open(output_file_path, "wb") as outfile:
                decrypted = decryptor.update(content)
                outfile.write(decrypted)
                outfile.write(decryptor.finalize())

            return output_file_path

        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            if os.path.exists(output_file_path):
                os.remove(output_file_path)
            raise ValueError(f"Decryption failed: {str(e)}")

    def _load_metadata(self, metadata_path: str) -> Dict:
        """Load and validate metadata structure."""
        try:
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
            required_fields = {
                "iv",
                "salt",
                "tag",
                "encoded_key",
                "file_signature",
                "metadata_signature",
            }
            if not all(field in metadata for field in required_fields):
                raise ValueError("Missing required metadata fields")
            return metadata
        except Exception as e:
            raise ValueError(f"Failed to load metadata: {str(e)}")

    def _verify_metadata(self, metadata: Dict) -> bool:
        """Verify metadata signature with enhanced validation."""
        try:
            signature = base64.b64decode(metadata["metadata_signature"])
            unsigned_metadata = {
                k: v for k, v in metadata.items() if k != "metadata_signature"
            }
            metadata_bytes = json.dumps(
                unsigned_metadata, sort_keys=True, ensure_ascii=False
            ).encode("utf-8")

            self.public_key.verify(
                signature,
                metadata_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception as e:
            logger.error(f"Metadata verification failed: {str(e)}")
            return False

    def _verify_file_signature(self, file_path: str, metadata: Dict) -> bool:
        """Verify file signature with comprehensive checks."""
        try:
            iv = base64.b64decode(metadata["iv"])
            tag = base64.b64decode(metadata["tag"])
            salt = base64.b64decode(metadata["salt"])
            signature = base64.b64decode(metadata["file_signature"])

            hasher = hashlib.sha256()
            hasher.update(iv + salt)

            with open(file_path, "rb") as f:
                while chunk := f.read(self.CHUNK_SIZE):
                    hasher.update(chunk)
            hasher.update(tag)

            self.public_key.verify(
                signature,
                hasher.digest(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception as e:
            logger.error(f"File signature verification failed: {str(e)}")
            return False

    def _derive_key(self, base_key: bytes, salt: bytes) -> bytes:
        """Derive encryption key using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
            backend=default_backend(),
        )
        return kdf.derive(base_key)

    def _decrypt_file_content(
        self, input_path: str, output_path: str, key: bytes, metadata: Dict
    ) -> str:
        """Decrypt file content with enhanced validation."""
        iv = base64.b64decode(metadata["iv"])
        tag = base64.b64decode(metadata["tag"])

        try:
            cipher = Cipher(
                algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()
            )
            decryptor = cipher.decryptor()

            with open(input_path, "rb") as infile:
                # Skip the IV at the beginning
                infile.read(self.IV_SIZE)
                # Read encrypted content excluding the tag at the end
                encrypted_data = infile.read()
                content = encrypted_data[: -len(tag)]

            with open(output_path, "wb") as outfile:
                decrypted = decryptor.update(content)
                outfile.write(decrypted)
                outfile.write(decryptor.finalize())

            return output_path

        except Exception as e:
            self._secure_cleanup(output_path)
            logger.error(f"Decryption error details: {str(e)}")
            raise ValueError(f"Decryption failed: {str(e)}")

    @staticmethod
    def _secure_cleanup(file_path: str) -> None:
        """Securely remove failed decryption output."""
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            logger.error(f"Cleanup failed: {str(e)}")


# Example usage
if __name__ == "__main__":
    metadata_file_path = "metadata.json"
    encrypted_file_path = "encrypted.bin"
    decrypted_file_path = "decrypted.txt"
    public_key_path = "public_key.pem"

    decryptor = SecureFileDecryptor(public_key_path)

    with open(metadata_file_path, "r") as meta_file:
        metadata = json.load(meta_file)

    if not decryptor._verify_metadata(metadata):
        raise ValueError("Invalid metadata signature")

    if not decryptor._verify_file_signature(encrypted_file_path, metadata):
        raise ValueError("Invalid file signature")

    decryptor.decrypt_file(encrypted_file_path, metadata, decrypted_file_path)
