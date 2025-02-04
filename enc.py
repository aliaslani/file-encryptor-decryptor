import os
import json
import base64
import hashlib
import shutil
from tempfile import TemporaryDirectory
import uuid
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from loguru import logger
from typing import Dict, Optional
import secrets
from pathlib import Path
from datetime import datetime
import pyzipper
from secrets import token_urlsafe
import ctypes
from environ import Env
import sys
import argparse

env = Env()
env.read_env()


def secure_string_cleanup(s: str):
    try:
        # Get the memory address of the string
        string_buffer = ctypes.create_string_buffer(s.encode())
        # Overwrite with zeros
        ctypes.memset(string_buffer, 0, len(string_buffer))
    except Exception:
        pass


class SecureFileEncryptor:
    """Handles file encryption and metadata signing with enhanced security"""

    CHUNK_SIZE = 64 * 1024 * 1024  # Reduced to 64MB for better memory management
    IV_SIZE = 12  # GCM recommended IV size
    SALT_SIZE = 32  # For key derivation
    MIN_KEY_SIZE = 2048  # Minimum RSA key size

    def __init__(self, private_key_path: str):
        """Initialize encryptor with private key validation."""
        self.private_key = self._load_and_validate_private_key(private_key_path)
        self._validate_security_requirements()

    def _validate_security_requirements(self) -> None:
        """Validate system security requirements."""
        if not hasattr(self.private_key, "key_size"):
            raise ValueError("Invalid key type")
        if self.private_key.key_size < self.MIN_KEY_SIZE:
            raise ValueError(f"RSA key size must be at least {self.MIN_KEY_SIZE} bits")

    @staticmethod
    def _load_and_validate_private_key(private_key_path: str) -> rsa.RSAPrivateKey:
        """Load and validate the private key."""
        try:
            with open(private_key_path, "rb") as key_file:
                key_data = key_file.read()
                if not key_data:
                    raise ValueError("Empty key file")
                key = serialization.load_pem_private_key(
                    key_data, password=None, backend=default_backend()
                )
                if not isinstance(key, rsa.RSAPrivateKey):
                    raise ValueError("Key must be RSA private key")
                return key
        except Exception as e:
            logger.error(f"Private key loading failed: {str(e)}")
            raise ValueError(f"Invalid private key: {str(e)}")

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key using PBKDF2."""
        base_key = os.urandom(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
            backend=default_backend(),
        )
        return kdf.derive(base_key)

    def encrypt_file(
        self,
        input_file_path: str,
        encrypted_file_path: str,
        metadata_file_path: str,
        overwrite: bool = False,
    ) -> None:
        """Encrypt file with enhanced security checks."""
        if not os.path.exists(input_file_path):
            raise FileNotFoundError(f"Input file not found: {input_file_path}")

        if os.path.exists(encrypted_file_path) and not overwrite:
            raise FileExistsError("Encrypted file already exists")

        salt = secrets.token_bytes(self.SALT_SIZE)
        aes_key = self._derive_key(salt)
        iv = secrets.token_bytes(self.IV_SIZE)

        with TemporaryDirectory(prefix="secure_") as temp_dir:
            temp_path = os.path.join(temp_dir, "temp_encrypted")
            try:
                tag = self._encrypt_to_temp_file(
                    input_file_path, temp_path, aes_key, iv
                )
                self._finalize_encryption(
                    temp_path,
                    encrypted_file_path,
                    metadata_file_path,
                    aes_key,
                    iv,
                    salt,
                    tag,
                )
            except Exception as e:
                logger.error(f"Encryption failed: {str(e)}")
                self._secure_cleanup(temp_path)
                raise

    def _encrypt_to_temp_file(
        self, input_path: str, temp_path: str, key: bytes, iv: bytes
    ) -> bytes:
        """Encrypt file with memory-efficient chunking."""
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        try:
            with open(input_path, "rb") as infile, open(temp_path, "wb") as outfile:
                outfile.write(iv)
                while True:
                    chunk = infile.read(self.CHUNK_SIZE)
                    if not chunk:
                        break
                    outfile.write(encryptor.update(chunk))
                outfile.write(encryptor.finalize())
                outfile.write(encryptor.tag)
                return encryptor.tag
        except Exception as e:
            self._secure_cleanup(temp_path)
            raise ValueError(f"Encryption failed: {str(e)}")

    def _finalize_encryption(
        self,
        temp_path: str,
        encrypted_path: str,
        metadata_path: str,
        key: bytes,
        iv: bytes,
        salt: bytes,
        tag: bytes,
    ) -> None:
        """Finalize encryption and save metadata securely."""
        try:
            signature = self._generate_signature(temp_path, iv, tag, salt)
            metadata = self._create_metadata(key, iv, signature, tag, salt)
            metadata_signature = self._sign_metadata(metadata)
            metadata["metadata_signature"] = base64.b64encode(
                metadata_signature
            ).decode("utf-8")

            # Atomic operations for file saving
            shutil.move(temp_path, encrypted_path)
            with open(metadata_path, "w") as meta_file:
                json.dump(metadata, meta_file, indent=4)
        except Exception as e:
            self._secure_cleanup(temp_path)
            raise ValueError(f"Finalization failed: {str(e)}")

    def _generate_signature(
        self, file_path: str, iv: bytes, tag: bytes, salt: bytes
    ) -> bytes:
        """Generate comprehensive file signature."""
        try:
            hasher = hashlib.sha256()
            hasher.update(iv + salt)
            with open(file_path, "rb") as f:
                while chunk := f.read(self.CHUNK_SIZE):
                    hasher.update(chunk)
            hasher.update(tag)
            return self._sign_data(hasher.digest())
        except Exception as e:
            raise ValueError(f"Signature generation failed: {str(e)}")

    @staticmethod
    def _secure_cleanup(file_path: Optional[str]) -> None:
        """Securely cleanup temporary files."""
        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, "wb") as f:
                    f.write(secrets.token_bytes(os.path.getsize(file_path)))
                os.remove(file_path)
            except Exception as e:
                logger.error(f"Secure cleanup failed: {str(e)}")

    def _create_metadata(
        self, key: bytes, iv: bytes, signature: bytes, tag: bytes, salt: bytes
    ) -> Dict:
        """Create comprehensive metadata."""
        return {
            "key_id": str(uuid.uuid4()),
            "iv": base64.b64encode(iv).decode("utf-8"),
            "salt": base64.b64encode(salt).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
            "encoded_key": base64.b64encode(key).decode("utf-8"),
            "file_signature": base64.b64encode(signature).decode("utf-8"),
            "created_at": datetime.now().isoformat(),
            "algorithm": "AES-256-GCM",
            "key_derivation": "PBKDF2-SHA256-600000",
        }

    def _sign_data(self, data: bytes) -> bytes:
        """Sign data with enhanced padding."""
        try:
            return self.private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except Exception as e:
            raise ValueError(f"Data signing failed: {str(e)}")

    def _sign_metadata(self, metadata: Dict) -> bytes:
        """Sign metadata with sorting and encoding validation."""
        try:
            metadata_bytes = json.dumps(
                metadata, sort_keys=True, ensure_ascii=False
            ).encode("utf-8")
            return self._sign_data(metadata_bytes)
        except Exception as e:
            raise ValueError(f"Metadata signing failed: {str(e)}")


class SecureFileEncryptorWithZip(SecureFileEncryptor):
    """Extends SecureFileEncryptor to create password-protected zip archives."""

    def encrypt_to_zip(
        self,
        input_file_path: str,
        zip_path: str,
        env_file_path: str,
        cleanup: bool = True,
    ) -> None:
        """Encrypt file and create AES-256 password-protected zip archive."""
        try:
            password = self._load_password_from_env(env_file_path)

            with TemporaryDirectory(prefix="secure_zip_") as temp_dir_str:
                temp_dir = Path(temp_dir_str)
                os.chmod(temp_dir, 0o700)  # Secure directory permissions

                encrypted_file = temp_dir / "encrypted.bin"
                metadata_file = temp_dir / "metadata.json"

                # Validate input file existence
                if not Path(input_file_path).is_file():
                    raise FileNotFoundError(
                        f"Input file does not exist: {input_file_path}"
                    )

                # Validate output directory
                zip_dir = Path(zip_path).parent
                if not zip_dir.exists() or not os.access(zip_dir, os.W_OK):
                    raise PermissionError(
                        f"No write permission for output directory: {zip_dir}"
                    )

                # Encrypt file
                self.encrypt_file(
                    input_file_path=input_file_path,
                    encrypted_file_path=str(encrypted_file),
                    metadata_file_path=str(metadata_file),
                )

                # Create AES-256 password-protected zip
                self._create_protected_zip(
                    zip_path, password, encrypted_file, metadata_file
                )

                # Set secure permissions on zip file
                os.chmod(zip_path, 0o600)  # Only owner can read/write

                logger.info(f"Encrypted zip created: {zip_path}")

        except Exception as e:
            logger.exception("Zip creation failed")
            if os.path.exists(zip_path):
                os.unlink(zip_path)  # Remove failed zip file
            raise ValueError(f"Failed to create encrypted zip: {str(e)}")

        finally:
            if cleanup:
                self._secure_cleanup(temp_dir)

    def _load_password_from_env(self, env_file_path: str) -> str:
        """Load encryption password from .env file."""
        if not Path(env_file_path).is_file():
            raise FileNotFoundError(f"Environment file not found: {env_file_path}")

        env.read_env(env_file_path)
        password = os.getenv("ENCRYPTION_PASSWORD")

        if not password or len(password) < 16:
            raise ValueError(
                "ENCRYPTION_PASSWORD must be at least 16 characters long in the .env file"
            )

        return password

    def _create_protected_zip(self, zip_path: str, password: str, *files: Path):
        """Create an AES-256 password-protected ZIP archive."""
        with pyzipper.AESZipFile(zip_path, "w", compression=pyzipper.ZIP_LZMA) as zf:
            zf.setpassword(password.encode())
            zf.setencryption(pyzipper.WZ_AES, nbits=256)

            for file in files:
                if not file.exists():
                    raise FileNotFoundError(f"Missing file for ZIP: {file}")
                zf.write(file, file.name)

        if not Path(zip_path).is_file():
            raise RuntimeError("Zip file creation failed")

    def _secure_cleanup(self, temp_dir: Path):
        """Securely clean up temporary files by overwriting before deletion."""
        if temp_dir and temp_dir.exists():
            for file in temp_dir.glob("*"):
                try:
                    with open(file, "wb") as f:
                        f.write(
                            os.urandom(os.path.getsize(file))
                        )  # Overwrite before deletion
                    file.unlink()
                except Exception as e:
                    logger.warning(f"Failed to securely delete {file}: {e}")
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure File Encryption with Zip")
    parser.add_argument("--input_file", type=str, required=True, help="Input file path")
    parser.add_argument(
        "--key", type=str, default="rsa_key.pem", help="Path to RSA key file"
    )
    parser.add_argument(
        "--env_file",
        type=str,
        required=True,
        help="Path to .env file containing ENCRYPTION_PASSWORD",
    )

    args = parser.parse_args()

    input_file = args.input_file
    key_file = args.key
    env_file = args.env_file
    zip_file = f"{input_file}.zip"

    encryptor = SecureFileEncryptorWithZip(key_file)

    try:
        encryptor.encrypt_to_zip(input_file, zip_file, env_file)
        print(f"\n✅ Encryption successful!\n📦 Zip File: {zip_file}")
    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)
