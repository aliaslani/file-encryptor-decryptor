from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import os
import argparse
from typing import Tuple
from pathlib import Path
import sys
from loguru import logger


class KeyGenerator:
    """Utility class for generating and managing RSA key pairs"""

    def __init__(self, key_size: int = 4096):
        """
        Initialize key generator with specified key size

        Args:
            key_size: Size of RSA key in bits (default: 4096)
        """
        self.key_size = key_size

    def generate_key_pair(self) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate a new RSA key pair

        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=self.key_size, backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def save_private_key(
        self, private_key: rsa.RSAPrivateKey, path: str, password: str = None
    ):
        """
        Save private key to file, optionally encrypted with password

        Args:
            private_key: RSA private key to save
            path: Path to save the key
            password: Optional password to encrypt the key
        """
        encryption_algorithm = (
            serialization.BestAvailableEncryption(password.encode())
            if password
            else serialization.NoEncryption()
        )

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )

        with open(path, "wb") as f:
            f.write(pem)

        # Set restrictive permissions on private key
        os.chmod(path, 0o600)

    def save_public_key(self, public_key: rsa.RSAPublicKey, path: str):
        """
        Save public key to file

        Args:
            public_key: RSA public key to save
            path: Path to save the key
        """
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with open(path, "wb") as f:
            f.write(pem)

    @staticmethod
    def test_key_pair(
        private_key_path: str, public_key_path: str, password: str = None
    ) -> bool:
        """
        Test a key pair by performing a test encryption/signature

        Args:
            private_key_path: Path to private key
            public_key_path: Path to public key
            password: Optional password for encrypted private key

        Returns:
            bool: True if test succeeds
        """
        try:
            # Load keys
            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password.encode() if password else None,
                    backend=default_backend(),
                )

            with open(public_key_path, "rb") as f:
                public_key = serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )

            # Test data
            test_data = b"Test message for key verification"

            # Sign with private key
            signature = private_key.sign(
                test_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            # Verify with public key
            public_key.verify(
                signature,
                test_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            return True

        except Exception as e:
            logger.error(f"Key pair test failed: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Generate RSA key pair for file encryption"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./keys",
        help="Directory to store generated keys",
    )
    parser.add_argument(
        "--key-size", type=int, default=4096, help="RSA key size in bits"
    )
    parser.add_argument(
        "--private-key-password",
        type=str,
        help="Password to encrypt private key (optional)",
    )

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate keys
    generator = KeyGenerator(key_size=args.key_size)
    private_key, public_key = generator.generate_key_pair()

    # Save keys
    private_key_path = output_dir / "private_key.pem"
    public_key_path = output_dir / "public_key.pem"

    generator.save_private_key(
        private_key, str(private_key_path), args.private_key_password
    )
    generator.save_public_key(public_key, str(public_key_path))

    logger.info(f"Private key saved to: {private_key_path}")
    logger.info(f"Public key saved to: {public_key_path}")

    # Test the generated keys
    if generator.test_key_pair(
        str(private_key_path), str(public_key_path), args.private_key_password
    ):
        logger.info("Key pair successfully generated and verified!")
    else:
        logger.error("Key pair verification failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
