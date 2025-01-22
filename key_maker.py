from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.backends import default_backend
import base64
import os
import argparse
from loguru import logger


class AESKeyGenerator:
    """Utility class for generating and encoding AES keys"""

    @staticmethod
    def generate_key(key_size: int = 32) -> bytes:
        """
        Generate a random AES key

        Args:
            key_size: Size of key in bytes (32 for AES-256)

        Returns:
            bytes: Random AES key
        """
        return os.urandom(key_size)

    @staticmethod
    def encode_key(key: bytes) -> str:
        """
        Encode AES key as base64 string

        Args:
            key: AES key bytes

        Returns:
            str: Base64 encoded key
        """
        return base64.b64encode(key).decode("utf-8")

    @staticmethod
    def decode_key(encoded_key: str) -> bytes:
        """
        Decode base64 encoded key

        Args:
            encoded_key: Base64 encoded key string

        Returns:
            bytes: Decoded key bytes
        """
        return base64.b64decode(encoded_key)

    @staticmethod
    def validate_key(key: bytes) -> bool:
        """
        Validate that a key is suitable for AES

        Args:
            key: Key bytes to validate

        Returns:
            bool: True if key is valid
        """
        try:
            algorithms.AES(key)
            return True
        except ValueError:
            return False


def main():
    parser = argparse.ArgumentParser(description="Generate and encode AES key")
    parser.add_argument("--output", type=str, help="Output file for the encoded key")
    parser.add_argument(
        "--decode", type=str, help="Decode and validate an existing base64 key"
    )

    args = parser.parse_args()

    generator = AESKeyGenerator()

    if args.decode:
        # Decode and validate existing key
        try:
            key = generator.decode_key(args.decode)
            if generator.validate_key(key):
                logger.info("Key is valid for AES")
                logger.info(f"Key length: {len(key) * 8} bits")
            else:
                logger.error("Invalid key length for AES")
        except Exception as e:
            logger.error(f"Failed to decode key: {e}")
    else:
        # Generate new key
        key = generator.generate_key()
        encoded_key = generator.encode_key(key)

        if args.output:
            # Save to file
            with open(args.output, "w") as f:
                f.write(encoded_key)
            logger.info(f"Key saved to: {args.output}")
        else:
            # Print to console
            print("Generated AES key (base64 encoded):")
            print(encoded_key)


if __name__ == "__main__":
    main()
