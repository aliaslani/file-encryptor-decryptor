import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from base64 import urlsafe_b64encode


def derive_key(password, salt):
    """
    Derive a key using PBKDF2HMAC with a password and a salt.
    """
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))


def generate_salt():
    """
    Generate a random 16-byte salt.
    """
    return os.urandom(16)


def encrypt_key(key, password="password1234"):
    """
    Encrypt the encryption key using a password.
    """
    salt = generate_salt()
    derived_key = derive_key(password, salt)
    fernet = Fernet(derived_key)
    return salt + fernet.encrypt(key)


def decrypt_key(encrypted_key, password="password1234"):
    """
    Decrypt the encryption key using a password.
    """
    salt = encrypted_key[:16]
    derived_key = derive_key(password, salt)
    fernet = Fernet(derived_key)
    return fernet.decrypt(encrypted_key[16:])


def generate_encryption_key(key_path="encryption.key"):
    """
    Generate and save a new encryption key to a file if it doesn't exist.
    Ensures the key is securely stored and reused across executions.
    """
    if not os.path.exists(key_path):
        key = Fernet.generate_key()
        with open(key_path, "wb") as key_file:
            key_file.write(encrypt_key(key))
        print(f"New encryption key generated and saved to '{key_path}'")
    else:
        print(f"Encryption key already exists at '{key_path}'")


def load_encryption_key(key_path="encryption.key"):
    """
    Load the encryption key from a secure file.
    Raises an exception if the key file is missing or unreadable.
    """
    if not os.path.exists(key_path):
        raise FileNotFoundError(
            f"Encryption key file '{key_path}' not found. Run generate_encryption_key() first."
        )
    try:
        with open(key_path, "rb") as key_file:
            return Fernet(decrypt_key(key_file.read()))
    except Exception as e:
        raise ValueError(f"Failed to load encryption key: {e}")


def encrypt_file(source_path, destination_path, fernet_instance):
    """
    Encrypts a file using the provided Fernet instance.

    Parameters:
    - source_path (str): Path to the source file to encrypt.
    - destination_path (str): Path to save the encrypted file.
    - fernet_instance (Fernet): An instance of Fernet for encryption.
    """
    if not os.path.exists(source_path):
        raise FileNotFoundError(f"Source file '{source_path}' not found.")

    try:
        with open(source_path, "rb") as src, open(destination_path, "wb") as dest:
            while chunk := src.read(4096):  # Read file in chunks
                encrypted = fernet_instance.encrypt(chunk)
                dest.write(encrypted)
        print(f"File successfully encrypted and saved to '{destination_path}'")
    except Exception as e:
        raise IOError(f"Error during file encryption: {e}")


def main():
    """
    Main function to handle file encryption and decryption.
    """
    # File paths
    source = "test.zip"  # Path to the file you want to encrypt
    encrypted = "test.encrypted"  # Path for the encrypted file
    key_path = "encryption.key"  # Path to store/load the encryption key

    # Generate encryption key if it doesn't exist
    if not os.path.exists(key_path):
        generate_encryption_key(key_path)

    try:
        # Load the Fernet instance
        fernet = load_encryption_key(key_path)

        # Encrypt the file
        encrypt_file(source, encrypted, fernet)

        # Decrypt the file
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
