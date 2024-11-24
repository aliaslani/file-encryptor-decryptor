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


def decrypt_key(encrypted_key, password="password1234"):
    """
    Decrypt the encryption key using a password.
    """
    salt = encrypted_key[:16]
    derived_key = derive_key(password, salt)
    fernet = Fernet(derived_key)
    return fernet.decrypt(encrypted_key[16:])


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


def decrypt_file(encrypted_path, destination_path, fernet_instance):
    """
    Decrypts a file using the provided Fernet instance.

    Parameters:
    - encrypted_path (str): Path to the encrypted file.
    - destination_path (str): Path to save the decrypted file.
    - fernet_instance (Fernet): An instance of Fernet for decryption.
    """
    if not os.path.exists(encrypted_path):
        raise FileNotFoundError(f"Encrypted file '{encrypted_path}' not found.")

    try:
        with open(encrypted_path, "rb") as enc, open(destination_path, "wb") as dest:
            while chunk := enc.read(4096):  # Read file in chunks
                decrypted = fernet_instance.decrypt(chunk)
                dest.write(decrypted)
        print(f"File successfully decrypted and saved to '{destination_path}'")
    except Exception as e:
        raise IOError(f"Error during file decryption: {e}")


def main():
    """
    Main function to handle file encryption and decryption.
    """
    # File paths
    encrypted = "test.encrypted"  # Path for the encrypted file
    decrypted = "test.decrypted"  # Path for the decrypted file
    key_path = "encryption.key"  # Path to store/load the encryption key

    try:
        # Load the Fernet instance
        fernet = load_encryption_key(key_path)

        # Decrypt the file
        decrypt_file(encrypted, decrypted, fernet)
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    main()
