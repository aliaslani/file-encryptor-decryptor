import pyzipper
from pathlib import Path
import sys

def extract_zip(zip_path: str, extract_to: str, password: str) -> None:
    """
    Extracts a password-protected zip file created with AES encryption.

    Args:
        zip_path (str): Path to the zip file.
        extract_to (str): Directory to extract the files into.
        password (str): Password for the zip file.

    Raises:
        ValueError: If extraction fails due to an incorrect password or other errors.
        FileNotFoundError: If the zip file does not exist.
    """
    zip_file_path = Path(zip_path)
    output_dir = Path(extract_to)

    if not zip_file_path.exists():
        raise FileNotFoundError(f"Zip file not found: {zip_file_path}")

    try:
        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)

        # Open and extract zip
        with pyzipper.AESZipFile(zip_file_path, 'r') as zip_file:
            zip_file.pwd = password.encode()
            zip_file.extractall(path=output_dir)
        print(f"Extraction successful. Files are in: {output_dir}")

    except pyzipper.BadZipFile:
        raise ValueError("The file is not a valid zip file.")
    except RuntimeError as e:
        raise ValueError(f"Failed to extract zip file: {e}")
    except pyzipper.LargeZipFile:
        raise ValueError("The zip file is too large to extract.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python decompress.py <zip_path> <extract_to> <password>")
        sys.exit(1)

    zip_path = sys.argv[1]
    extract_to = sys.argv[2]
    password = sys.argv[3]

    try:
        extract_zip(zip_path, extract_to, password)
    except Exception as e:
        print(f"Error: {e}")

