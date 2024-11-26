import os
from cryptography.fernet import Fernet

KEY_FILE = 'encryption_key.key'


def store_key(key):
    """
    Store the encryption key in a file securely.
    """
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)


def retrieve_key():
    """
    Retrieve the encryption key from the file.
    """
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError("Key file not found. Please generate and store a key first.")

    with open(KEY_FILE, 'rb') as key_file:
        key = key_file.read()
    return key


def generate_and_store_key():
    """
    Generate a new encryption key and store it securely.
    """
    key = Fernet.generate_key()
    store_key(key)
    print(f"Key generated and stored in {KEY_FILE}")

# Example usage
if __name__ == "__main__":
    # Generate and store a new key
    generate_and_store_key()

    # Retrieve the stored key
    key = retrieve_key()
    print(f"Retrieved Key: {key.decode()}")
