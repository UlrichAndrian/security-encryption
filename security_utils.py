import secrets
import string
from cryptography.fernet import Fernet


def generate_random_password(length=12):
    """
    Generate a secure random password with the given length.
    The password will contain letters, digits, and punctuation.
    """
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password


def generate_key():
    """
    Generate a key for encryption and decryption.
    This key should be kept secret.
    """
    return Fernet.generate_key()


def encrypt_message(message, key):
    """
    Encrypt a message using the provided key.
    """
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message


def decrypt_message(encrypted_message, key):
    """
    Decrypt an encrypted message using the provided key.
    """
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message).decode()
    return decrypted_message
