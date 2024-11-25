import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from base64 import urlsafe_b64encode, urlsafe_b64decode
import hashlib
import os
import argparse

# Function to generate an RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt data with AES
def encrypt_aes(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return iv + ct

# Function to decrypt data with AES
def decrypt_aes(ciphertext, key):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

# Function to encrypt data with RSA
def encrypt_rsa(public_key, data):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Function to decrypt data with RSA
def decrypt_rsa(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Function to hash data using SHA-256
def hash_data_sha256(data):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()

# Function to encrypt a file with AES
def encrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        data = f.read()
    encrypted_data = encrypt_aes(data, key)
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

# Function to decrypt a file with AES
def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = decrypt_aes(encrypted_data, key)
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

# Main function to handle command-line arguments
def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files using AES and RSA.")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help="Mode of operation.")
    parser.add_argument('input_file', help="Input file to be processed.")
    parser.add_argument('output_file', help="Output file after processing.")
    parser.add_argument('--key', help="File containing the AES key.", required=False)
    args = parser.parse_args()

    # Generate or load AES key
    if args.key:
        with open(args.key, 'rb') as f:
            aes_key = f.read()
    else:
        aes_key = os.urandom(32)  # AES-256 key
        with open('aes_key.key', 'wb') as f:
            f.write(aes_key)

    if args.mode == 'encrypt':
        encrypt_file(args.input_file, args.output_file, aes_key)
        print(f"File {args.input_file} encrypted to {args.output_file}.")
    elif args.mode == 'decrypt':
        decrypt_file(args.input_file, args.output_file, aes_key)
        print(f"File {args.input_file} decrypted to {args.output_file}.")

if __name__ == "__main__":
    main()
