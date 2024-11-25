import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hmac
from base64 import urlsafe_b64encode, urlsafe_b64decode
import hashlib
import os
import argparse
import zlib

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

# Function to derive a key from a password
def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt data with multiple layers
def encrypt_multi_layer(data, password):
    # Generate salt
    salt = os.urandom(16)
    # Derive key from password
    key = derive_key_from_password(password, salt)
    # First layer encryption with AES
    encrypted_data = encrypt_aes(data, key)
    # Second layer encryption with ChaCha20
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    multi_layer_encrypted_data = encryptor.update(encrypted_data) + encryptor.finalize()
    return salt + nonce + multi_layer_encrypted_data

# Function to decrypt data with multiple layers
def decrypt_multi_layer(ciphertext, password):
    # Extract salt and nonce
    salt = ciphertext[:16]
    nonce = ciphertext[16:32]
    multi_layer_encrypted_data = ciphertext[32:]
    # Derive key from password
    key = derive_key_from_password(password, salt)
    # First layer decryption with ChaCha20
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    encrypted_data = decryptor.update(multi_layer_encrypted_data) + decryptor.finalize()
    # Second layer decryption with AES
    return decrypt_aes(encrypted_data, key)

# Function to calculate HMAC for integrity check
def calculate_hmac(data, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

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

# Function to compress data before encryption
def compress_data(data):
    return zlib.compress(data)

# Function to decompress data after decryption
def decompress_data(data):
    return zlib.decompress(data)

# Function to encrypt data with additional RSA layer
def encrypt_with_rsa_layer(data, public_key):
    # Encrypt the AES key with RSA
    encrypted_key = encrypt_rsa(public_key, data)
    return encrypted_key

# Function to decrypt data with additional RSA layer
def decrypt_with_rsa_layer(encrypted_key, private_key):
    # Decrypt the AES key with RSA
    decrypted_key = decrypt_rsa(private_key, encrypted_key)
    return decrypted_key

# Main function to handle command-line arguments
def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files using enhanced multi-layer encryption.")
    parser.add_argument('mode', choices=['encrypt', 'decrypt'], help="Mode of operation.")
    parser.add_argument('input_file', help="Input file to be processed.")
    parser.add_argument('output_file', help="Output file after processing.")
    parser.add_argument('--password', help="Password for key derivation.", required=True)
    parser.add_argument('--rsa-private-key', help="Path to RSA private key for decryption.", required=False)
    parser.add_argument('--rsa-public-key', help="Path to RSA public key for encryption.", required=False)
    args = parser.parse_args()

    with open(args.input_file, 'rb') as f:
        data = f.read()

    if args.mode == 'encrypt':
        # Compress data
        compressed_data = compress_data(data)
        # Encrypt with multi-layer
        encrypted_data = encrypt_multi_layer(compressed_data, args.password)
        # Encrypt AES key with RSA if public key is provided
        if args.rsa_public_key:
            with open(args.rsa_public_key, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
            encrypted_data = encrypt_with_rsa_layer(encrypted_data, public_key)
        hmac_value = calculate_hmac(encrypted_data, args.password.encode())
        with open(args.output_file, 'wb') as f:
            f.write(hmac_value + encrypted_data)
        print(f"File {args.input_file} encrypted to {args.output_file}.")
    elif args.mode == 'decrypt':
        hmac_value = data[:32]
        encrypted_data = data[32:]
        calculated_hmac = calculate_hmac(encrypted_data, args.password.encode())
        if hmac_value != calculated_hmac:
            print("Integrity check failed. The file may have been tampered with.")
            return
        # Decrypt AES key with RSA if private key is provided
        if args.rsa_private_key:
            with open(args.rsa_private_key, 'rb') as key_file:
                private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
            encrypted_data = decrypt_with_rsa_layer(encrypted_data, private_key)
        # Decrypt with multi-layer
        decrypted_data = decrypt_multi_layer(encrypted_data, args.password)
        # Decompress data
        decompressed_data = decompress_data(decrypted_data)
        with open(args.output_file, 'wb') as f:
            f.write(decompressed_data)
        print(f"File {args.input_file} decrypted to {args.output_file}.")

if __name__ == "__main__":
    main()
