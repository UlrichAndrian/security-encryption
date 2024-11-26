from security_utils import generate_random_password, generate_key, encrypt_message, decrypt_message


def main():
    # Generate a random password
    password = generate_random_password()
    print(f"Generated Password: {password}")

    # Generate an encryption key
    key = generate_key()
    print(f"Generated Key: {key.decode()}")

    # Message to encrypt
    message = "This is a secret message."
    print(f"Original Message: {message}")

    # Encrypt the message
    encrypted_message = encrypt_message(message, key)
    print(f"Encrypted Message: {encrypted_message}")

    # Decrypt the message
    decrypted_message = decrypt_message(encrypted_message, key)
    print(f"Decrypted Message: {decrypted_message}")


if __name__ == "__main__":
    main()
