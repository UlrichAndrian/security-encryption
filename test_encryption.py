import os
from encryption_tool import encrypt_file, decrypt_file

# Test key (for demonstration purposes)
TEST_KEY = b'test_key_12345678'  # Ensure this matches the expected key length

# Create a sample file to test encryption and decryption
def create_sample_file(filename):
    with open(filename, 'w') as f:
        f.write("This is a test file for encryption and decryption.")

# Test the encryption and decryption process
def test_encryption_decryption():
    sample_file = 'sample_test.txt'
    encrypted_file = 'sample_test.enc'
    decrypted_file = 'sample_test.dec'

    # Create a sample file
    create_sample_file(sample_file)

    # Encrypt the sample file
    encrypt_file(sample_file, encrypted_file, TEST_KEY)
    print(f"Encrypted {sample_file} to {encrypted_file}")

    # Decrypt the encrypted file
    decrypt_file(encrypted_file, decrypted_file, TEST_KEY)
    print(f"Decrypted {encrypted_file} to {decrypted_file}")

    # Verify the decrypted content
    with open(decrypted_file, 'r') as f:
        content = f.read()
        assert content == "This is a test file for encryption and decryption.", "Decryption failed!"
        print("Decryption verified successfully.")

    # Clean up test files
    os.remove(sample_file)
    os.remove(encrypted_file)
    os.remove(decrypted_file)

# Run the test
test_encryption_decryption()
