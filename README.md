# Encryption Tool

This project is a command-line tool for encrypting and decrypting files using AES, ChaCha20, and RSA algorithms. It provides strong security for sensitive data and is designed to be simple to use.

## Features

- **Multi-layer Encryption**: Securely encrypt files with multiple layers using AES and ChaCha20.
- **RSA Encryption**: Optionally encrypt AES keys with RSA for enhanced security.
- **Data Compression**: Compress data before encryption to reduce size and obscure patterns.
- **SHA-256 Hashing**: Verify data integrity with SHA-256 hashes.
- **Command-Line Interface**: Easily encrypt and decrypt files via command-line arguments.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/UlrichAndrian/security-encryption.git
   cd security-encryption
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

- **Encrypt a File**:
  ```bash
  python encryption_tool.py encrypt <input_file> <output_file> --password <your_password> --rsa-public-key <path_to_rsa_public_key>
  ```

- **Decrypt a File**:
  ```bash
  python encryption_tool.py decrypt <input_file> <output_file> --password <your_password> --rsa-private-key <path_to_rsa_private_key>
  ```

If no RSA keys are specified, the tool will proceed with multi-layer encryption using the provided password.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
