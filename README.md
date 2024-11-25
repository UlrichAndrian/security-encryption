# Encryption Tool

This project is a command-line tool for encrypting and decrypting files using AES and RSA algorithms. It provides strong security for sensitive data and is designed to be simple to use.

## Features

- **AES Encryption**: Securely encrypt files with AES-256.
- **RSA Encryption**: Encrypt AES keys with RSA for added security.
- **SHA-256 Hashing**: Verify data integrity with SHA-256 hashes.
- **Command-Line Interface**: Easily encrypt and decrypt files via command-line arguments.

## Installation

1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd security
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

- **Encrypt a File**:
  ```bash
  python encryption_tool.py encrypt <input_file> <output_file> --key <optional_key_file>
  ```

- **Decrypt a File**:
  ```bash
  python encryption_tool.py decrypt <input_file> <output_file> --key <optional_key_file>
  ```

If no key file is specified, a new AES key will be generated and saved as `aes_key.key`.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
