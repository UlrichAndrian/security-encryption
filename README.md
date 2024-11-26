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

3. Run the application:
   ```bash
   python encryption_tool.py
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

## GUI Application

In addition to the command-line tool, this project includes a graphical user interface (GUI) built with Tkinter. The GUI allows users to easily encrypt and decrypt files without needing to use the command line.

### GUI Features

- **User-Friendly Interface**: Simple and intuitive interface for encryption and decryption tasks.
- **File Selection Dialogs**: Easily select files and directories for encryption or decryption.
- **Password Protection**: Secure your files with password-based encryption.

### Running the GUI

To run the GUI application, execute the following command:

```bash
python encryption_gui.py
```

Ensure that all dependencies are installed as listed in `requirements.txt`.

## Testing

To run the tests, use:
```bash
pytest
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
