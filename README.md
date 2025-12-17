# Secure File Encryption Tool

A command-line tool for encrypting and decrypting files using AES-256 encryption (Fernet cipher), with support for both key-based and password-based encryption modes.

## Features

- 🔐 **AES-256 Encryption** - File encryption using Python's Fernet cipher
- 🔑 **Dual Encryption Modes** - Key-based or password-based encryption
- 🛡️ **File Integrity Verification** - SHA-256 hashing to detect tampering
- 🔒 **Secure Password Handling** - PBKDF2 key derivation with 200,000 iterations
- 📦 **Efficient Processing** - Chunk-based reading for large files
- ✨ **User-Friendly CLI** - Clear error messages and intuitive interface

## Project Structure
```
secure-file-tool/
├── crypto.py          # Core encryption/hashing functions
├── crypto_cli.py      # Command-line interface
└── README.md          # This file
```

## Requirements
- **Python 3.9+**
- **cryptography library**

**Install dependencies**:
```powershell
pip install cryptography
```

## Security Features

- **PBKDF2 Key Derivation**: Converts passwords to encryption keys using 200,000 iterations
- **Unique Salt Generation**: Each encrypted file uses a unique random salt
- **Magic Bytes**: File format identification prevents decryption errors
- **SHA-256 Hashing**: Cryptographic hashing for file integrity verification

## Usage

### 1. Generate Encryption Key File
```powershell
python crypto_cli.py genkey --out mykey.key
```
Creates a new encryption key and saves it to my.key

### 2. Encrypt Files

**Using key file:**
```powershell
python crypto_cli.py encrypt --in document.pdf --out document.pdf.enc --key my.key
```

**Using password:**
```powershell
python crypto_cli.py encrypt --in document.pdf --out document.pdf.enc --password
# You'll be prompted to enter and confirm password
```

### 3. Decrypt Files

**Using key file:**
```powershell
python crypto_cli.py decrypt --in document.pdf.enc --out document.pdf --key mykey.key
```

**Using password:**
```powershell
python crypto_cli.py decrypt --in document.pdf.enc --out document.pdf --password
# You'll be prompted to enter password
```

### 4. Hash Files (Integrity Check)

**Generate hash:**
```powershell
python crypto_cli.py hash --in document.pdf
# Output: SHA-256: a3c5f9e2b1d4c8a7f6e5...
```

**Verify file integrity:**
```powershell
python crypto_cli.py verify --in document.pdf --hash a3c5f9e2b1d4c8a7f6e5...
# Output: ✅ File integrity verified
```

## Exit Codes
| Code | Meaning                                                   |
| ---- | --------------------------------------------------------- |
| `0`  | Success                                                   |
| `1`  | User / file error (missing file, invalid input)           |
| `2`  | Cryptographic failure (wrong key/password, tampered file) |

## Security Design Notes

### Password-based encryption
- Uses PBKDF2 (SHA-256, 200,000 iterations)
- Random 16-byte salt per file
- Salt stored alongside ciphertext
- Derived keys are Fernet-compatible

### File format (password mode)
```
[MAGIC][SALT][CIPHERTEXT]
```
- **MAGIC**: identifies password-encrypted files and version
- **SALT**: required to re-derive the key during decryption

No passwords are ever stored or logged

## Future Improvements
- Batch / directory encryption
- Web interface for easier use
- Cloud storage integration (AWS S3)
- File compression before encryption
- GUI application
- Integration into a secure file-sharing backend

## Author's Notes
Built this tool to understand cryptographic principles and secure file handling:
- Symmetric encryption
- Password-based key derivation
- Secure CLI design
- Cryptographic error handling