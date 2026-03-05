# things this fork changed

File overwrite / path traversal: The original program used filenames from the vault directly when decrypting, which could allow malicious files to overwrite important system files. In the fixed version, all filenames are passed through a sanitize_filename function, which extracts only the base name and rejects any path separators. This ensures decrypted files are saved safely in the current directory and cannot escape the vault.

Large file memory crash: Originally, the program loaded entire files into memory for encryption and decryption, which could crash the program with very large files. In the fixed version, a check_file_size function was added to reject files over 100 MB. This does not implement full streaming, but it prevents crashes or freezes due to extremely large files.

Weak password-hashing configuration: The original code used Argon2::default() for key derivation, which could be weak against brute-force attacks. The fixed version replaces this with an explicit Argon2id configuration: 64 MB memory cost, 3 iterations, 1 parallelism thread, and 32-byte output. This makes offline password guessing significantly harder without changing how the user interacts with the program.






# original readme follows 

# Encrypted File Vault

A secure command-line file encryption tool built in Rust, implementing AES-256-GCM encryption with Argon2 key derivation for password-based file protection.

## Features

- **AES-256-GCM Encryption** - Industry-standard authenticated encryption
- **Argon2 Key Derivation** - Memory-hard password hashing resistant to brute-force attacks
- **Password Confirmation** - Prevents accidental encryption with mistyped passwords
- **Memory Security** - Automatic password zeroing after use
- **Interactive CLI** - Simple numbered menu system for file selection
- **Organised Vault** - Encrypted files stored in dedicated vault directory
- **Authenticated Encryption** - Detects tampering and wrong passwords automatically

## Security Details

### Encryption Algorithm
- **Cipher**: AES-256-GCM (Galois/Counter Mode)
- **Key Size**: 256 bits
- **Authentication**: Built-in GCM authentication tag

### Key Derivation
- **Algorithm**: Argon2id (default configuration)
- **Salt Size**: 32 bytes (randomly generated per file)
- **Purpose**: Converts passwords into cryptographic keys whilst resisting GPU attacks

### File Format
Encrypted files use the following structure:
```
[32 bytes: Salt] + [12 bytes: Nonce] + [Variable: Ciphertext + Auth Tag]
```

## Installation

### Prerequisites
- Rust 1.70 or higher ([Install Rust](https://rustup.rs/))

### Building from Source

Clone the repository:
```bash
git clone https://github.com/harrymoorheadtaylor/Rust-File-Vault.git
cd Rust-File-Vault
```

Build the project:
```bash
cargo build --release
```

The compiled binary will be located at:
- `target/release/file_vault` (Linux/macOS)
- `target\release\file_vault.exe` (Windows)

### Alternative: Install Directly with Cargo
```
cargo install --git https://github.com/harrymoorheadtaylor/Rust-File-Vault
```

Once installed run it anywhere using:
```
file_vault
```

## Usage

Run the programme from the project directory:
```bash
cargo run
```

Or use the compiled binary directly:
```bash
./target/release/file_vault  # Linux/macOS
.\target\release\file_vault.exe  # Windows
```

### Menu Options

1. **Encrypt a file** - Select a file from the current directory to encrypt
2. **Decrypt a file** - Select an encrypted file from the vault to decrypt
3. **List encrypted files** - View all files currently in the vault
4. **Exit** - Close the programme

### Example Workflow

**Encrypting a file:**
```
=== Encrypt File ===

Available files:
  1. document.pdf
  2. secret.txt

Enter file number: 1
Enter password: 
Confirm password: 
Passwords match
Encrypting...

Encryption complete!
Encrypted file saved: vault/document.pdf.vault
Original file deleted
```

**Decrypting a file:**
```
=== Decrypt File ===

Encrypted files in vault:
  1. document.pdf.vault

Enter file number: 1
Enter password: 
Decrypting...

Decryption complete!
Decrypted file saved: document.pdf
Encrypted file deleted from vault
```

## Project Structure
```
Rust-File-Vault/
├── src/
│   └── main.rs          # Main application code
├── vault/               # Directory for encrypted files (created automatically)
├── Cargo.toml           # Project dependencies
├── Cargo.lock           # Dependency lock file
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

## Dependencies

- **aes-gcm** (0.10) - AES-256-GCM encryption implementation
- **argon2** (0.5) - Argon2 password hashing
- **rand** (0.8) - Cryptographically secure random number generation
- **rpassword** (7.3) - Secure password input without echo
- **zeroize** (1.7) - Secure memory zeroing for sensitive data

All cryptographic implementations are from the [RustCrypto](https://github.com/RustCrypto) project.

## Security Considerations

### Best Practices Implemented

- **Strong Encryption**: AES-256-GCM provides both confidentiality and authenticity
- **Secure Key Derivation**: Argon2 makes brute-force attacks computationally expensive
- **Memory Safety**: Rust's ownership system prevents memory-related vulnerabilities
- **Password Zeroing**: Sensitive data is explicitly cleared from memory after use
- **No Password Storage**: Passwords are never written to disk
- **Hidden Input**: Password entry doesn't display characters to prevent shoulder surfing

### User Responsibilities

- **Use strong, unique passwords** - Weak passwords compromise encryption strength
- **Keep passwords secure** - Lost passwords mean permanently lost data
- **Verify file integrity** - GCM authentication will detect tampering but cannot recover corrupted files

## Technical Implementation

### Why Rust?
- **Memory safety** without garbage collection overhead
- **Zero-cost abstractions** for cryptographic operations
- **Strong type system** prevents common security bugs
- **Industry adoption** for security-critical applications

### Why These Algorithms?

**AES-256-GCM:**
- NIST-approved standard
- Hardware acceleration on modern CPUs
- Provides both encryption and authentication
- Resistant to known attacks

**Argon2:**
- Winner of the Password Hashing Competition (2015)
- Memory-hard algorithm resistant to GPU/ASIC attacks
- Configurable time/memory trade-offs
- Recommended by OWASP

## Limitations

- Files must be small enough to fit in memory (both plaintext and ciphertext)
- Encrypted filenames reveal original filename and extension
- No password recovery mechanism
  
## Licence

MIT Licence - See LICENSE file for details

## Author

Harry Moorhead-Taylor - BSc Computer Science with Cyber Security, University of Liverpool

GitHub: [@harrymoorheadtaylor](https://github.com/harrymoorheadtaylor)

## Acknowledgements

- [RustCrypto](https://github.com/RustCrypto) for cryptographic implementations
