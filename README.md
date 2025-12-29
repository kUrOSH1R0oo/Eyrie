# Eyrie Password Manager

Eyrie is a secure, CLI (Soon to be GUI) password manager written in Python. It provides robust encryption, two-factor authentication (2FA), password generation, and comprehensive credential management. Designed for security-conscious users, Eyrie stores passwords in an encrypted vault file (`.eyr` format) and emphasizes usability through an interactive CLI interface.

## Goal

The primary goal of Eyrie is to provide a lightweight, self-contained password manager that prioritizes security without relying on cloud services or external databases. It aims to empower users to manage sensitive credentials securely on their local machine, with features like encrypted backups, password history tracking, and 2FA to prevent unauthorized access. Eyrie bridges the gap between simple text-based storage and enterprise-grade tools, making it ideal for developers, sysadmins, and privacy-focused individuals.

## Features

- **Secure Vault Storage**: Passwords are stored in a custom encrypted `.eyr` file format with integrity checks.
- **Encryption**: Uses Argon2id for key derivation, AES-GCM for symmetric encryption, and HMAC-SHA256 for authentication.
- **Two-Factor Authentication (2FA)**: TOTP-based 2FA with recovery codes and trusted device support.
- **Password Generation**: Cryptographically secure random passwords with customizable options (length, character sets, exclusions).
- **Password History**: Tracks changes to passwords for auditing and reuse prevention.
- **Interactive CLI**: Command-line interface with auto-completion, history, and secure input prompts.
- **Export/Import**: Encrypted backups with separate backup passwords.
- **Validation**: Strong password requirements, entropy checks, and breach detection simulation.
- **Clipboard Integration**: Secure copying of passwords with auto-clear timeout.
- **Vault Management**: Change master password, view vault stats, and lock sessions.

## Benefits

- **Enhanced Security**: All data is encrypted at rest. No plaintext storage. Memory is securely erased after use.
- **Offline Operation**: No internet required, reducing attack surface.
- **Portability**: Single vault file can be backed up or moved easily.
- **Auditability**: Password history helps detect reuse or patterns.
- **User-Friendly**: Interactive mode with help menus and validators simplifies usage.
- **Customizable**: Adjustable password strength, categories, and 2FA settings.
- **Cost-Free**: Open-source alternative to paid managers like LastPass or 1Password.
- **Privacy**: Local storage ensures no third-party access to your data.

## Uniqueness

Unlike mainstream password managers (e.g., Bitwarden or KeePass), Eyrie stands out with:
- **Custom File Format (.eyr)**: A binary format with built-in compression, indexing, and metadata for efficient storage and retrieval.
- **Integrated 2FA Management**: Seamless setup with QR code display in terminal using ASCII art.
- **Password Reuse Detection**: Warns during updates if a new password matches history.
- **Secure Erase**: Explicit memory sanitization for keys and sensitive data.
- **Minimal Dependencies**: Relies on Python standard libraries where possible, with optional third-party for UI enhancements.
- **Terminal-Centric Design**: Full-featured CLI with key bindings and auto-suggest.
- **Backup Scheduling**: Configurable automated backups with retention policies.

Eyrie focuses on cryptographic best practices (e.g., constant-time comparisons, memory-hard KDF) while keeping the codebase modular and extensible.

## Installation

Eyrie requires Python 3.8+ and the following dependencies:

- `prompt_toolkit`: For interactive prompts and auto-completion.
- `pyperclip`: For secure clipboard operations.
- `qrcode`: For generating ASCII QR codes for 2FA.
- `email_validator`: For email format validation.
- `cryptography`: For cryptographic primitives (Argon2id, AES-GCM, HKDF).

Install via pip:

```bash
pip3 install -r requirements.txt
```

Clone the repository:

```bash
git clone https://github.com/kUrOSH1R0oo/Eyrie.git
cd Eyrie
```

Run the main script:

```bash
python3 eyrie.py --help
```

## Executables

Precompiled binaries are available in the **GitHub Releases** section:

- **Windows:** Download the `.exe` version of Eyrie from [here](https://github.com/kUrOSH1R0oo/Eyrie/releases/download/v1.0.1/eyrie.exe).
- **Linux:** Download the `ELF` binary from [here](https://github.com/kUrOSH1R0oo/Eyrie/releases/download/v1.0.1/eyrie).

## Usage

Eyrie supports both command-line arguments and an interactive shell.

## Command-Line
Basic commands:
- Create Vault:

```bash
python3 eyrie.py init --vault vault.eyr
```

- Unlock Vault

```bash
python3 eyrie.py unlock --vault vault.eyr
```

- Generate Password:

```bash
python3 eyrie.py generate --length 16
```

- Export Vault:

```bash
python3 eyrie.py export --vault vault.eyr --backup-path backup.enc --password "your_backup_pass" --confirm-password "your_backup_pass"
```

- Import Vault:

```bash
python3 eyrie.py import --backup-path backup.enc --password "your_backup_pass" --target-vault new_vault.eyr
```

- Change Master Password:

```bash
python3 eyrie.py change-master --vault vault.eyr
```

- 2FA Commands:

```bash
python3 eyrie.py 2fa setup --vault vault.eyr
python3 eyrie.py 2fa disable --vault vault.eyr
python3 eyrie.py 2fa status --vault vault.eyr
```

*Use '--help' for full options.*

## Interactive 

Here are the available commands:

| Command              | Alias    | Description                                                                                   |
|----------------------|----------|-----------------------------------------------------------------------------------------------|
| `add_entry`          | `ae`     | Create a new credential entry (title, username, password, URL, category)                     |
| `list_entry`         | `le`     | Show table of all stored entries (ID, title, username, category, created)                    |
| `get_entry`          | `ge`     | View full details of one entry (including the password)                                      |
| `update_entry`       | `ue`     | Modify an existing entry (username, password, URL, category, etc.)                           |
| `delete_entry`       | `de`     | Permanently remove an entry (with confirmation)                                              |
| `password_history`   | `ph`     | Show password change history for an entry (masked previous passwords + dates)               |
| `reveal_version`     | `rv`     | Reveal plaintext password of a specific history version                                      |
| `clear_history`      | `ch`     | Delete all previous password versions for an entry (keeps current password)                  |
| `gen_passwd`         | `gp`     | Generate a new secure random password (configurable length & character types)               |
| `ch_master_passwd`   | `cmp`    | Change the master password (re-encrypts entire vault with new key)                           |
| `vault_info`         | `vi`     | Show vault statistics & metadata (entry count, dates, 2FA status, size, …)                  |
| `export_vault`       | `ev`     | Create encrypted backup of the complete vault                                                |
| `setup_2fa`          | `2fa`    | Enable Two-Factor Authentication (shows QR code + recovery codes)                            |
| `disable_2fa`        | `d2fa`   | Turn off Two-Factor Authentication                                                           |
| `show_2fa`           | `s2fa`   | Display current 2FA status & remaining unused recovery codes                                 |
| `help`               | `h`      | Show this help screen                                                                        |
| `exit`               | `q`, `quit` | Exit interactive mode and lock vault                                                      |

## Example Session:

```
eyrie@password/> add_entry
Service/Title: Google
Username/Email: user@example.com
Password: ********
URL (optional): https://google.com
Category (optional): Web
[+] Entry added successfully (ID: 1)
```

## Architecture and Flowchart

Eyrie follows a modular design:

- **Modules**: crypto.py (encryption), database.py (vault ops), tfa.py (2FA), ui.py (display), validation.py (checks), export_import.py (backups), password_generator.py (gen), eyr_format.py (file format).
- **Core Flow**: User authenticates → Derive key → Decrypt vault → Perform ops → Encrypt changes.

## ASCII Flowchart of Functionality

```
+-------------------+     +-------------------+     +-------------------+
| User Input (CLI)  |     | Authentication    |     | Vault Operations  |
| - Commands        |     | - Master Password |     | - Add/Update/Get  |
| - Interactive     | --> | - 2FA (TOTP)      | --> | - Delete/List     |
| - Args            |     | - Trusted Device  |     | - History         |
+-------------------+     +-------------------+     +-------------------+
          |                           |                        |
          v                           v                        v
+-------------------+     +-------------------+     +-------------------+
| Validation        |     | Key Derivation    |     | Encryption/Decryption |
| - Password Strength|     | - Argon2id KDF   |     | - AES-GCM         |
| - Input Checks    | <-- | - Salt            | <-- | - HMAC Auth      |
+-------------------+     +-------------------+     +-------------------+
          |                           |                        |
          v                           v                        v
+-------------------+     +-------------------+     +-------------------+
| Password Gen      |     | 2FA Management    |     | File I/O (.eyr)   |
| - Secure Random   |     | - QR Code (ASCII) |     | - Custom Format   |
| - Custom Options  | --> | - Recovery Codes  | --> | - Compression     |
+-------------------+     +-------------------+     +-------------------+
                                      |
                                      v
                            +-------------------+
                            | Export/Import     |
                            | - Encrypted Backup|
                            | - CSV (Soon)      |
                            +-------------------+
```

## Encryption Algorithm Flowchart (Detailed)

Eyrie's encryption uses modern primitives for confidentiality, integrity, and authenticity.

```
+-------------------+     +-------------------+
| Master Password   |     | Fixed Salt (v1.0) |
| (User Input)      |     | (Backup/Import)   |
+-------------------+     +-------------------+
          |                           |
          v                           v
    +-----------------------------------+
    | Key Derivation (Argon2id)         |
    | - Time Cost: 2                    |
    | - Memory: 100MB                    |
    | - Parallelism: 4                 |
    | Output: 64-byte Key Material      |
    +-----------------------------------+
                       |
                       v
    +-----------------------------------+
    | HKDF (SHA-256) for Key Separation |
    | - Encryption Key (32 bytes)       |
    | - Auth Key (32 bytes)             |
    +-----------------------------------+
          |                           |
          v                           v
+-------------------+     +-------------------+
| Encrypt Data      |     | Compute HMAC      |
| - AES-GCM         |     | - SHA-256         |
| - Nonce (12 bytes)|     | - Auth Key        |
| - Tag (16 bytes)  |     |                   |
+-------------------+     +-------------------+
          |                           |
          v                           v
    +-----------------------------------+
    | Store in .eyr Format              |
    | - Header (Magic, Checksum)         |
    | - Entry Table (Offsets)           |
    | - Compressed Entries               |
    | - Metadata (JSON)                 |
    | - Footer (Validation)             |
    +-----------------------------------+
```

Steps in Detail:

- **Key Derivation**: Password + Salt → Argon2id → 64-byte key.
- **Key Separation**: HKDF derives separate encryption and auth keys.
- **Encryption**: AES-GCM encrypts data with nonce and tag.
- **Authentication**: HMAC-SHA256 on data for integrity.
- **Storage**: Binary format with CRC32 checks and compression.
- **Decryption**: Reverse process with verification.
- **Security**: Resistant to timing attacks, GPU cracking, and tampering.

## Security Considerations

- **Threat Model**: Protects against local file access, brute-force, and side-channel attacks.
- **Best Practices**: Use strong master passwords (validated with entropy checks). Enable 2FA. Regularly backup.
- **Limitations**: Not designed for multi-user or web access. Vault file should be stored securely (e.g., encrypted drive).
- **Audits**: Encourage third-party reviews of crypto.py and eyr_format.py.

## License

Eyrie is under **GNU GENERAL PUBLIC LICENSE**

## Author

Kur0Sh1ro (A1SBERG)
