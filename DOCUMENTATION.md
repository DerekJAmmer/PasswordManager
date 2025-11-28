# Password Manager - Complete Documentation

November 19, 2025

## Overview

This document provides comprehensive documentation for the Secure Password Manager application. The Password Manager is a desktop application that securely stores, manages, and retrieves passwords using military-grade encryption. The application features both a command-line interface and a graphical user interface built with Tkinter.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Installation](#installation)
3. [Application Features](#application-features)
4. [Security Architecture](#security-architecture)
5. [Command Line Usage](#command-line-usage)
6. [Graphical User Interface](#graphical-user-interface)
7. [Configuration](#configuration)
8. [File Storage](#file-storage)
9. [Security Features](#security-features)
10. [Troubleshooting](#troubleshooting)

---

## Getting Started

### System Requirements

- Python 3.8 or higher
- Windows, macOS, or Linux operating system
- Minimum 100MB free disk space
- Standard permissions on user directory

### Quick Start

1. Install Python dependencies:
```
pip install -r requirements.txt
```

2. Run the application:
```
python vault.py
```

3. Initialize your first vault:
```
python vault.py init
```

4. Create your master password when prompted (minimum 12 characters recommended)

---

## Installation

### Step 1: Clone or Download

Navigate to the project directory containing all application files.

### Step 2: Install Dependencies

Open a terminal or command prompt in the project directory and run:

```
pip install -r requirements.txt
```

Required packages:
- cryptography (version 41.0.0+): Encryption library
- argon2-cffi (version 21.3.0+): Password hashing
- pyperclip (version 1.8.2+): Clipboard management
- pycryptodome (version 3.18.0+): Additional cryptographic utilities

### Step 3: Verify Installation

Test the installation by running:

```
python vault.py --help
```

If successful, you will see the help menu with available commands.

---

## Application Features

### Core Functionality

The Password Manager provides the following features:

**Vault Management**
- Create new encrypted vaults
- Load existing vaults with password protection
- Export vaults as encrypted backups
- Import backups into new or existing vaults
- Support for multiple vault files

**Password Storage**
- Add new password entries with metadata
- Store username, URL, and notes alongside passwords
- Automatic timestamp recording for each entry
- Import entries from backup files while preserving all metadata
- Secure encryption of all stored data

**Password Retrieval**
- View stored passwords with complete entry information
- List all stored entries in alphabetical order
- Search and filter capabilities

**Entry Management**
- Delete password entries with safety confirmation
- Update entry information (through delete and re-add)
- View complete entry metadata

**Security Operations**
- Automatic file permission enforcement
- Audit logging of all vault operations
- Session management with auto-lock capability
- Brute force protection with exponential backoff

---

## Security Architecture

### Encryption Method

The Password Manager uses AES-256-GCM (Advanced Encryption Standard with Galois/Counter Mode) for all password encryption. This provides both confidentiality and authentication in a single operation.

**Key Specifications:**
- Cipher: AES-256-GCM
- Key Size: 256 bits (32 bytes)
- Authentication Tag: 128 bits
- Nonce Size: 96 bits (12 bytes)

### Key Derivation

Master passwords are converted to encryption keys using a two-tier key derivation approach:

Primary Method: Argon2id
- If available and functioning, the application attempts to use Argon2id for key derivation
- Argon2id is a modern, memory-hard password hashing algorithm recommended by security experts

Fallback Method: PBKDF2-SHA256
- If Argon2id is unavailable, the application falls back to PBKDF2 with SHA-256
- Iterations: 100,000
- Key Length: 256 bits
- Salt Length: 128 bits (randomly generated per vault)

Both methods ensure that even weak passwords are computationally difficult to crack through brute force attacks. The dual-approach provides flexibility while maintaining security standards.

### Authentication and Integrity

Each encrypted entry includes dual-layer authentication:

1. AES-GCM Authentication: The AES-GCM cipher mode generates a 128-bit authentication tag that verifies the integrity of the ciphertext.

2. HMAC-SHA256 Verification: An additional HMAC-SHA256 authentication code is computed over the concatenation of the nonce and ciphertext, providing an extra layer of authentication.

Both tags are verified during decryption. If either verification fails, the entry is rejected and not decrypted. This dual authentication approach provides defense-in-depth against tampering and corruption of stored data.

### Randomness

All cryptographic random values (salts, nonces) are generated using the operating system's secure random number generator:
- Unix/Linux: /dev/urandom
- Windows: CryptGen API

---

## Command Line Usage

### Initialize a Vault

Command:
```
python vault.py init [--path /custom/path] [--name vault_name]
```

Creates a new encrypted vault. You will be prompted to enter and confirm a master password.

Parameters:
- `--path`: Optional custom path for vault storage. Default is ~/.local_vault/passwords.json
- `--name`: Optional name for the vault. Default is "default"

Example:
```
python vault.py init
```

Example with custom name:
```
python vault.py init --name work_vault
```

### Add a Password Entry

Command:
```
python vault.py add <entry_name> [--url URL] [--notes NOTES]
```

Adds a new password entry to the vault.

Parameters:
- `entry_name`: Name or identifier for the password entry
- `--url`: Optional URL or website address
- `--notes`: Optional additional notes or information

You will be prompted for the master password, username, and password to store.

Example:
```
python vault.py add gmail --url https://mail.google.com
```

### Retrieve a Password

Command:
```
python vault.py get <entry_name>
```

Retrieves and displays a password entry from the vault.

Parameters:
- `entry_name`: Name of the password entry to retrieve

You will be prompted for the master password. The entry details will be displayed in JSON format.

Example:
```
python vault.py get gmail
```

### List All Entries

Command:
```
python vault.py list
```

Displays all stored password entry names in alphabetical order. Does not display passwords.

Example:
```
python vault.py list
```

### Delete an Entry

Command:
```
python vault.py delete <entry_name> [--force]
```

Removes a password entry from the vault. A confirmation prompt will appear unless --force is used.

Parameters:
- `entry_name`: Name of the password entry to delete
- `--force`: Skip confirmation prompt

Example:
```
python vault.py delete gmail
```

### Export a Vault

Command:
```
python vault.py export <output_file> [--password PASSWORD]
```

Creates an encrypted backup of the entire vault. The backup is encrypted with a separate password that differs from the master password.

Parameters:
- `output_file`: Path where the backup file will be saved
- `--password`: Optional password for the backup. If not provided, you will be prompted

The backup password must meet the same strength requirements as the master password (minimum 12 characters, with mixed character types).

Example:
```
python vault.py export backup.json
```

**Backup Security**

Backup files are protected with two layers of encryption:

1. **File-Level Encryption**: The entire backup file is encrypted with a file-level key derived from your export password. This prevents unauthorized users from reading the backup file structure.

2. **Content-Level Encryption**: Individual password entries within the backup are separately encrypted and authenticated with HMAC-SHA256.

This dual-layer approach ensures:
- Unauthorized users cannot inspect what is in the backup without the export password
- Wrong password is detected immediately without exposing any backup contents
- Tampering is detected at both the file and entry levels

**Backup Formats**

The application supports two backup formats:
- Version 2.0: Legacy format with single-layer encryption (for backward compatibility)
- Version 2.1: Current format with file-level password protection (recommended)

All new backups are created in version 2.1 format. Old backups continue to work without changes.

### Import a Vault

Command:
```
python vault.py import <import_file> [--path /custom/path] [--name vault_name]
```

Imports entries from an encrypted backup file. This command allows you to restore a previously exported vault or transfer passwords to a new system.

Parameters:
- `import_file`: Path to the encrypted backup file to import
- `--path`: Optional custom path for new vault. Default is ~/.local_vault/passwords.json
- `--name`: Optional name for imported vault. Default is "imported"

You will be prompted for the export password (the password used when exporting the backup).

Example:
```
python vault.py import backup.json
```

**Import Process**

When importing a backup:
1. The backup file version is detected
2. If version 2.1 (file-level protection): The file-level encryption is decrypted first
   - Wrong password is immediately detected with an error message
   - Backup structure cannot be examined without the correct password
3. The content-level encryption is decrypted and HMAC verified
4. All entries are validated and added to the vault

If any integrity check fails, the import is aborted and an error is reported.

---

## Graphical User Interface

### Launching the GUI

The graphical interface is automatically launched when running the application. To start the GUI:

```
python vault.py
```

### Main Window

The main window displays:
- Vault status (locked/unlocked)
- Current vault name
- List of stored password entries
- Action buttons for common operations

### Unlocking the Vault

1. Enter your master password in the password field
2. Click the "Unlock Vault" button
3. The vault will decrypt and display all stored entries

### Adding a Password

1. Click the "Add Entry" button
2. Fill in the entry details:
   - Entry name (required)
   - Username (optional)
   - Password (required)
   - URL (optional)
   - Notes (optional)
3. Click "Add" to save the entry

### Editing an Entry

1. Select an entry from the list
2. Click "Edit" button
3. Modify the entry details as needed
4. Click "Save" to update the entry
5. The changes will be encrypted and saved to the vault

### Viewing Entry Details

1. Select an entry from the list
2. Entry details will be displayed on the right side panel
3. Click the eye icon next to the password to show or hide it
4. Entry metadata including username, URL, and notes are displayed

### Copying to Clipboard

1. Select an entry
2. Click "Copy Password"
3. The password will be copied to your clipboard
4. The clipboard will be automatically cleared after 15 seconds

### Deleting an Entry

1. Select an entry from the list
2. Click "Delete"
3. Confirm the deletion in the dialog that appears
4. The entry will be permanently removed

### Exporting a Backup

1. Click "Export Backup" in the main toolbar
2. Choose a location and filename for the backup
3. Enter a separate password for the backup (can be different from vault password)
4. The encrypted backup will be created at the specified location

**How Export Works:**
- All password entries are decrypted using the current vault's master key
- Plaintext entries are re-encrypted using the backup password
- The export is wrapped with file-level encryption for additional security
- Final backup file cannot be read without the backup password
- All entry metadata (username, URL, notes, timestamps) are preserved

### Importing a Backup

1. Click "Import Backup" in the main toolbar
2. Select the encrypted backup file to import
3. Enter the password used when the backup was exported
4. Create a new vault with a different master password (if creating new vault)
5. All entries will be imported and re-encrypted with the new vault's key

**How Import Works:**
- Backup file is decrypted using the backup password
- Plaintext entries are extracted from the decrypted backup
- Each entry is re-encrypted using the new vault's master key
- Entries are saved to the new vault
- All original metadata is preserved during import
- Timestamps show when entries were added, not when they were originally created

**Important Notes:**
- Import passwords are NOT validated for strength (they were already validated in source vault)
- Import operation creates a completely new vault (does not modify existing vaults)
- Backup and new vault passwords must be entered correctly for successful import
- If import fails, check that backup password is correct and backup file is not corrupted

---

## Import/Export Security Details

### Backup Encryption

Backups use a two-layer encryption approach:

1. **Content Layer (Backup Password):**
   - Each entry encrypted independently with backup password
   - Uses AES-256-GCM encryption
   - Preserves entry privacy within backup

2. **File Layer (Backup Password):**
   - Entire backup structure encrypted again with backup password
   - Prevents access to metadata even if content layer is compromised
   - File-level nonce prevents replay attacks

### Password Handling During Import

- Backup password is captured separately from new vault password
- Backup password is used only for decryption, not stored in new vault
- New vault password is used only for the new vault, not for decryption
- Both passwords are erased from memory after import completes

### Data Integrity

- Backup files include integrity hashes to detect tampering
- Corrupted backups will fail during import with clear error message
- GCM mode provides authentication tag verification on all encrypted data
- If import fails, original vault remains untouched

---

## Configuration

### Configuration File

The application configuration is stored in `config.py`. Key settings include:

**Encryption Parameters:**
- KDF_N: 16384 (memory cost factor for Argon2id, if available)
- KDF_R: 8 (block size for Argon2id, if available)
- KDF_P: 1 (parallelization factor for Argon2id, if available)
- SALT_LENGTH: 16 bytes (128 bits of random salt per vault)
- NONCE_LENGTH: 12 bytes (96 bits of random nonce per entry)
- KEY_LENGTH: 32 bytes (256-bit AES key)

**Security Policies:**
- MIN_PASSWORD_LENGTH: 12 characters minimum
- PASSWORD_STRENGTH_ENTROPY_THRESHOLD: 60 bits
- MAX_UNLOCK_ATTEMPTS: 5 failed attempts before lockout
- UNLOCK_ATTEMPT_BACKOFF_BASE: Exponential backoff multiplier
- CLIPBOARD_CLEAR_TIMEOUT: 15 seconds
- AUTO_LOCK_TIMEOUT: 900 seconds (15 minutes)
- AUDIT_LOG_MAX_SIZE: 10 megabytes

**File Paths:**
- VAULT_DIR: ~/.local_vault (default storage location)
- VAULTS_CONFIG_FILE: ~/.local_vault/vaults.json
- AUDIT_LOG_FILE: ~/.local_vault/audit.log

### Modifying Configuration

To change settings, edit the values in `config.py`. Changes take effect on the next application restart.

Important: Do not reduce MIN_PASSWORD_LENGTH or PASSWORD_STRENGTH_ENTROPY_THRESHOLD as this will weaken security.

---

## File Storage

### Vault File Location

By default, vault files are stored in the user's home directory under `.local_vault`:

- Windows: C:\Users\YourUsername\.local_vault\
- macOS: /Users/YourUsername/.local_vault/
- Linux: /home/YourUsername/.local_vault/

### Vault File Structure

Vault files are stored in JSON format with the following structure:

```
{
  "version": "2.0",
  "created": "2025-11-19T12:34:56Z",
  "modified": "2025-11-19T12:34:56Z",
  "salt": "base64_encoded_salt_value",
  "entries": {
    "entry_name": {
      "nonce": "base64_encoded_nonce",
      "ciphertext": "base64_encoded_encrypted_data",
      "hmac": "base64_encoded_hmac_tag"
    }
  },
  "metadata": {
    "vault_name": "default",
    "key_derivation": "Argon2id",
    "encryption": "AES-256-GCM",
    "integrity_protection": "HMAC-SHA256"
  },
  "integrity_hash": "vault_level_integrity_hash"
}
```

**Field Descriptions:**
- version: Vault format version (currently 2.0)
- created: Timestamp when vault was created
- modified: Timestamp of last modification
- salt: Random value used in key derivation (unique per vault, base64 encoded)
- entries: Dictionary of password entries
- nonce: Random value used in encryption (unique per entry, base64 encoded)
- ciphertext: Encrypted password entry data (base64 encoded)
- hmac: HMAC-SHA256 authentication tag for entry integrity verification
- metadata: Information about vault configuration and encryption methods
- integrity_hash: Vault-level integrity hash for detecting tampering

### File Permissions

Vault files are automatically protected with restrictive permissions:

- Unix/Linux: 600 (read/write for owner only)
- Windows: ACL with full access for owner only

These permissions ensure only the vault owner can read the vault file.

### Audit Log

All vault operations are recorded in `audit.log`:
- File location: ~/.local_vault/audit.log
- Format: Timestamp, operation type, and details
- Permission: 600 (owner only)
- Automatic rotation when reaching maximum size

---

## Security Features

### Master Password Protection

The master password is the key to your vault. It is:
- Never stored in plain text
- Never displayed on screen
- Used to derive the encryption key
- Required for every vault operation

Choose a strong master password with:
- Minimum 12 characters
- Mix of uppercase and lowercase letters
- Numbers and special characters
- Avoid dictionary words and personal information

### Brute Force Protection

The application implements multiple layers of brute force protection:

**Key Derivation Delay:** Each master password validation requires approximately 100 milliseconds of computation, making dictionary attacks impractical.

**Failed Attempt Tracking:** After 5 failed unlock attempts, the vault enters a locked state with exponential backoff delays between attempts.

**Rate Limiting:** The application enforces minimum time intervals between unlock attempts.

### Auto-Lock

Active vault sessions automatically lock after 15 minutes of inactivity. A new master password entry is required to unlock.

### Session Management

- Only one vault can be active at a time
- Sessions maintain connection to the vault file
- Master key is stored in memory while vault is unlocked
- Memory is cleared when vault locks or application closes

### Clipboard Security

When copying passwords to the clipboard:
- Password is stored in secure clipboard buffer
- Clipboard automatically clears after 15 seconds
- User is notified of clipboard clearing

### Audit Logging

All significant vault operations are logged with timestamps:
- Vault creation and loading
- Entry additions and deletions
- Export operations
- Failed authentication attempts
- Session locks and unlocks

Audit logs are write-only and protected with owner-only file permissions.

---

## Troubleshooting

### Cannot Create Vault

**Problem:** "Permission denied" error when creating vault

**Solution:** 
- Ensure .local_vault directory is readable and writable
- Check user permissions on home directory
- Try creating the directory manually: mkdir ~/.local_vault

### Incorrect Master Password

**Problem:** "Authentication failed" or "Invalid master password" error

**Solution:**
- Master password is case-sensitive
- Verify Caps Lock is not enabled
- If vault is locked, wait for backoff period before retrying

**Note:** There is no password recovery. If you forget your master password, the vault cannot be accessed.

### Entry Not Found

**Problem:** Entry appears to be missing from vault

**Solution:**
- Entry names are case-sensitive
- Use "list" command to view all stored entries
- Entry may have been deleted

### Vault File Corrupted

**Problem:** "Invalid vault format" or decryption errors

**Solution:**
- Restore from backup using export file if available
- Manually check vault file is valid JSON
- Do not edit vault file manually as this causes corruption

### GUI Does Not Start

**Problem:** GUI window does not appear

**Solution:**
- Verify Python and Tkinter are installed
- Check for error messages in terminal
- On Linux, may need to install additional packages: sudo apt-get install python3-tk

### Slow Performance

**Problem:** Master password validation or encryption takes unusually long

**Solution:**
- This is normal for the first operation after application start
- Subsequent operations are faster
- If persistently slow, check system resources and background processes

### Clipboard Not Clearing

**Problem:** Password remains in clipboard after 15 seconds

**Solution:**
- Some clipboard managers may interfere with auto-clear
- Manual clipboard clear may be necessary
- Use keyboard shortcut to clear: Ctrl+Alt+X or right-click clipboard manager

### File Permission Issues

**Problem:** Cannot read or write vault file

**Solution:**
- On Windows: Check NTFS permissions and ACL
- On Unix/Linux: Check file permissions with ls -l
- Restore file permissions: chmod 600 ~/.local_vault/passwords.json

---

## Advanced Topics

### Backup and Recovery

Regular backups are recommended. Use the export feature to create encrypted backups:

1. Export vault to a file with a separate password
2. Store backup in a secure location
3. Test restore capability periodically
4. Use backup in case of vault corruption or data loss

### Multiple Vaults

The application supports multiple vault files:

1. Initialize additional vaults with different paths
2. Load specific vault when needed
3. Each vault has independent master password

Example:
```
python vault.py init --path ~/work_vault.json
python vault.py init --path ~/personal_vault.json
```

### Transferring to New System

1. Export vault from old system using the export command
2. Install application on new system
3. Import backup file using the import command
4. The imported vault will be restored with all entries intact

Example workflow:
```
# On old system:
python vault.py export backup.json
# (move backup.json to new system)

# On new system:
python vault.py import backup.json
```

---

## File Structure

The application consists of the following Python modules:

- `vault.py`: Main application and vault management
- `gui.py`: Graphical user interface implementation
- `security.py`: Encryption and security utilities
- `config.py`: Configuration constants
- `exceptions.py`: Custom exception definitions
- `clipboard_manager.py`: Secure clipboard operations

Documentation and reference files:
- `README.md`: General project information
- `requirements.txt`: Python dependencies
- `DOCUMENTATION.md`: This file

---

## Support and Additional Information

For additional help or information:

1. Check this documentation file
2. Review inline code comments in source files
3. Check error messages displayed in application
4. Review audit.log for operation history

For security concerns or bug reports, review the application code and security implementation before taking action.

---

**Document Version:** 1.0  
**Last Updated:** November 19, 2025  
**Application Version:** 1.0.0  
**Status:** Production Ready

