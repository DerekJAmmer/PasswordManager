# Security Summary - Password Manager

## Overview

This document summarizes the security functionality implemented in the password manager application. The application implements defense-in-depth security using industry-standard cryptographic practices, file system protections, runtime security controls, and comprehensive audit logging.

---

## Security Implementation

### Cryptographic Foundation

The application uses modern cryptographic algorithms for all password storage and protection.

**Key Derivation**

The master password is converted into a 256-bit encryption key using Argon2id through the `argon2-cffi` library. PBKDF2-HMAC-SHA256 is wired as a fallback and only runs if the Argon2 import fails at startup.

- Primary method: Argon2id
  - Variant: Argon2id
  - Time cost: 2
  - Memory cost: 19456 KiB (19 MiB)
  - Parallelism: 1
  - Output: 32 bytes
  - Parameters match the OWASP 2023 recommendation for Argon2id.

- Fallback method: PBKDF2-HMAC-SHA256
  - Iterations: 310,000 (OWASP 2023 minimum for SHA-256)
  - Output: 32 bytes

Each vault records which KDF it was created with, along with the exact parameters, in `metadata.kdf`. Load-time derivation reads that record and calls the matching function. This removes any guesswork at import or unlock time and makes future KDF changes possible without another format break.

Salts are 16 bytes per vault and 16 bytes per backup layer. They come from the OS CSPRNG via Python's `secrets` module, which prevents pre-computed rainbow table attacks.

**Encryption**

All password entries are encrypted using AES-256-GCM:
- 256-bit encryption key (32 bytes)
- Galois/Counter Mode (GCM) for authenticated encryption
- Unique 12-byte random nonce per entry
- 128-bit authentication tag automatically generated during encryption

Each entry is independently encrypted with its own unique nonce, preventing patterns from emerging if the same password appears in multiple entries.

**Authentication**

The application implements dual-layer authentication for integrity verification:

1. AES-GCM authentication: The GCM mode generates and verifies a 128-bit authentication tag with each encryption/decryption operation.

2. HMAC-SHA256: An additional authentication code is computed over the nonce and ciphertext using SHA-256, providing a second layer of integrity verification.

Both authentication mechanisms must pass verification before decrypted data is considered valid. If either fails, the entry is rejected and a VaultCorruptedError is raised. This dual approach provides defense-in-depth against tampering and helps detect vault file corruption.

**Random Number Generation**

All cryptographic randomness comes from operating system sources:
- Unix/Linux/macOS: /dev/urandom
- Windows: CryptGen API

This ensures salts and nonces are cryptographically random and unpredictable.

### File System Protection

The vault file and related configuration files are protected at the operating system level.

**Windows ACL Enforcement**

On Windows systems, vault files and backup files are protected using NTFS Access Control Lists:
- Vault and backup files: owner R-only, Administrators R-only, inheritance disabled
- Vault directory: owner Full control, Administrators Full control, inheritance disabled
- All other users: no access

The icacls invocation is a list-form `subprocess.run(..., shell=False)` call (no string interpolation), which closes the classic icacls command-injection path. Each on-disk rewrite relaxes the ACL to R,W just long enough to call `write_text`, then restores the R-only ACL.

**Unix Permissions Enforcement**

On Unix-like systems (Linux, macOS):
- Vault and backup files at rest: `0o400` (owner read-only)
- Vault directory: `0o700`
- Audit log: `0o600` (append-only writes need owner write)

Vault rewrites use a chmod-0o600 → write → chmod-0o400 dance. The file is never world-readable or world-writable at any point. See `security.set_vault_file_permissions`, `security.make_vault_writable`, and `vault.VaultManager._persist_vault`.

**Application-Level Verification**

When loading a vault, the application verifies that file permissions are correct. If permissions have been modified, the vault will still load, but this represents a potential security issue.

### Runtime Security

The application implements several runtime controls to prevent unauthorized access and data leakage.

**Master Key Management**

The derived 32-byte master key is never persisted on the VaultManager instance. Every operation that needs the key calls `_get_derived_key()`, uses the key inside a `try / finally` block, and wipes it with `wipe_key()` before returning. `wipe_key` releases the OS memory lock (see below) and zero-fills the bytearray.

The master password (the user-supplied string) lives on the instance for the duration of the session so the key can be re-derived per call. `lock_vault()`, `clear_sensitive_data()`, and the auto-lock path all zero-fill the password bytes, drop the salt, and set `vault_data` and the decrypted metadata plaintext to `None`.

**mlock / VirtualLock on Derived Key Buffers**

`_get_derived_key()` returns a `bytearray` that has been passed through `security.try_lock_memory()`. On POSIX this calls `libc.mlock()` on the key buffer; on Windows it calls `VirtualLock()` through `ctypes`. The goal is to keep a derived key out of swap for the microseconds it is in RAM.

Memory locking is best-effort. Unprivileged users have a small `RLIMIT_MEMLOCK` budget on Linux, and a working set limit on Windows. On failure the helper returns `False`, writes a single `MEMORY_LOCK_UNAVAILABLE` audit event, and the caller proceeds. Key wipes still run. This is documented as a honest, partial mitigation, not a complete defence against an administrator-privileged attacker with a process memory dump.

**Auto-Lock on Inactivity**

Vaults automatically lock after 15 minutes of inactivity. The application tracks the last activity timestamp on every vault operation:
- Reading a password entry updates last_activity
- Adding an entry updates last_activity
- Listing entries updates last_activity
- Deleting an entry updates last_activity

On every vault operation, the application checks if more than 15 minutes have passed since the last activity. If so, the vault is locked and a VaultLockedError is raised.

The GUI displays a countdown timer showing time remaining before auto-lock.

**Clipboard Auto-Clear**

When a user copies a password to the clipboard, a background thread is started that clears the clipboard after 15 seconds. This prevents the password from remaining in the clipboard after the user has finished using it.

The clipboard auto-clear is implemented using a background thread that runs independently of the main GUI thread.

**Session Management**

Only one vault can be loaded at a time. When loading a new vault, the previous vault is automatically locked. The master key is maintained in memory only while a vault is actively loaded.

### Integrity and Tamper Detection

The application implements multiple layers of integrity checking to detect if vault files have been modified.

**Entry-Level HMAC Verification**

Each encrypted entry stores:
- Nonce (base64 encoded)
- Ciphertext (base64 encoded)
- HMAC tag (computed over nonce + ciphertext)

During decryption, the HMAC is recomputed over the same nonce and ciphertext. If the computed HMAC does not match the stored HMAC, the entry is rejected.

This prevents:
- Modification of the ciphertext by attackers
- Swapping of entries (nonce is part of HMAC)
- Replay of old ciphertexts

**Vault-Level Integrity Hash**

A vault-level integrity hash is computed by:
1. For each entry (in sorted order), concatenating: entry_name:nonce:ciphertext
2. Computing SHA-256 hash of each concatenated entry
3. Combining all entry hashes
4. Computing final SHA-256 of combined hashes

This vault integrity hash is stored in the vault file. On load, if the vault metadata includes an integrity_hash, it is recomputed and compared. If they do not match, a VaultCorruptedError is raised.

This detects if entries have been added, deleted, or reordered.

**Encrypted Metadata Block (Validation Token + Timestamps)**

Each v3.1 vault stores an `encrypted_metadata` field at the top level. This is a single AES-256-GCM blob that decrypts to a JSON document of the form:

```
{
  "validation_token": "password_manager:v3.1:valid",
  "created": "<ISO-8601>",
  "modified": "<ISO-8601>"
}
```

On load, the block is decrypted with the derived master key. If the decryption or the `validation_token` comparison fails, a wrong-password error is raised before any user entry is touched. On write, the block is re-encrypted with a fresh nonce, with `modified` bumped to `now()`.

Moving the timestamps inside this block closes the Phase-2 "timestamp leakage" finding. An attacker with only read access to the vault file can no longer see when the vault was created or last modified without the master password.

### Anti-Brute Force Protection

The application implements rate limiting to prevent brute force attacks on the master password.

**Failed Attempt Tracking**

Failed unlock attempts are tracked per vault:
- Attempting to load the vault with an incorrect master password increments a failed_unlock_attempts counter
- Successful unlock resets the counter to 0

**Maximum Attempts and Lockout**

After 5 failed unlock attempts, the vault enters a locked state with an exponential backoff delay:
- Attempt 1-4: Try again immediately
- Attempt 5: Locked for 1 second
- Next attempt after timeout: Locked for 2 seconds
- Next attempt: Locked for 4 seconds
- Pattern continues doubling

The lockout is enforced through a .lock file that stores the timestamp when the vault can be unlocked again.

**Lock File Persistence**

The .lock file persists on disk, so if the user closes the application during a brute force lockout, the lockout remains in effect when they reopen the application.

**Per-Vault Rate Limiting**

Each vault has independent rate limiting. Failing to unlock one vault does not affect the rate limit on other vaults.

### Password Strength Validation

All passwords in the system must meet minimum strength requirements.

**Master Password Requirements**

The master password must:
- Be at least 12 characters long
- Have at least 60 bits of Shannon entropy
- Include characters from at least 3 different character classes (uppercase, lowercase, numbers, special characters)

**Entry Password Requirements**

Passwords stored as vault entries must also meet the same minimum strength requirements. This prevents users from storing weak passwords that might be recovered by an attacker.

**Entropy Calculation**

Password entropy is calculated using Shannon entropy formula:
- Each unique character increases entropy
- Character distribution is analyzed
- Passwords with repeated characters have lower entropy
- Minimum 60 bits of entropy required

### Backup Import/Export Security

The application implements secure backup functionality with protection against multiple attack vectors.

**Backup Encryption Architecture**

Backups use a two-layer encryption scheme:

1. **Content Layer (Backup Password):**
   - Each password entry is decrypted from source vault using source vault key
   - Plaintext entry is re-encrypted using backup password
   - AES-256-GCM with unique nonce per entry
   - GCM provides both encryption and authentication

2. **File Layer (Backup Password):**
   - Entire backup structure (including all entries) is encrypted again
   - File-level password derived with unique salt
   - AES-256-GCM with file-level nonce
   - Prevents any metadata access without correct password

**Key Derivation for Backups**

Backup passwords run through the same KDF pipeline as vault passwords:
- Primary: Argon2id (time_cost 2, memory_cost 19456 KiB, parallelism 1)
- Fallback: PBKDF2-HMAC-SHA256 at 310,000 iterations
- Independent 16-byte salt for the outer (file) layer and the inner (content) layer
- The KDF parameters used at export time are written into both the outer envelope and the inner `export_data`, so import always derives with the exact parameters used at export

**Entry Re-encryption Process**

During export:
1. Source vault is opened with source vault password
2. Each entry is decrypted with source vault key
3. Plaintext entry data is extracted
4. Plaintext is re-encrypted with backup password
5. Re-encrypted entry is stored in backup

During import:
1. Backup is decrypted with backup password (outer layer)
2. Entry data is decrypted with backup password (inner layer)
3. Plaintext entries are extracted
4. New vault is created or selected
5. Plaintext entries are re-encrypted with new vault key
6. Entries are stored in new vault

**Attack Prevention**

- **Keylogging Protection:** Backup password is entered separately from vault password, cannot compromise both
- **Dictionary Attacks:** Backup passwords require 60+ bits entropy, same as vault passwords
- **Rainbow Table Attacks:** Unique 16-byte salts per backup layer prevent pre-computation
- **Brute Force Attacks:** Argon2id requires 2 seconds per key derivation attempt
- **Tampering Detection:** GCM authentication tags detect any modification to backup
- **Credential Separation:** Backup and vault passwords are independent

**File Permissions for Backups**

Backup files created by export receive:
- Read-only permissions for owner (file cannot be modified)
- No access for group or other users
- Inheritance disabled to prevent permission inheritance
- Helps prevent accidental modification of backups

**Integrity Verification**

Backup files include:
- GCM authentication tags (file-level and entry-level)
- Vault integrity hashes (detects added/removed/reordered entries)
- Timestamp validation (detects forged metadata)
- Corrupted backups fail with clear error message

### Audit Logging

All vault operations are logged for security auditing and incident investigation.

**Logged Events**

The audit log records:
- Vault creation and loading
- Entry additions and deletions
- Export and import operations
- Failed authentication attempts
- Brute force detection triggers
- Tampering detection events
- Auto-lock events
- Manual vault locking

**What Is Not Logged**

To protect user privacy:
- Master passwords are never logged
- Plaintext passwords are never logged
- Usernames are never logged
- Entry contents are never logged (only entry names for operations)

**Audit Log Storage**

The audit log is stored in ~/.local_vault/audit.log with the same restricted file permissions as vault files (0o600 on Unix, ACL-restricted on Windows).

**Log Format**

Each log entry contains:
- Timestamp (ISO 8601 format)
- Event type (VAULT_CREATED, ENTRY_ADDED, AUTHENTICATION_FAILED, etc.)
- Event details (entry name, vault path, etc.)
- Success/failure indicator

**Log Rotation**

When the audit log exceeds 10 MB, it is rotated:
- Current log is renamed to audit.log.timestamp
- New audit.log is created
- Old rotated logs are retained for historical analysis

### Backup and Recovery

Secure backup and restore functionality allows users to protect against data loss.

**Export Function**

When exporting a vault:
- The user provides a separate export password (different from master password)
- The export password is validated for strength
- A new random salt is generated for the export
- All entries are decrypted with the master key
- Entries are re-encrypted with a key derived from the export password
- The backup file is created with restricted file permissions

The backup file is completely independent from the original vault. The original vault encryption remains unchanged.

**File-Level Password Protection for Backups**

Backup files implement two-layer encryption to prevent unauthorized access:

Layer 1 - File-Level Protection:
- The entire backup structure is encrypted with a file-level key derived from the export password
- A unique salt is generated for file-level encryption
- File-level HMAC prevents tampering with the backup structure itself
- Wrong password detected immediately without accessing backup contents

Layer 2 - Content-Level Protection:
- Individual entries are encrypted with a content-level key (also from export password)
- Each entry has its own HMAC for integrity verification
- Content-level HMAC verified after decrypting file-level layer

This two-layer approach ensures:
- Unauthorized users cannot inspect the backup file structure
- Wrong password fails at the file-level before any content is examined
- Even if someone obtains the backup file, they cannot determine what it contains without the export password
- Tampering is detected at both the file level and entry level

**Backup Format Versions**

- Version 3.2 is the only accepted backup format. The outer envelope is tagged `3.2` and carries `kdf`, `file_nonce`, `file_ciphertext`, and `file_salt`. Its inner `export_data` (once file-layer decryption succeeds) is tagged `3.1` and matches the current vault schema.

Earlier formats (1.0, 2.0, 2.1, and the Phase-1 `3.1` outer / `3.0` inner pairing) are rejected on import with a clear error. There was no real data under the old formats, so no migration path is provided.

**Import Function**

When importing a backup:
- The backup version is checked
- All required fields are validated to be present and non-empty
- Base64 encoding of all cryptographic values is validated
- If version 2.1: File-level decryption occurs first (requires password)
  - Wrong password fails immediately with security error
  - Any tampering with file_ciphertext, file_nonce triggers HMAC failure
- Content is then decrypted and HMAC verified
- All entries are added to the currently loaded vault

**Backup Tampering Detection**

Any modification to a backup file will be immediately detected:

File-Level Tampering Detection:
- If file_ciphertext is modified: HMAC verification fails (data changed)
- If file_nonce is modified: HMAC verification fails (nonce part of HMAC calculation)
- If file_hmac is modified: HMAC comparison fails
- If file_salt is modified: Different key derived, decryption fails
- If any required field is missing: Validation fails before decryption
- If any field contains invalid base64: Decoding fails with error

Content-Level Tampering Detection:
- If content_nonce is modified: Content-level HMAC verification fails
- If content_ciphertext is modified: HMAC verification fails
- If content_hmac is modified: HMAC comparison fails
- If content_salt is modified: Different key derived, decryption fails

Manual Editing Prevention:
The backup is stored in JSON for portability, but editing the file is cryptographically impossible without the export password. Any attempt to modify the file will result in one of these failures:
1. HMAC verification failure (if data is changed but HMAC is not updated)
2. Decryption failure (if wrong password is used)
3. Validation failure (if structure is broken)

In all cases, the import is aborted and the user is notified that the backup file has been corrupted or tampered with.

The import process verifies HMAC on all encrypted data, protecting against tampering during backup storage, transfer, or deliberate modification.

---

## Vulnerability Report Remediation Status

This section tracks the findings from `Vulnerability_Assessment_November_21_2025.md` and the Phase-0 agent audit against their current code state. Each item is marked **Resolved**, **Partially mitigated**, or **Accepted risk**, with a code reference.

### Critical

**C1. Master key resident in RAM for the whole session.** — **Resolved.**
The VaultManager no longer caches a derived key. Every operation re-derives via `_get_derived_key()` (`vault.py:208`) and wipes the bytearray with `wipe_key()` (`security.py`) in a `finally` block. See `vault.add_entry`, `vault.get_entry`, `vault.delete_entry`, `vault._add_entry_direct`, `vault.add_entry_from_import`, `vault.export_vault`, `vault.import_vault`, `vault.decrypt_backup_entries`. The key is held for microseconds per call.

### High

**H1. Swap paging can flush the in-memory key to disk.** — **Partially mitigated.**
`security.try_lock_memory()` wraps `libc.mlock()` on POSIX and `kernel32.VirtualLock()` on Windows, and is called on every derived-key bytearray before it is returned from `_get_derived_key()`. Unprivileged mlock budgets are small on Linux (`RLIMIT_MEMLOCK`), and the lock may silently fail. Failures emit a single `MEMORY_LOCK_UNAVAILABLE` audit event and the caller continues. The key is still zero-filled in every case.

**H2. Admin-privileged process dump.** — **Accepted risk.**
A process running as root (POSIX) or with `SeDebugPrivilege` (Windows) can still read live process memory and extract the derived key during the microseconds it is live, or read the master password bytes that live on the instance. This is an inherent limit of a userspace password manager without an HSM or DPAPI integration. Documented honestly rather than hidden.

**H3. Vault files created 0o600; should be 0o400 at rest.** — **Resolved.**
`set_vault_file_permissions()` (`security.py`) now sets `0o400` on POSIX and an owner-R-only ACL on Windows. `_persist_vault()` (`vault.py`) relaxes to 0o600 only for the duration of the rewrite. `set_readonly_permissions()` for backups also now writes 0o400 instead of 0o444.

**H4. PBKDF2 at 100k iterations is below OWASP 2023 minimum.** — **Resolved in Phase 1.** Argon2id is the default KDF (OWASP 2023 params: t=2, m=19456 KiB, p=1). PBKDF2-HMAC-SHA256 fallback is 310,000 iterations — only reached if `argon2-cffi` is not importable. Each vault records its KDF in `metadata.kdf`.

### Medium

**M1. Backup metadata timestamps stored unencrypted at the top level.** — **Resolved.**
Vault-level `created` and `modified` have been moved into the `encrypted_metadata` block (v3.1 vault format). The on-disk JSON has no plaintext timestamps; see `tests/test_phase2_hardening.py::TestEncryptedTimestamps`. Backup envelopes already had no top-level timestamps (the inner `export_data` is encrypted under both the content key and the file key).

**M2. `pycryptodome` listed in requirements but never imported.** — **Resolved.**
Dropped from `requirements.txt`. The test suite and end-to-end smoke verified the application runs without it.

**M3. `subprocess.run(..., shell=True)` in three icacls calls.** — **Resolved.**
`security._run_icacls()` builds a list-form argv and calls `subprocess.run(args, shell=False, ...)`. `_set_file_permissions`, `set_vault_file_permissions`, `make_vault_writable`, `set_readonly_permissions`, and `set_secure_dir_permissions` all route through it. The classic command-injection surface against an attacker-controlled path is closed.

### KDF Documentation vs Code

**K1. Docs advertised Argon2id but code always called PBKDF2@100k.** — **Resolved in Phase 1.** `argon2-cffi` is now actually invoked (`_derive_key_argon2id`). Docs are rewritten to match code. Unit tests assert Argon2id is called, PBKDF2 fallback is only reached when patched off, and `metadata.kdf` reflects reality.

### Other Notable Weaknesses

**N1. Clipboard reliability.** — Accepted as known limit of desktop clipboard APIs. Auto-clear after 15s via background thread. Revisit in Phase 6 (scalability / portability).

**N2. File permissions are not continuously verified on load.** — Accepted for now. If a privileged user tampered with the ACL, the vault still loads. Out of scope for Phase 2; reconsider if Phase 6 adds file integrity monitoring.

**N3. No master-password change.** — Accepted for Phase 2. Listed in the agent-audit backlog for Phase 4.

**N4. Audit log not encrypted.** — Accepted. Deferred to a later phase.

**N5. No 2FA / hardware key support.** — Accepted. Out of scope for a single-user desktop tool.

**N6. Rate-limit params are fixed.** — Accepted. Sufficient for single-user local use.

**N7. No secure deletion / SSD TRIM.** — Accepted. Out of scope; the vault is encrypted-at-rest, which limits the practical value of secure deletion.

**N8. No multi-device sync.** — Not a weakness in the threat model; local-first is a feature.

---

## Security Parameters and Thresholds

The following parameters control the security behavior of the application. These are defined in config.py and can be adjusted for different security requirements.

| Parameter | Current Value | Purpose | Security Impact |
|-----------|---|---|---|
| ARGON2_TIME_COST | 2 | Argon2id iteration count | Higher = slower brute force, more CPU per derivation |
| ARGON2_MEMORY_COST | 19456 (KiB) | Argon2id memory cost (19 MiB) | Higher = harder to parallelize on GPUs/ASICs |
| ARGON2_PARALLELISM | 1 | Argon2id lanes | Higher = more parallelism; keep at 1 for single-user desktop |
| PBKDF2_ITERATIONS | 310000 | PBKDF2-HMAC-SHA256 fallback rounds | OWASP 2023 minimum for SHA-256 |
| SALT_LENGTH | 16 bytes | Salt randomness | Larger = harder rainbow tables, not noticeable to user |
| NONCE_LENGTH | 12 bytes | Nonce size for GCM | Larger = lower collision risk, current is standard |
| KEY_LENGTH | 32 bytes | AES encryption key | 32 = AES-256, 16 = AES-128 (not used) |
| MIN_PASSWORD_LENGTH | 12 | Master password minimum | Lower = weaker passwords allowed |
| PASSWORD_STRENGTH_ENTROPY_THRESHOLD | 60 bits | Minimum password entropy | Lower = weaker passwords allowed |
| MAX_UNLOCK_ATTEMPTS | 5 | Failed attempts before lockout | Lower = faster lockout, could lock out user |
| UNLOCK_ATTEMPT_BACKOFF_BASE | 2 | Exponential backoff multiplier | Higher = longer delays between attempts |
| CLIPBOARD_CLEAR_TIMEOUT | 15 seconds | Time before clipboard clears | Lower = faster clearing, might be too quick |
| AUTO_LOCK_TIMEOUT | 900 seconds (15 min) | Inactivity before auto-lock | Lower = more frequent locks, higher = longer session |
| AUDIT_LOG_MAX_SIZE | 10 MB | Log rotation threshold | Larger = less frequent rotation, larger files |

---

## Security Testing

The application has been tested with the following security test cases:

**Encryption Tests**
- Verify roundtrip encryption/decryption produces original plaintext
- Verify different plaintexts produce different ciphertexts
- Verify wrong password cannot decrypt vault
- Verify HMAC verification rejects tampered ciphertexts

**Key Derivation Tests**
- Verify same password and salt always produce same key
- Verify different passwords produce different keys
- Verify salt is randomly generated
- Verify Argon2id is actually invoked when `argon2-cffi` is importable
- Verify the PBKDF2 fallback runs when the Argon2 import is patched to fail
- Verify a vault records its KDF parameters in `metadata.kdf` and re-uses them on load

**Brute Force Protection Tests**
- Verify failed attempts are counted
- Verify vault locks after 5 attempts
- Verify exponential backoff is enforced
- Verify lockout survives application restart

**Integrity Tests**
- Verify HMAC verification detects single-bit changes
- Verify vault-level hash detects entry additions
- Verify vault-level hash detects entry deletions
- Verify vault-level hash detects entry reordering

**Edge Cases**
- Unicode characters in passwords
- Very long passwords (1000+ characters)
- Special characters in entry names
- Empty entry notes
- Simultaneous vault operations
- Out-of-order encryption/decryption

---

## Architecture Overview

The application is organized into focused modules:

**vault.py** - Core encryption engine
- VaultManager class handles all encryption/decryption
- Key derivation with Argon2id/PBKDF2 fallback
- AES-256-GCM encryption implementation
- HMAC verification and computation
- Rate limiting and auto-lock logic
- Audit logging integration
- Backup and restore functions

**security.py** - Shared security utilities
- Password strength validation
- HMAC operations and verification
- File permission enforcement (ACLs/chmod)
- Audit log management and rotation
- Memory cleanup (buffer zeroing)
- Entropy calculation

**config.py** - Centralized security configuration
- All KDF parameters in one place
- Encryption settings defined once
- Security policy thresholds
- File path definitions
- Clipboard timeout
- Auto-lock timeout

**gui.py** - Tkinter user interface
- Main window with vault status display
- Entry dialogs for add/edit operations
- Auto-lock countdown timer
- Password strength indicator
- Error display and handling
- Import/export interface

**clipboard_manager.py** - Clipboard functionality
- SecureClipboard class with auto-clear
- Background thread for timeout
- Cross-platform clipboard support
- Fallback to pyperclip

**exceptions.py** - Custom exception hierarchy
- VaultException (base)
- InvalidMasterPasswordError
- WeakPasswordError
- BruteForceDetectedError
- VaultLockedError
- VaultNotLoadedError
- VaultCorruptedError
- And others for specific errors

---

## Conclusion

The password manager implements a comprehensive security architecture with defense-in-depth principles. All core security features are in place and functional. The application is suitable for personal use and provides strong protection against common attack vectors.

The identified weaknesses are primarily related to advanced attack scenarios (memory forensics, side-channel attacks) and convenience features (multi-device sync, master password change). A remediation roadmap is in place to address these weaknesses in future phases.

Current Status: Production-ready for local use with strong cryptographic foundation and comprehensive audit logging.

---

Document Version: 3.0
Last Updated: 2026-04-19 (Phase 2 security remediation)
Review Schedule: Quarterly security audits recommended



