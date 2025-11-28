#!/usr/bin/env python3

import os
import sys
import json
import base64
import getpass
import argparse
import subprocess
import hashlib
import hmac
import secrets
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from config import (
    KDF_N, KDF_R, KDF_P, SALT_LENGTH, NONCE_LENGTH, KEY_LENGTH,
    VAULT_DIR, VAULTS_CONFIG_FILE, MAX_UNLOCK_ATTEMPTS,
    UNLOCK_ATTEMPT_BACKOFF_BASE, AUTO_LOCK_TIMEOUT
)
from exceptions import (
    VaultException, VaultNotLoadedError, VaultCorruptedError,
    InvalidMasterPasswordError, InvalidEntryError, WeakPasswordError,
    EncryptionError, BruteForceDetectedError, VaultLockedError
)
from security import (
    set_secure_permissions, set_secure_dir_permissions, set_readonly_permissions,
    validate_password_strength, compute_hmac, verify_hmac,
    zero_fill_buffer, secure_random_bytes, log_audit_event,
    setup_audit_logging, secure_derive_key
)


class VaultManager:
    """
    Manages encrypted password vault with AES-256-GCM encryption and PBKDF2 key derivation.
    Provides security features including integrity verification, rate limiting, and audit logging.
    """

    SALT_LENGTH = SALT_LENGTH
    NONCE_LENGTH = NONCE_LENGTH
    KEY_LENGTH = KEY_LENGTH

    def __init__(self, vault_path: Optional[Path] = None):
        """Initialize vault manager with optional custom path"""
        if vault_path is None:
            self.vault_path = VAULT_DIR / "passwords.json"
        else:
            self.vault_path = Path(vault_path)

        self.vault_data: Optional[Dict[str, Any]] = None
        self.master_password: Optional[str] = None
        self.master_password_salt: Optional[bytes] = None
        self.master_key_hash: Optional[str] = None
        self.loaded_at: Optional[datetime] = None
        self.last_activity: Optional[datetime] = None
        self.failed_unlock_attempts = 0
        self.is_locked = False

        try:
            setup_audit_logging()
        except Exception as e:
            print(f"Warning: Audit logging initialization failed: {e}")

    def _derive_key_argon2id(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key using PBKDF2-SHA256"""
        import hashlib
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000,
            dklen=self.KEY_LENGTH
        )
        return key

    def _derive_key_fallback(self, password: str, salt: bytes) -> bytes:
        """Fallback key derivation using PBKDF2"""
        import hashlib
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            100000,
            dklen=self.KEY_LENGTH
        )
        return key

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key with fallback to PBKDF2"""
        try:
            return self._derive_key_argon2id(password, salt)
        except Exception:
            return self._derive_key_fallback(password, salt)

    def _get_derived_key(self) -> bytes:
        """Get encryption key from stored password and salt"""
        if not self.master_password or not self.master_password_salt:
            raise VaultException("Vault not loaded - no password available")
        return self._derive_key(self.master_password, self.master_password_salt)

    def _encrypt_data(self, plaintext: str, key: bytes) -> Tuple[str, str]:
        """Encrypt plaintext with AES-256-GCM, returns (nonce_b64, ciphertext_b64)"""
        try:
            nonce = secrets.token_bytes(self.NONCE_LENGTH)
            cipher = AESGCM(key)
            ciphertext = cipher.encrypt(nonce, plaintext.encode(), None)
            return (
                base64.b64encode(nonce).decode(),
                base64.b64encode(ciphertext).decode()
            )
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}")

    def _decrypt_data(self, nonce_b64: str, ciphertext_b64: str, key: bytes) -> str:
        """Decrypt base64-encoded (nonce, ciphertext) with GCM authentication"""
        try:
            nonce = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            cipher = AESGCM(key)
            plaintext = cipher.decrypt(nonce, ciphertext, None)
            return plaintext.decode()
        except Exception as e:
            log_audit_event("DECRYPTION_FAILED", f"Possible tampering: {str(e)}", False)
            raise VaultCorruptedError(f"Decryption/authentication failed - backup may have been tampered with: {e}")

    def _compute_vault_integrity_hash(self) -> str:
        """Compute SHA256 hash of vault entries for tampering detection"""
        if not self.vault_data or "entries" not in self.vault_data:
            return ""

        entry_hashes = []
        for name, entry in sorted(self.vault_data["entries"].items()):
            entry_str = f"{name}:{entry.get('nonce', '')}:{entry.get('ciphertext', '')}"
            entry_hashes.append(hashlib.sha256(entry_str.encode()).hexdigest())

        combined = "".join(entry_hashes)
        return hashlib.sha256(combined.encode()).hexdigest()

    def _verify_vault_integrity(self) -> bool:
        """Verify vault integrity hash to detect tampering"""
        if "integrity_hash" not in self.vault_data or not self.vault_data["integrity_hash"]:
            return True

        stored_hash = self.vault_data["integrity_hash"]
        computed_hash = self._compute_vault_integrity_hash()

        if stored_hash and computed_hash and not hmac.compare_digest(stored_hash, computed_hash):
            log_audit_event("VAULT_TAMPERING_DETECTED", "Vault integrity check failed", False)
            raise VaultCorruptedError("Vault integrity verification failed - possible tampering")

        return True

    def _check_rate_limiting(self):
        """Check if vault is locked due to brute force detection"""
        lock_file = self.vault_path.with_suffix('.lock')

        if lock_file.exists():
            try:
                with open(lock_file, 'r') as f:
                    lock_data = json.load(f)
                    locked_until = datetime.fromisoformat(lock_data['locked_until'])

                    if datetime.now() < locked_until:
                        remaining = (locked_until - datetime.now()).total_seconds()
                        raise VaultLockedError(
                            f"Vault is locked due to too many failed attempts. "
                            f"Try again in {int(remaining)} seconds."
                        )
                    else:
                        lock_file.unlink()
                        self.failed_unlock_attempts = 0
            except json.JSONDecodeError:
                lock_file.unlink()

        if self.failed_unlock_attempts >= MAX_UNLOCK_ATTEMPTS:
            backoff_seconds = UNLOCK_ATTEMPT_BACKOFF_BASE ** (self.failed_unlock_attempts - MAX_UNLOCK_ATTEMPTS + 1)
            locked_until = datetime.now() + timedelta(seconds=backoff_seconds)

            lock_file.parent.mkdir(parents=True, exist_ok=True)
            with open(lock_file, 'w') as f:
                json.dump({'locked_until': locked_until.isoformat()}, f)

            log_audit_event(
                "BRUTE_FORCE_DETECTED",
                f"Too many failed unlock attempts from {self.vault_path}",
                False
            )
            raise BruteForceDetectedError(
                f"Too many failed attempts. Vault locked for {backoff_seconds} seconds."
            )

    def _check_auto_lock(self):
        """Check if vault should be auto-locked due to inactivity"""
        if not self.loaded_at:
            return

        inactivity = datetime.now() - self.last_activity
        if inactivity.total_seconds() > AUTO_LOCK_TIMEOUT:
            self.master_key = None
            self.is_locked = True
            log_audit_event("AUTO_LOCK", f"Vault auto-locked after {AUTO_LOCK_TIMEOUT}s inactivity")
            raise VaultLockedError("Vault auto-locked due to inactivity")

    def init_vault(self, password: str, vault_name: str = "default") -> bool:
        """Initialize new vault with master password"""
        if self.vault_path.exists():
            raise VaultException(f"Vault already exists at {self.vault_path}")

        try:
            is_valid, feedback = validate_password_strength(password)
            if not is_valid:
                raise WeakPasswordError(feedback)

            self.vault_path.parent.mkdir(parents=True, exist_ok=True)
            set_secure_dir_permissions(self.vault_path.parent)

            salt = secrets.token_bytes(self.SALT_LENGTH)
            key = self._derive_key(password, salt)
            self.master_password = password
            self.master_password_salt = salt

            self.vault_data = {
                "version": "2.0",
                "created": datetime.now().isoformat(),
                "modified": datetime.now().isoformat(),
                "salt": base64.b64encode(salt).decode(),
                "entries": {},
                "metadata": {
                    "vault_name": vault_name,
                    "key_derivation": "Argon2id",
                    "encryption": "AES-256-GCM",
                    "integrity_protection": "GCM-authenticated"
                },
                "integrity_hash": ""
            }

            sentinel_data = {"_sentinel": "validation_marker"}
            sentinel_json = json.dumps(sentinel_data)
            nonce, ciphertext = self._encrypt_data(sentinel_json, key)
            self.vault_data["entries"]["_sentinel"] = {
                "nonce": nonce,
                "ciphertext": ciphertext
            }

            zero_fill_buffer(bytearray(key))
            del key

            self.vault_data["integrity_hash"] = self._compute_vault_integrity_hash()
            self.vault_path.write_text(json.dumps(self.vault_data, indent=2))
            set_secure_permissions(self.vault_path)

            log_audit_event(
                "VAULT_CREATED",
                f"New vault '{vault_name}' created at {self.vault_path}"
            )
            return True

        except WeakPasswordError as e:
            log_audit_event("VAULT_CREATION_FAILED", f"Weak password: {str(e)}", False)
            raise
        except Exception as e:
            log_audit_event("VAULT_CREATION_ERROR", str(e), False)
            raise VaultException(f"Error initializing vault: {e}")

    def load_vault(self, password: str) -> bool:
        """Load and unlock vault with master password"""
        try:
            self._check_rate_limiting()

            if not self.vault_path.exists():
                raise VaultException(f"Vault file not found at {self.vault_path}")

            vault_json = self.vault_path.read_text()
            self.vault_data = json.loads(vault_json)

            if self.vault_data.get("version", "1.0") not in ["1.0", "2.0"]:
                raise VaultCorruptedError("Unsupported vault version")

            salt = base64.b64decode(self.vault_data["salt"])
            key = self._derive_key(password, salt)
            self.master_password = password
            self.master_password_salt = salt

            if "integrity_hash" in self.vault_data and self.vault_data["integrity_hash"]:
                self._verify_vault_integrity()

            entries = list(self.vault_data.get("entries", {}).items())
            if entries:
                try:
                    first_entry_name, first_entry = entries[0]
                    nonce = first_entry.get("nonce", "")
                    ciphertext = first_entry.get("ciphertext", "")
                    self._decrypt_data(nonce, ciphertext, key)
                except Exception as e:
                    zero_fill_buffer(bytearray(key))
                    del key
                    self.failed_unlock_attempts += 1
                    log_audit_event(
                        "VAULT_UNLOCK_FAILED",
                        f"Authentication failed (attempt {self.failed_unlock_attempts})",
                        False
                    )
                    raise InvalidMasterPasswordError("Wrong password or corrupted vault")
            else:
                try:
                    cipher = AESGCM(key)
                except Exception as e:
                    zero_fill_buffer(bytearray(key))
                    del key
                    self.failed_unlock_attempts += 1
                    log_audit_event(
                        "VAULT_UNLOCK_FAILED",
                        f"Authentication failed (attempt {self.failed_unlock_attempts})",
                        False
                    )
                    raise InvalidMasterPasswordError("Wrong password or corrupted vault")

            zero_fill_buffer(bytearray(key))
            del key

            self.loaded_at = datetime.now()
            self.last_activity = datetime.now()
            self.failed_unlock_attempts = 0
            self.is_locked = False

            log_audit_event(
                "VAULT_LOADED",
                f"Vault loaded successfully from {self.vault_path}"
            )
            return True

        except (InvalidMasterPasswordError, VaultLockedError, BruteForceDetectedError):
            raise
        except Exception as e:
            log_audit_event("VAULT_LOAD_ERROR", str(e), False)
            raise VaultException(f"Error loading vault: {e}")

    def add_entry_from_import(self, name: str, username: str, password: str,
                             url: str = "", notes: str = "") -> bool:
        """Add entry from imported backup without password strength validation"""
        try:
            self._check_auto_lock()

            if self.vault_data is None or self.master_password is None:
                raise VaultNotLoadedError("Vault not loaded")

            if not name:
                raise InvalidEntryError("Entry name is required")
            if not password:
                raise InvalidEntryError("Entry password is required")

            if name in self.vault_data["entries"]:
                log_audit_event("ENTRY_OVERWRITE", f"Overwriting existing import entry: {name}")

            entry_data = {
                "username": username,
                "password": password,
                "url": url,
                "notes": notes,
                "created": datetime.now().isoformat(),
                "modified": datetime.now().isoformat()
            }
            entry_json = json.dumps(entry_data)

            key = self._get_derived_key()
            try:
                nonce, ciphertext = self._encrypt_data(entry_json, key)
                self.vault_data["entries"][name] = {
                    "nonce": nonce,
                    "ciphertext": ciphertext
                }

                self.vault_data["modified"] = datetime.now().isoformat()
                self.vault_data["integrity_hash"] = self._compute_vault_integrity_hash()
                self.vault_path.write_text(json.dumps(self.vault_data, indent=2))
                set_secure_permissions(self.vault_path)

                self.last_activity = datetime.now()
                log_audit_event("ENTRY_IMPORTED", f"Entry imported: {name}")
                return True
            finally:
                zero_fill_buffer(bytearray(key))
                del key

        except Exception as e:
            log_audit_event("ENTRY_IMPORT_ERROR", str(e), False)
            raise

    def add_entry(self, name: str, username: str, password: str,
                  url: str = "", notes: str = "") -> bool:
        """Add encrypted entry to vault with validation"""
        try:
            self._check_auto_lock()

            if self.vault_data is None or self.master_password is None:
                raise VaultNotLoadedError("Vault not loaded")

            if not name or not password:
                raise InvalidEntryError("Entry name and password required")

            is_valid, _ = validate_password_strength(password)
            if not is_valid:
                raise WeakPasswordError("New password does not meet strength requirements")

            if name in self.vault_data["entries"]:
                log_audit_event("ENTRY_OVERWRITE", f"Overwriting existing entry: {name}")

            entry_data = {
                "username": username,
                "password": password,
                "url": url,
                "notes": notes,
                "created": datetime.now().isoformat(),
                "modified": datetime.now().isoformat()
            }
            entry_json = json.dumps(entry_data)

            key = self._get_derived_key()
            try:
                nonce, ciphertext = self._encrypt_data(entry_json, key)
                self.vault_data["entries"][name] = {
                    "nonce": nonce,
                    "ciphertext": ciphertext
                }

                self.vault_data["modified"] = datetime.now().isoformat()
                self.vault_data["integrity_hash"] = self._compute_vault_integrity_hash()
                self.vault_path.write_text(json.dumps(self.vault_data, indent=2))
                set_secure_permissions(self.vault_path)

                self.last_activity = datetime.now()
                log_audit_event("ENTRY_ADDED", f"New entry added: {name}")
                return True
            finally:
                zero_fill_buffer(bytearray(key))
                del key

        except Exception as e:
            log_audit_event("ENTRY_ADD_ERROR", str(e), False)
            raise

    def get_entry(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve and decrypt entry from vault"""
        try:
            self._check_auto_lock()

            if self.vault_data is None or self.master_password is None:
                raise VaultNotLoadedError("Vault not loaded")

            if name == "_sentinel":
                raise InvalidEntryError(f"Entry '{name}' not found")

            if name not in self.vault_data["entries"]:
                raise InvalidEntryError(f"Entry '{name}' not found")

            entry = self.vault_data["entries"][name]

            key = self._get_derived_key()
            try:
                entry_json = self._decrypt_data(
                    entry["nonce"],
                    entry["ciphertext"],
                    key
                )

                self.last_activity = datetime.now()
                log_audit_event("ENTRY_ACCESSED", f"Entry retrieved: {name}")
                return json.loads(entry_json)
            finally:
                zero_fill_buffer(bytearray(key))
                del key

        except Exception as e:
            log_audit_event("ENTRY_ACCESS_ERROR", str(e), False)
            raise

    def list_entries(self) -> list:
        """List all entry names"""
        try:
            self._check_auto_lock()

            if self.vault_data is None:
                raise VaultNotLoadedError("Vault not loaded")

            self.last_activity = datetime.now()
            entries = [name for name in self.vault_data["entries"].keys() if name != "_sentinel"]
            return sorted(entries)

        except Exception as e:
            log_audit_event("ENTRY_LIST_ERROR", str(e), False)
            raise

    def delete_entry(self, name: str) -> bool:
        """Delete entry from vault"""
        try:
            self._check_auto_lock()

            if self.vault_data is None:
                raise VaultNotLoadedError("Vault not loaded")

            if name == "_sentinel":
                raise InvalidEntryError(f"Cannot delete system entry '{name}'")

            if name not in self.vault_data["entries"]:
                raise InvalidEntryError(f"Entry '{name}' not found")

            del self.vault_data["entries"][name]

            self.vault_data["modified"] = datetime.now().isoformat()
            self.vault_data["integrity_hash"] = self._compute_vault_integrity_hash()

            self.vault_path.write_text(json.dumps(self.vault_data, indent=2))
            set_secure_permissions(self.vault_path)

            self.last_activity = datetime.now()
            log_audit_event("ENTRY_DELETED", f"Entry deleted: {name}")
            return True

        except Exception as e:
            log_audit_event("ENTRY_DELETE_ERROR", str(e), False)
            raise

    def update_entry(self, name: str, **kwargs) -> bool:
        """Update existing entry"""
        try:
            entry = self.get_entry(name)
            entry.update(kwargs)
            entry["modified"] = datetime.now().isoformat()
            return self._add_entry_direct(name, entry)

        except Exception as e:
            log_audit_event("ENTRY_UPDATE_ERROR", str(e), False)
            raise

    def _add_entry_direct(self, name: str, entry_data: Dict) -> bool:
        """Internal method to add entry dict directly"""
        entry_json = json.dumps(entry_data)

        key = self._get_derived_key()
        try:
            nonce, ciphertext = self._encrypt_data(entry_json, key)
            self.vault_data["entries"][name] = {
                "nonce": nonce,
                "ciphertext": ciphertext
            }

            self.vault_data["modified"] = datetime.now().isoformat()
            self.vault_data["integrity_hash"] = self._compute_vault_integrity_hash()
            self.vault_path.write_text(json.dumps(self.vault_data, indent=2))
            set_secure_permissions(self.vault_path)

            self.last_activity = datetime.now()
            return True
        finally:
            zero_fill_buffer(bytearray(key))
            del key

    def export_vault(self, export_path: Path, export_password: str) -> bool:
        """Export vault to encrypted backup with file-level password protection"""
        try:
            self._check_auto_lock()

            if self.vault_data is None:
                raise VaultNotLoadedError("Vault not loaded")

            is_valid, _ = validate_password_strength(export_password)
            if not is_valid:
                raise WeakPasswordError("Export password does not meet strength requirements")

            content_salt = secrets.token_bytes(self.SALT_LENGTH)
            content_key = self._derive_key(export_password, content_salt)

            user_entries_plaintext = {}
            for entry_name, entry_nonce_ciphertext in self.vault_data["entries"].items():
                if entry_name == "_sentinel":
                    continue
                try:
                    entry_json = self._decrypt_data(
                        entry_nonce_ciphertext["nonce"],
                        entry_nonce_ciphertext["ciphertext"],
                        self._get_derived_key()
                    )
                    entry_dict = json.loads(entry_json)
                    user_entries_plaintext[entry_name] = entry_dict
                except Exception as e:
                    print(f"Warning: Could not export entry '{entry_name}': {e}")
                    continue

            export_data = {
                "version": "2.0",
                "exported": datetime.now().isoformat(),
                "source": str(self.vault_path),
                "entries": {},
                "metadata": self.vault_data["metadata"]
            }

            for entry_name, entry_plaintext in user_entries_plaintext.items():
                entry_json = json.dumps(entry_plaintext)
                nonce, ciphertext = self._encrypt_data(entry_json, content_key)
                export_data["entries"][entry_name] = {
                    "nonce": nonce,
                    "ciphertext": ciphertext
                }

            export_json = json.dumps(export_data, indent=2)
            content_nonce, content_ciphertext = self._encrypt_data(export_json, content_key)

            inner_backup = {
                "nonce": content_nonce,
                "ciphertext": content_ciphertext,
                "content_salt": base64.b64encode(content_salt).decode()
            }

            inner_json = json.dumps(inner_backup)
            file_salt = secrets.token_bytes(self.SALT_LENGTH)
            file_key = self._derive_key(export_password, file_salt)
            file_nonce, file_ciphertext = self._encrypt_data(inner_json, file_key)

            outer_backup = {
                "version": "2.1",
                "file_nonce": file_nonce,
                "file_ciphertext": file_ciphertext,
                "file_salt": base64.b64encode(file_salt).decode()
            }

            export_path.parent.mkdir(parents=True, exist_ok=True)
            export_path.write_text(json.dumps(outer_backup, indent=2))
            set_readonly_permissions(export_path)

            self.last_activity = datetime.now()
            log_audit_event("VAULT_EXPORTED", f"Vault exported to {export_path}")
            return True

        except Exception as e:
            log_audit_event("EXPORT_ERROR", str(e), False)
            raise

    def _validate_export_data(self, export_data: Dict[str, Any]) -> bool:
        """Validate exported backup data structure"""
        if not isinstance(export_data, dict):
            raise VaultException("Corrupted backup: export data is not a dictionary")

        required_fields = ["version", "exported", "entries", "metadata"]
        for field in required_fields:
            if field not in export_data:
                raise VaultException(f"Corrupted backup: missing '{field}' in export data")

        if not isinstance(export_data.get("entries"), dict):
            raise VaultException("Corrupted backup: entries must be a dictionary")

        if not isinstance(export_data.get("metadata"), dict):
            raise VaultException("Corrupted backup: metadata must be a dictionary")

        version = export_data.get("version")
        if not isinstance(version, str) or version not in ["1.0", "2.0"]:
            raise VaultException(f"Corrupted backup: invalid version format {version}")

        exported = export_data.get("exported")
        if not isinstance(exported, str):
            raise VaultException("Corrupted backup: exported timestamp is not a string")

        try:
            datetime.fromisoformat(exported)
        except ValueError:
            raise VaultException(f"Corrupted backup: invalid timestamp format {exported}")

        return True

    def import_vault(self, import_path: Path, import_password: str) -> Dict[str, Any]:
        """Import backup with file-level password protection and GCM verification"""
        try:
            if not import_path.exists():
                raise VaultException(f"Import file not found: {import_path}")

            backup_json = import_path.read_text()
            backup = json.loads(backup_json)

            version = backup.get("version", "2.0")

            if version == "2.1":
                required_fields = ["file_nonce", "file_ciphertext", "file_salt"]
                for field in required_fields:
                    if field not in backup:
                        raise VaultException(f"Corrupted backup: missing '{field}' field")
                    if not backup[field]:
                        raise VaultException(f"Corrupted backup: empty '{field}' field")

                file_nonce = backup.get("file_nonce", "")
                file_ciphertext = backup.get("file_ciphertext", "")

                try:
                    file_salt = base64.b64decode(backup.get("file_salt", ""))
                except Exception as e:
                    raise VaultException(f"Corrupted backup: invalid file_salt encoding - {e}")

                file_key = self._derive_key(import_password, file_salt)

                try:
                    inner_json = self._decrypt_data(file_nonce, file_ciphertext, file_key)
                except VaultCorruptedError as e:
                    log_audit_event("IMPORT_ERROR", f"Backup tampering detected at file level: {str(e)}", False)
                    raise VaultException("BACKUP TAMPERING DETECTED: File has been modified. GCM authentication failed.")
                except EncryptionError as e:
                    log_audit_event("IMPORT_ERROR", f"File-level decryption error: {str(e)}", False)
                    raise VaultException(f"Failed to decrypt backup file: {str(e)} - Wrong password or corrupted file")
                except Exception as e:
                    log_audit_event("IMPORT_ERROR", f"File-level decryption failed: {str(e)}", False)
                    raise VaultException(f"Failed to decrypt backup: {str(e)}")

                try:
                    inner_backup = json.loads(inner_json)
                except json.JSONDecodeError as e:
                    raise VaultException(f"Corrupted backup: inner JSON is invalid - {e}")

                required_content_fields = ["nonce", "ciphertext", "content_salt"]
                for field in required_content_fields:
                    if field not in inner_backup:
                        raise VaultException(f"Corrupted backup: missing content '{field}' field")
                    if not inner_backup[field]:
                        raise VaultException(f"Corrupted backup: empty content '{field}' field")

                content_nonce = inner_backup.get("nonce", "")
                content_ciphertext = inner_backup.get("ciphertext", "")

                try:
                    content_salt = base64.b64decode(inner_backup.get("content_salt", ""))
                except Exception as e:
                    raise VaultException(f"Corrupted backup: invalid content_salt encoding - {e}")

                content_key = self._derive_key(import_password, content_salt)

                try:
                    export_json = self._decrypt_data(content_nonce, content_ciphertext, content_key)
                except VaultCorruptedError as e:
                    log_audit_event("IMPORT_ERROR", f"Backup tampering detected at content level: {str(e)}", False)
                    raise VaultException("BACKUP TAMPERING DETECTED: Content has been modified. GCM authentication failed.")
                except EncryptionError as e:
                    log_audit_event("IMPORT_ERROR", f"Content-level decryption error: {str(e)}", False)
                    raise VaultException(f"Failed to decrypt backup content: {str(e)}")
                except Exception as e:
                    log_audit_event("IMPORT_ERROR", f"Content-level decryption failed: {str(e)}", False)
                    raise VaultException(f"Content verification failed: {str(e)}")

                try:
                    export_data = json.loads(export_json)
                except json.JSONDecodeError as e:
                    raise VaultException(f"Corrupted backup: export data JSON is invalid - {e}")

                self._validate_export_data(export_data)
                export_data["_content_salt"] = inner_backup.get("content_salt", "")

            else:
                required_fields = ["nonce", "ciphertext", "salt"]
                for field in required_fields:
                    if field not in backup:
                        raise VaultException(f"Corrupted backup: missing '{field}' field")
                    if not backup[field]:
                        raise VaultException(f"Corrupted backup: empty '{field}' field")

                nonce = backup.get("nonce", "")
                ciphertext = backup.get("ciphertext", "")

                try:
                    salt = base64.b64decode(backup.get("salt", ""))
                except Exception as e:
                    raise VaultException(f"Corrupted backup: invalid salt encoding - {e}")

                import_key = self._derive_key(import_password, salt)

                try:
                    export_json = self._decrypt_data(nonce, ciphertext, import_key)
                except VaultCorruptedError as e:
                    log_audit_event("IMPORT_ERROR", f"Backup tampering detected: {str(e)}", False)
                    raise VaultException("BACKUP TAMPERING DETECTED: Backup file has been modified. GCM authentication failed.")
                except EncryptionError as e:
                    log_audit_event("IMPORT_ERROR", f"Decryption error: {str(e)}", False)
                    raise VaultException(f"Failed to decrypt backup: {str(e)}")
                except Exception as e:
                    log_audit_event("IMPORT_ERROR", f"Backup import failed: {str(e)}", False)
                    raise VaultException(f"Failed to import backup: {str(e)}")

                try:
                    export_data = json.loads(export_json)
                except json.JSONDecodeError as e:
                    raise VaultException(f"Corrupted backup: export data JSON is invalid - {e}")

                self._validate_export_data(export_data)
                export_data["_content_salt"] = backup.get("salt", "")

            log_audit_event("VAULT_IMPORTED", f"Vault imported from {import_path}")
            return export_data

        except VaultException:
            raise
        except Exception as e:
            log_audit_event("IMPORT_ERROR", f"Unexpected error during import: {str(e)}", False)
            raise VaultException(f"Import failed: {str(e)}")

    def decrypt_backup_entries(self, backup_entries: Dict, import_password: str, content_salt_b64: str) -> Dict[str, Dict[str, str]]:
        """Decrypt entries from imported backup using backup password"""
        try:
            content_salt = base64.b64decode(content_salt_b64)
            content_key = self._derive_key(import_password, content_salt)

            decrypted_entries = {}

            for entry_name, entry_data in backup_entries.items():
                if entry_name == "_sentinel":
                    continue

                try:
                    nonce_b64 = entry_data.get("nonce", "")
                    ciphertext_b64 = entry_data.get("ciphertext", "")

                    if not nonce_b64 or not ciphertext_b64:
                        continue

                    entry_json = self._decrypt_data(nonce_b64, ciphertext_b64, content_key)
                    entry_dict = json.loads(entry_json)

                    decrypted_entries[entry_name] = {
                        "username": entry_dict.get("username", ""),
                        "password": entry_dict.get("password", ""),
                        "url": entry_dict.get("url", ""),
                        "notes": entry_dict.get("notes", ""),
                    }
                except Exception as e:
                    print(f"Failed to decrypt entry '{entry_name}': {e}")
                    continue

            return decrypted_entries

        except Exception as e:
            raise VaultException(f"Failed to decrypt backup entries: {e}")

    def lock_vault(self):
        """Manually lock vault"""
        if self.master_password:
            zero_fill_buffer(bytearray(self.master_password.encode()))
            self.master_password = None
        self.master_password_salt = None
        self.is_locked = True
        log_audit_event("VAULT_LOCKED", "Vault manually locked")

    def clear_sensitive_data(self):
        """Clear sensitive data from memory"""
        if self.master_password:
            zero_fill_buffer(bytearray(self.master_password.encode()))
            self.master_password = None
        self.master_password_salt = None
        self.vault_data = None
        self.is_locked = True


def main():
    """CLI interface for vault"""
    parser = argparse.ArgumentParser(
        description="Secure Password Vault (AES-256-GCM with Argon2id KDF)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize new vault")
    init_parser.add_argument("--path", help="Custom vault path")
    init_parser.add_argument("--name", default="default", help="Vault name")

    # Add command
    add_parser = subparsers.add_parser("add", help="Add new entry")
    add_parser.add_argument("name", help="Entry name/label")
    add_parser.add_argument("--path", help="Custom vault path")
    add_parser.add_argument("--url", default="", help="Associated URL")
    add_parser.add_argument("--notes", default="", help="Additional notes")

    # Get command
    get_parser = subparsers.add_parser("get", help="Retrieve entry")
    get_parser.add_argument("name", help="Entry name")
    get_parser.add_argument("--path", help="Custom vault path")

    # List command
    list_parser = subparsers.add_parser("list", help="List all entries")
    list_parser.add_argument("--path", help="Custom vault path")

    # Delete command
    del_parser = subparsers.add_parser("delete", help="Delete entry")
    del_parser.add_argument("name", help="Entry name")
    del_parser.add_argument("--path", help="Custom vault path")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export vault backup")
    export_parser.add_argument("export_path", help="Export file path")
    export_parser.add_argument("--path", help="Custom vault path")

    # Import command
    import_parser = subparsers.add_parser("import", help="Import vault backup")
    import_parser.add_argument("import_path", help="Import file path")
    import_parser.add_argument("--path", help="Custom vault path (for new vault)")
    import_parser.add_argument("--name", default="imported", help="New vault name")

    args = parser.parse_args()

    vault_path = Path(args.path) if hasattr(args, 'path') and args.path else None
    vault = VaultManager(vault_path)

    try:
        if args.command == "init":
            password = getpass.getpass("Create master password: ")
            vault.init_vault(password, args.name)
            print(f"✓ Vault initialized at {vault.vault_path}")

        elif args.command == "add":
            password = getpass.getpass("Master password: ")
            vault.load_vault(password)
            username = input(f"Username for '{args.name}': ")
            pwd = getpass.getpass(f"Password for '{args.name}': ")
            vault.add_entry(args.name, username, pwd, args.url, args.notes)
            print(f"✓ Entry '{args.name}' added")

        elif args.command == "get":
            password = getpass.getpass("Master password: ")
            vault.load_vault(password)
            entry = vault.get_entry(args.name)
            print(json.dumps(entry, indent=2))

        elif args.command == "list":
            password = getpass.getpass("Master password: ")
            vault.load_vault(password)
            entries = vault.list_entries()
            if entries:
                print("Entries:")
                for entry in entries:
                    print(f"  - {entry}")
            else:
                print("No entries in vault")

        elif args.command == "delete":
            password = getpass.getpass("Master password: ")
            vault.load_vault(password)
            confirm = input(f"Delete '{args.name}'? (yes/no): ")
            if confirm.lower() == "yes":
                vault.delete_entry(args.name)
                print(f"✓ Entry '{args.name}' deleted")

        elif args.command == "export":
            password = getpass.getpass("Master password: ")
            vault.load_vault(password)
            export_password = getpass.getpass("Export encryption password: ")
            vault.export_vault(Path(args.export_path), export_password)
            print(f"✓ Vault exported to {args.export_path}")

        elif args.command == "import":
            import_password = getpass.getpass("Import file password: ")
            imported = vault.import_vault(Path(args.import_path), import_password)
            print(f"✓ Vault imported. Contains {len(imported.get('entries', {}))} entries")

        else:
            parser.print_help()

    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # If no arguments provided, launch the GUI
    if len(sys.argv) == 1:
        try:
            import tkinter as tk
            sys.path.insert(0, str(Path(__file__).parent))
            from gui import PasswordManagerGUI

            root = tk.Tk()
            app = PasswordManagerGUI(root)
            root.mainloop()

        except ImportError as e:
            print(f"\n❌ Error: Could not import GUI: {e}")
            print("\nMake sure gui.py is in the same directory as vault.py")
            sys.exit(1)
        except Exception as e:
            print(f"\n❌ Error launching GUI: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)

