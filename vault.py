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
    SALT_LENGTH, NONCE_LENGTH, KEY_LENGTH,
    ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM,
    PBKDF2_ITERATIONS, VAULT_FORMAT_VERSION, BACKUP_FORMAT_VERSION,
    VALIDATION_TOKEN_PLAINTEXT,
    VAULT_DIR, VAULTS_CONFIG_FILE, MAX_UNLOCK_ATTEMPTS,
    UNLOCK_ATTEMPT_BACKOFF_BASE, AUTO_LOCK_TIMEOUT
)

try:
    from argon2 import low_level as _argon2_low_level
    from argon2 import Type as _Argon2Type
    ARGON2_AVAILABLE = True
except ImportError:
    _argon2_low_level = None
    _Argon2Type = None
    ARGON2_AVAILABLE = False
from exceptions import (
    VaultException, VaultNotLoadedError, VaultCorruptedError,
    InvalidMasterPasswordError, InvalidEntryError, WeakPasswordError,
    EncryptionError, BruteForceDetectedError, VaultLockedError
)
from security import (
    set_secure_permissions, set_secure_dir_permissions, set_readonly_permissions,
    set_vault_file_permissions, make_vault_writable,
    validate_password_strength, compute_hmac, verify_hmac,
    zero_fill_buffer, wipe_key, try_lock_memory,
    secure_random_bytes, log_audit_event,
    setup_audit_logging, secure_derive_key
)


class VaultManager:
    """
    Manages an encrypted password vault. AES-256-GCM for entry encryption.
    Argon2id for key derivation, with a PBKDF2-HMAC-SHA256 fallback at 310k
    iterations if argon2-cffi is not importable. Also provides integrity
    verification, rate limiting, and audit logging.
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
        # Plaintext of the encrypted_metadata block (validation_token + timestamps).
        # Populated at init_vault / load_vault time, re-encrypted on each write.
        self._meta_plaintext: Optional[Dict[str, str]] = None

        try:
            setup_audit_logging()
        except Exception as e:
            print(f"Warning: Audit logging initialization failed: {e}")

    def _derive_key_argon2id(
        self,
        password: str,
        salt: bytes,
        time_cost: int = ARGON2_TIME_COST,
        memory_cost: int = ARGON2_MEMORY_COST,
        parallelism: int = ARGON2_PARALLELISM,
    ) -> bytearray:
        """Derive encryption key using Argon2id. Returns a locked bytearray."""
        if not ARGON2_AVAILABLE:
            raise EncryptionError("argon2-cffi is not available")
        raw = _argon2_low_level.hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=self.KEY_LENGTH,
            type=_Argon2Type.ID,
        )
        buf = bytearray(raw)
        try_lock_memory(buf)
        return buf

    def _derive_key_fallback(
        self,
        password: str,
        salt: bytes,
        iterations: int = PBKDF2_ITERATIONS,
    ) -> bytearray:
        """PBKDF2-HMAC-SHA256 fallback. Returns a locked bytearray."""
        raw = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=self.KEY_LENGTH,
        )
        buf = bytearray(raw)
        try_lock_memory(buf)
        return buf

    @staticmethod
    def _build_default_kdf_metadata() -> Dict[str, Any]:
        """Return the kdf metadata dict for a new vault."""
        if ARGON2_AVAILABLE:
            return {
                "name": "Argon2id",
                "time_cost": ARGON2_TIME_COST,
                "memory_cost": ARGON2_MEMORY_COST,
                "parallelism": ARGON2_PARALLELISM,
                "hash_len": KEY_LENGTH,
                "salt_length": SALT_LENGTH,
            }
        return {
            "name": "PBKDF2-HMAC-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "hash_len": KEY_LENGTH,
            "salt_length": SALT_LENGTH,
        }

    def _derive_key_from_metadata(
        self, password: str, salt: bytes, kdf_meta: Dict[str, Any]
    ) -> bytearray:
        """Derive a key using the KDF recorded in vault metadata."""
        name = kdf_meta.get("name")
        if name == "Argon2id":
            return self._derive_key_argon2id(
                password,
                salt,
                time_cost=kdf_meta.get("time_cost", ARGON2_TIME_COST),
                memory_cost=kdf_meta.get("memory_cost", ARGON2_MEMORY_COST),
                parallelism=kdf_meta.get("parallelism", ARGON2_PARALLELISM),
            )
        if name == "PBKDF2-HMAC-SHA256":
            return self._derive_key_fallback(
                password,
                salt,
                iterations=kdf_meta.get("iterations", PBKDF2_ITERATIONS),
            )
        raise VaultException(f"Unsupported KDF in vault metadata: {name!r}")

    def _derive_key(self, password: str, salt: bytes) -> bytearray:
        """Derive an encryption key using the best KDF available.

        Used for fresh vaults and for backup file/content keys. Reading an
        existing vault always goes through _derive_key_from_metadata so the
        recorded params are honoured.
        """
        return self._derive_key_from_metadata(
            password, salt, self._build_default_kdf_metadata()
        )

    def _get_derived_key(self) -> bytearray:
        """Derive the master key using this vault's recorded KDF metadata.

        Returns a locked bytearray. The caller MUST invoke `wipe_key(buf)` in
        a `finally` block to zero and unlock the memory.
        """
        if not self.master_password or not self.master_password_salt:
            raise VaultException("Vault not loaded - no password available")
        kdf_meta = (self.vault_data or {}).get("metadata", {}).get("kdf")
        if not kdf_meta:
            # Back-compat path for code that derives before vault_data is
            # populated. Uses the default (Argon2id if available).
            kdf_meta = self._build_default_kdf_metadata()
        return self._derive_key_from_metadata(
            self.master_password, self.master_password_salt, kdf_meta
        )

    def _encrypt_data(self, plaintext: str, key) -> Tuple[str, str]:
        """Encrypt plaintext with AES-256-GCM, returns (nonce_b64, ciphertext_b64).

        `key` may be bytes or bytearray; AESGCM accepts both via buffer protocol.
        """
        try:
            nonce = secrets.token_bytes(self.NONCE_LENGTH)
            cipher = AESGCM(key if isinstance(key, (bytes, bytearray)) else bytes(key))
            ciphertext = cipher.encrypt(nonce, plaintext.encode(), None)
            return (
                base64.b64encode(nonce).decode(),
                base64.b64encode(ciphertext).decode()
            )
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}")

    def _decrypt_data(self, nonce_b64: str, ciphertext_b64: str, key) -> str:
        """Decrypt base64-encoded (nonce, ciphertext) with GCM authentication."""
        try:
            nonce = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            cipher = AESGCM(key if isinstance(key, (bytes, bytearray)) else bytes(key))
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
            if self.master_password:
                zero_fill_buffer(bytearray(self.master_password.encode()))
            self.master_password = None
            self.master_password_salt = None
            self.vault_data = None
            self._meta_plaintext = None
            self.is_locked = True
            log_audit_event("AUTO_LOCK", f"Vault auto-locked after {AUTO_LOCK_TIMEOUT}s inactivity")
            raise VaultLockedError("Vault auto-locked due to inactivity")

    def _refresh_encrypted_metadata(self) -> None:
        """Re-encrypt the metadata block (validation_token + timestamps).

        Bumps `modified` to now and re-encrypts with a fresh nonce. The
        ciphertext goes into `vault_data["encrypted_metadata"]`. Preserves
        `created` from the instance's current plaintext.
        """
        if self._meta_plaintext is None:
            raise VaultException("Encrypted metadata not initialized")
        self._meta_plaintext["modified"] = datetime.now().isoformat()
        meta_json = json.dumps(self._meta_plaintext, sort_keys=True)

        key = self._get_derived_key()
        try:
            nonce, ciphertext = self._encrypt_data(meta_json, key)
        finally:
            wipe_key(key)

        self.vault_data["encrypted_metadata"] = {
            "nonce": nonce,
            "ciphertext": ciphertext,
        }

    def _persist_vault(self) -> None:
        """Write vault_data to disk with secure permissions.

        Relaxes the on-disk perms to owner-rw just long enough to rewrite
        the file, then restores owner-read-only. New files go straight to
        owner-read-only. Callers must have already refreshed the encrypted
        metadata and integrity hash.
        """
        make_vault_writable(self.vault_path)
        self.vault_path.write_text(json.dumps(self.vault_data, indent=2))
        set_vault_file_permissions(self.vault_path)

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
            kdf_meta = self._build_default_kdf_metadata()
            self.master_password = password
            self.master_password_salt = salt

            now_iso = datetime.now().isoformat()
            self._meta_plaintext = {
                "validation_token": VALIDATION_TOKEN_PLAINTEXT,
                "created": now_iso,
                "modified": now_iso,
            }

            self.vault_data = {
                "version": VAULT_FORMAT_VERSION,
                "salt": base64.b64encode(salt).decode(),
                "encrypted_metadata": {},
                "entries": {},
                "metadata": {
                    "vault_name": vault_name,
                    "kdf": kdf_meta,
                    "encryption": "AES-256-GCM",
                    "integrity_protection": "GCM-authenticated",
                },
                "integrity_hash": "",
            }

            # Encrypts using _get_derived_key, which reads vault_data.metadata.kdf.
            self._refresh_encrypted_metadata()
            self.vault_data["integrity_hash"] = self._compute_vault_integrity_hash()
            self._persist_vault()

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

            version = self.vault_data.get("version", "1.0")
            if version != VAULT_FORMAT_VERSION:
                raise VaultException(
                    f"Unsupported vault format '{version}'. This build "
                    f"requires version {VAULT_FORMAT_VERSION}. Older vaults "
                    "are not migrated automatically."
                )

            kdf_meta = self.vault_data.get("metadata", {}).get("kdf")
            if not kdf_meta:
                raise VaultCorruptedError("Vault metadata missing KDF specification")

            enc_meta = self.vault_data.get("encrypted_metadata")
            if not enc_meta or "nonce" not in enc_meta or "ciphertext" not in enc_meta:
                raise VaultCorruptedError("Vault is missing its encrypted_metadata block")

            salt = base64.b64decode(self.vault_data["salt"])
            key = self._derive_key_from_metadata(password, salt, kdf_meta)
            self.master_password = password
            self.master_password_salt = salt

            try:
                try:
                    meta_json = self._decrypt_data(
                        enc_meta["nonce"], enc_meta["ciphertext"], key
                    )
                except Exception:
                    self.master_password = None
                    self.master_password_salt = None
                    self.failed_unlock_attempts += 1
                    log_audit_event(
                        "VAULT_UNLOCK_FAILED",
                        f"Authentication failed (attempt {self.failed_unlock_attempts})",
                        False,
                    )
                    raise InvalidMasterPasswordError("Wrong password or corrupted vault")

                try:
                    meta_plaintext = json.loads(meta_json)
                except json.JSONDecodeError:
                    raise VaultCorruptedError("Encrypted metadata is not valid JSON")

                if meta_plaintext.get("validation_token") != VALIDATION_TOKEN_PLAINTEXT:
                    self.master_password = None
                    self.master_password_salt = None
                    self.failed_unlock_attempts += 1
                    log_audit_event(
                        "VAULT_UNLOCK_FAILED",
                        "Validation token plaintext mismatch",
                        False,
                    )
                    raise InvalidMasterPasswordError("Wrong password or corrupted vault")

                self._meta_plaintext = {
                    "validation_token": meta_plaintext["validation_token"],
                    "created": meta_plaintext.get("created", ""),
                    "modified": meta_plaintext.get("modified", ""),
                }
            finally:
                wipe_key(key)

            if self.vault_data.get("integrity_hash"):
                self._verify_vault_integrity()

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
        except VaultException:
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

                self._refresh_encrypted_metadata()
                self.vault_data["integrity_hash"] = self._compute_vault_integrity_hash()
                self._persist_vault()

                self.last_activity = datetime.now()
                log_audit_event("ENTRY_IMPORTED", f"Entry imported: {name}")
                return True
            finally:
                wipe_key(key)

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

                self._refresh_encrypted_metadata()
                self.vault_data["integrity_hash"] = self._compute_vault_integrity_hash()
                self._persist_vault()

                self.last_activity = datetime.now()
                log_audit_event("ENTRY_ADDED", f"New entry added: {name}")
                return True
            finally:
                wipe_key(key)

        except Exception as e:
            log_audit_event("ENTRY_ADD_ERROR", str(e), False)
            raise

    def get_entry(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve and decrypt entry from vault"""
        try:
            self._check_auto_lock()

            if self.vault_data is None or self.master_password is None:
                raise VaultNotLoadedError("Vault not loaded")

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
                wipe_key(key)

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
            return sorted(self.vault_data["entries"].keys())

        except Exception as e:
            log_audit_event("ENTRY_LIST_ERROR", str(e), False)
            raise

    def delete_entry(self, name: str) -> bool:
        """Delete entry from vault"""
        try:
            self._check_auto_lock()

            if self.vault_data is None:
                raise VaultNotLoadedError("Vault not loaded")

            if name not in self.vault_data["entries"]:
                raise InvalidEntryError(f"Entry '{name}' not found")

            del self.vault_data["entries"][name]

            self._refresh_encrypted_metadata()
            self.vault_data["integrity_hash"] = self._compute_vault_integrity_hash()
            self._persist_vault()

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
        """Export vault to an encrypted v3.1 dual-layer backup."""
        try:
            self._check_auto_lock()

            if self.vault_data is None:
                raise VaultNotLoadedError("Vault not loaded")

            is_valid, _ = validate_password_strength(export_password)
            if not is_valid:
                raise WeakPasswordError("Export password does not meet strength requirements")

            kdf_meta = self.vault_data["metadata"]["kdf"]

            user_entries_plaintext = {}
            master_key = self._get_derived_key()
            try:
                for entry_name, ec in self.vault_data["entries"].items():
                    try:
                        entry_json = self._decrypt_data(ec["nonce"], ec["ciphertext"], master_key)
                        user_entries_plaintext[entry_name] = json.loads(entry_json)
                    except Exception as e:
                        print(f"Warning: Could not export entry '{entry_name}': {e}")
                        continue
            finally:
                zero_fill_buffer(bytearray(master_key))
                del master_key

            content_salt = secrets.token_bytes(self.SALT_LENGTH)
            content_key = self._derive_key_from_metadata(export_password, content_salt, kdf_meta)
            try:
                export_data = {
                    "version": VAULT_FORMAT_VERSION,
                    "exported": datetime.now().isoformat(),
                    "source": str(self.vault_path),
                    "entries": {},
                    "metadata": self.vault_data["metadata"],
                }

                for entry_name, entry_plaintext in user_entries_plaintext.items():
                    entry_json = json.dumps(entry_plaintext)
                    nonce, ciphertext = self._encrypt_data(entry_json, content_key)
                    export_data["entries"][entry_name] = {
                        "nonce": nonce,
                        "ciphertext": ciphertext,
                    }

                export_json = json.dumps(export_data, indent=2)
                content_nonce, content_ciphertext = self._encrypt_data(export_json, content_key)
            finally:
                zero_fill_buffer(bytearray(content_key))
                del content_key

            inner_backup = {
                "nonce": content_nonce,
                "ciphertext": content_ciphertext,
                "content_salt": base64.b64encode(content_salt).decode(),
            }

            inner_json = json.dumps(inner_backup)
            file_salt = secrets.token_bytes(self.SALT_LENGTH)
            file_key = self._derive_key_from_metadata(export_password, file_salt, kdf_meta)
            try:
                file_nonce, file_ciphertext = self._encrypt_data(inner_json, file_key)
            finally:
                zero_fill_buffer(bytearray(file_key))
                del file_key

            outer_backup = {
                "version": BACKUP_FORMAT_VERSION,
                "kdf": kdf_meta,
                "file_nonce": file_nonce,
                "file_ciphertext": file_ciphertext,
                "file_salt": base64.b64encode(file_salt).decode(),
            }

            export_path.parent.mkdir(parents=True, exist_ok=True)
            make_vault_writable(export_path)
            export_path.write_text(json.dumps(outer_backup, indent=2))
            set_readonly_permissions(export_path)

            self.last_activity = datetime.now()
            log_audit_event("VAULT_EXPORTED", f"Vault exported to {export_path}")
            return True

        except Exception as e:
            log_audit_event("EXPORT_ERROR", str(e), False)
            raise

    def _validate_export_data(self, export_data: Dict[str, Any]) -> bool:
        """Validate the structure of a v3.0 inner export_data dict."""
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
        if version != VAULT_FORMAT_VERSION:
            raise VaultException(
                f"Corrupted backup: inner export_data version '{version}' "
                f"is not supported (expected {VAULT_FORMAT_VERSION})"
            )

        exported = export_data.get("exported")
        if not isinstance(exported, str):
            raise VaultException("Corrupted backup: exported timestamp is not a string")

        try:
            datetime.fromisoformat(exported)
        except ValueError:
            raise VaultException(f"Corrupted backup: invalid timestamp format {exported}")

        return True

    def import_vault(self, import_path: Path, import_password: str) -> Dict[str, Any]:
        """Import a v3.1 backup. Returns the inner export_data plus content-layer
        metadata needed by decrypt_backup_entries."""
        try:
            if not import_path.exists():
                raise VaultException(f"Import file not found: {import_path}")

            backup_json = import_path.read_text()
            backup = json.loads(backup_json)

            version = backup.get("version")
            if version != BACKUP_FORMAT_VERSION:
                raise VaultException(
                    f"Unsupported backup format '{version}'. This build "
                    f"requires version {BACKUP_FORMAT_VERSION}. Older backups "
                    "are not migrated automatically."
                )

            required_fields = ["kdf", "file_nonce", "file_ciphertext", "file_salt"]
            for field in required_fields:
                if field not in backup:
                    raise VaultException(f"Corrupted backup: missing '{field}' field")
                if not backup[field]:
                    raise VaultException(f"Corrupted backup: empty '{field}' field")

            kdf_meta = backup["kdf"]
            if not isinstance(kdf_meta, dict) or "name" not in kdf_meta:
                raise VaultException("Corrupted backup: 'kdf' is malformed")

            try:
                file_salt = base64.b64decode(backup["file_salt"])
            except Exception as e:
                raise VaultException(f"Corrupted backup: invalid file_salt encoding - {e}")

            file_key = self._derive_key_from_metadata(import_password, file_salt, kdf_meta)
            try:
                try:
                    inner_json = self._decrypt_data(
                        backup["file_nonce"], backup["file_ciphertext"], file_key
                    )
                except VaultCorruptedError:
                    log_audit_event("IMPORT_ERROR", "Backup tampering detected at file level", False)
                    raise VaultException(
                        "BACKUP TAMPERING DETECTED: file layer failed GCM authentication"
                    )
                except EncryptionError as e:
                    log_audit_event("IMPORT_ERROR", f"File-level decryption error: {str(e)}", False)
                    raise VaultException(
                        f"Failed to decrypt backup: wrong password or corrupted file"
                    )
            finally:
                zero_fill_buffer(bytearray(file_key))
                del file_key

            try:
                inner_backup = json.loads(inner_json)
            except json.JSONDecodeError as e:
                raise VaultException(f"Corrupted backup: inner JSON is invalid - {e}")

            for field in ("nonce", "ciphertext", "content_salt"):
                if field not in inner_backup or not inner_backup[field]:
                    raise VaultException(f"Corrupted backup: missing content '{field}'")

            try:
                content_salt = base64.b64decode(inner_backup["content_salt"])
            except Exception as e:
                raise VaultException(f"Corrupted backup: invalid content_salt encoding - {e}")

            content_key = self._derive_key_from_metadata(import_password, content_salt, kdf_meta)
            try:
                try:
                    export_json = self._decrypt_data(
                        inner_backup["nonce"], inner_backup["ciphertext"], content_key
                    )
                except VaultCorruptedError:
                    log_audit_event("IMPORT_ERROR", "Backup tampering detected at content level", False)
                    raise VaultException(
                        "BACKUP TAMPERING DETECTED: content layer failed GCM authentication"
                    )
                except EncryptionError as e:
                    log_audit_event("IMPORT_ERROR", f"Content-level decryption error: {str(e)}", False)
                    raise VaultException(f"Failed to decrypt backup content: {str(e)}")
            finally:
                zero_fill_buffer(bytearray(content_key))
                del content_key

            try:
                export_data = json.loads(export_json)
            except json.JSONDecodeError as e:
                raise VaultException(f"Corrupted backup: export data JSON is invalid - {e}")

            self._validate_export_data(export_data)
            export_data["_content_salt"] = inner_backup["content_salt"]
            export_data["_content_kdf"] = kdf_meta

            log_audit_event("VAULT_IMPORTED", f"Vault imported from {import_path}")
            return export_data

        except VaultException:
            raise
        except Exception as e:
            log_audit_event("IMPORT_ERROR", f"Unexpected error during import: {str(e)}", False)
            raise VaultException(f"Import failed: {str(e)}")

    def decrypt_backup_entries(
        self,
        backup_entries: Dict,
        import_password: str,
        content_salt_b64: str,
        kdf_meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Dict[str, str]]:
        """Decrypt entries from an imported backup using the backup password
        and the recorded KDF metadata. If kdf_meta is omitted, defaults to the
        build's default KDF for forward compatibility."""
        try:
            content_salt = base64.b64decode(content_salt_b64)
            if kdf_meta is None:
                kdf_meta = self._build_default_kdf_metadata()
            content_key = self._derive_key_from_metadata(
                import_password, content_salt, kdf_meta
            )

            decrypted_entries = {}
            try:
                for entry_name, entry_data in backup_entries.items():
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
            finally:
                zero_fill_buffer(bytearray(content_key))
                del content_key

        except Exception as e:
            raise VaultException(f"Failed to decrypt backup entries: {e}")

    def lock_vault(self):
        """Manually lock vault and drop all in-memory secrets."""
        if self.master_password:
            zero_fill_buffer(bytearray(self.master_password.encode()))
            self.master_password = None
        self.master_password_salt = None
        self.vault_data = None
        self._meta_plaintext = None
        self.is_locked = True
        log_audit_event("VAULT_LOCKED", "Vault manually locked")

    def clear_sensitive_data(self):
        """Clear sensitive data from memory"""
        if self.master_password:
            zero_fill_buffer(bytearray(self.master_password.encode()))
            self.master_password = None
        self.master_password_salt = None
        self.vault_data = None
        self._meta_plaintext = None
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

