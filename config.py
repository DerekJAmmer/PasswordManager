"""
Security Configuration and Constants
"""

import os
from pathlib import Path

# Encryption Parameters
KDF_N = 2**14  # 16384 - Argon2id memory cost
KDF_R = 8
KDF_P = 1
SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32  # 256-bit for AES-256

# Security Policies
MIN_PASSWORD_LENGTH = 12
PASSWORD_STRENGTH_ENTROPY_THRESHOLD = 60  # bits
MAX_UNLOCK_ATTEMPTS = 5
UNLOCK_ATTEMPT_BACKOFF_BASE = 2  # Exponential backoff
CLIPBOARD_CLEAR_TIMEOUT = 15  # seconds
AUTO_LOCK_TIMEOUT = 900  # 15 minutes
AUDIT_LOG_MAX_SIZE = 10 * 1024 * 1024  # 10MB

# Paths
VAULT_DIR = Path.home() / ".local_vault"
VAULT_DIR.mkdir(parents=True, exist_ok=True)

VAULTS_CONFIG_FILE = VAULT_DIR / "vaults.json"
AUDIT_LOG_FILE = VAULT_DIR / "audit.log"
MASTER_KEY_CACHE_FILE = VAULT_DIR / ".key_cache"  # DPAPI encrypted

# File Permissions
SECURE_PERMS_UNIX = 0o600  # Owner only
SECURE_PERMS_DIR_UNIX = 0o700

