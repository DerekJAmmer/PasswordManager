"""
Security Configuration and Constants
"""

import os
from pathlib import Path

# Encryption Parameters
SALT_LENGTH = 16
NONCE_LENGTH = 12
KEY_LENGTH = 32  # 256-bit for AES-256

# Argon2id defaults (OWASP 2023 recommended)
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 19456  # 19 MiB in KiB
ARGON2_PARALLELISM = 1

# PBKDF2 fallback iterations (OWASP 2023 minimum for SHA-256)
PBKDF2_ITERATIONS = 310000

# On-disk format versions
VAULT_FORMAT_VERSION = "3.0"
BACKUP_FORMAT_VERSION = "3.1"
VALIDATION_TOKEN_PLAINTEXT = "password_manager:v3.0:valid"

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

