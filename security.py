"""
Security and Validation Utilities
"""

import os
import ctypes
import math
import hmac
import hashlib
import secrets
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Tuple
import logging

from config import (
    MIN_PASSWORD_LENGTH, PASSWORD_STRENGTH_ENTROPY_THRESHOLD,
    AUDIT_LOG_FILE, AUDIT_LOG_MAX_SIZE, SECURE_PERMS_UNIX,
    SECURE_PERMS_DIR_UNIX, VAULT_DIR
)
from exceptions import (
    WeakPasswordError, PermissionError as VaultPermissionError,
    AuditLoggingError
)

# Configure audit logging
audit_logger = logging.getLogger("vault_audit")
audit_logger.setLevel(logging.INFO)


def setup_audit_logging():
    """Initialize audit logging to write-only file"""
    try:
        VAULT_DIR.mkdir(parents=True, exist_ok=True)

        if not AUDIT_LOG_FILE.exists():
            AUDIT_LOG_FILE.touch()

        _set_file_permissions(AUDIT_LOG_FILE)

        handler = logging.FileHandler(AUDIT_LOG_FILE, mode='a')
        formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
        audit_logger.addHandler(handler)

        if AUDIT_LOG_FILE.stat().st_size > AUDIT_LOG_MAX_SIZE:
            _rotate_audit_log()

    except Exception as e:
        raise AuditLoggingError(f"Failed to setup audit logging: {e}")


def log_audit_event(event_type: str, details: str, success: bool = True):
    """Log security-relevant events without sensitive data"""
    try:
        status = "SUCCESS" if success else "FAILED"
        audit_logger.info(f"[{status}] {event_type}: {details}")
    except Exception as e:
        raise AuditLoggingError(f"Failed to log audit event: {e}")


def _rotate_audit_log():
    """Rotate audit log when size exceeds limit"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = AUDIT_LOG_FILE.with_stem(f"audit_{timestamp}")
    AUDIT_LOG_FILE.rename(backup_path)
    AUDIT_LOG_FILE.touch()
    _set_file_permissions(AUDIT_LOG_FILE)


def _run_icacls(path: Path, grants: list) -> None:
    """Run icacls with list-form arguments (shell=False)."""
    username = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    args = ["icacls", str(path), "/inheritance:r"]
    for who, perm in grants:
        who_resolved = username if who == "$USER" else who
        args.extend(["/grant:r", f"{who_resolved}:({perm})"])
    subprocess.run(
        args,
        shell=False,
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _set_file_permissions(path: Path):
    """Set restrictive file permissions (owner read/write on Unix, ACL on Windows).

    Used for files that must remain writable by the owner — audit log, etc.
    """
    try:
        if os.name == "posix":
            path.chmod(SECURE_PERMS_UNIX)
        elif os.name == "nt":
            _run_icacls(path, [("$USER", "R,W"), ("Administrators", "R,W")])
    except Exception as e:
        raise VaultPermissionError(f"Failed to set file permissions: {e}")


def set_secure_permissions(path: Path):
    """Set secure file permissions (owner read/write)."""
    _set_file_permissions(path)


def set_vault_file_permissions(path: Path):
    """Set vault-file permissions to owner-read-only (0o400 / ACL R).

    Vault files should not be open for writing at rest. Callers that need
    to rewrite the vault must call `make_vault_writable` before the write,
    then this function again afterwards.
    """
    try:
        if os.name == "posix":
            path.chmod(0o400)
        elif os.name == "nt":
            _run_icacls(path, [("$USER", "R"), ("Administrators", "R")])
    except Exception as e:
        raise VaultPermissionError(f"Failed to set vault-file permissions: {e}")


def make_vault_writable(path: Path):
    """Relax permissions so the owner can rewrite a vault file in place.

    No-op if the file does not exist. Mirrors `set_secure_permissions` —
    owner read+write only. Use this immediately before overwriting the
    vault; follow the write with `set_vault_file_permissions`.
    """
    if not path.exists():
        return
    try:
        if os.name == "posix":
            path.chmod(SECURE_PERMS_UNIX)
        elif os.name == "nt":
            _run_icacls(path, [("$USER", "R,W"), ("Administrators", "R,W")])
    except Exception as e:
        raise VaultPermissionError(f"Failed to relax vault-file permissions: {e}")


def set_readonly_permissions(path: Path):
    """Set read-only permissions for backup files (0o400 / ACL R).

    Backups are write-once; owner-read-only matches the threat model.
    """
    try:
        if os.name == "posix":
            path.chmod(0o400)
        elif os.name == "nt":
            _run_icacls(path, [("$USER", "R"), ("Administrators", "R")])
    except Exception as e:
        raise VaultPermissionError(f"Failed to set read-only permissions: {e}")


def set_secure_dir_permissions(path: Path):
    """Set secure directory permissions."""
    try:
        if os.name == "posix":
            path.chmod(SECURE_PERMS_DIR_UNIX)
        elif os.name == "nt":
            _run_icacls(path, [("$USER", "F"), ("Administrators", "F")])
    except Exception as e:
        raise VaultPermissionError(f"Failed to set directory permissions: {e}")


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Validate password strength based on entropy and length"""
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"

    entropy = calculate_entropy(password)
    if entropy < PASSWORD_STRENGTH_ENTROPY_THRESHOLD:
        return False, f"Password is too weak (entropy: {entropy:.1f} bits, need {PASSWORD_STRENGTH_ENTROPY_THRESHOLD})"

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    variety_count = sum([has_lower, has_upper, has_digit, has_special])
    if variety_count < 3:
        return False, "Password should include uppercase, lowercase, digits, and special characters"

    return True, "Password is strong"


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of a password in bits"""
    charset_size = len(set(password))
    if charset_size == 0:
        return 0
    entropy_bits = len(password) * math.log2(charset_size)
    return entropy_bits


def compute_hmac(data: bytes, key: bytes) -> str:
    """Compute HMAC-SHA256 for integrity verification"""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_hmac(data: bytes, key: bytes, provided_hmac: str) -> bool:
    """Verify HMAC-SHA256 with constant-time comparison"""
    computed = compute_hmac(data, key)
    return hmac.compare_digest(computed, provided_hmac)


def zero_fill_buffer(buffer: bytearray):
    """Securely zero-fill sensitive buffer"""
    for i in range(len(buffer)):
        buffer[i] = 0


# Memory-locking helpers: keep derived-key bytes from being paged to swap.
# Best-effort only. Failure is logged once and the caller continues — this
# is a defense-in-depth layer, not a hard requirement for correctness.

_MLOCK_WARNED = False


def _warn_mlock_once(reason: str) -> None:
    global _MLOCK_WARNED
    if _MLOCK_WARNED:
        return
    _MLOCK_WARNED = True
    try:
        log_audit_event(
            "MEMORY_LOCK_UNAVAILABLE",
            f"Could not lock derived-key memory: {reason}",
            success=False,
        )
    except Exception:
        pass


def try_lock_memory(buffer: bytearray) -> bool:
    """Try to pin a bytearray into RAM so it can't be swapped to disk.

    Returns True on success, False otherwise. Never raises.
    """
    if not buffer:
        return False
    try:
        # ctypes pulls the underlying buffer address. bytearray has a writable
        # buffer, so c_char * n from_buffer is legal.
        length = len(buffer)
        addr = (ctypes.c_char * length).from_buffer(buffer)
        addr_ptr = ctypes.addressof(addr)
    except Exception as e:
        _warn_mlock_once(f"address resolution failed: {e}")
        return False

    try:
        if os.name == "posix":
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            rc = libc.mlock(ctypes.c_void_p(addr_ptr), ctypes.c_size_t(length))
            if rc != 0:
                _warn_mlock_once(f"mlock errno={ctypes.get_errno()}")
                return False
            return True
        if os.name == "nt":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            rc = kernel32.VirtualLock(
                ctypes.c_void_p(addr_ptr), ctypes.c_size_t(length)
            )
            if not rc:
                _warn_mlock_once(f"VirtualLock err={ctypes.get_last_error()}")
                return False
            return True
    except Exception as e:
        _warn_mlock_once(f"lock syscall unavailable: {e}")
        return False
    return False


def try_unlock_memory(buffer: bytearray) -> bool:
    """Best-effort munlock / VirtualUnlock. Never raises."""
    if not buffer:
        return False
    try:
        length = len(buffer)
        addr = (ctypes.c_char * length).from_buffer(buffer)
        addr_ptr = ctypes.addressof(addr)
    except Exception:
        return False
    try:
        if os.name == "posix":
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            return libc.munlock(ctypes.c_void_p(addr_ptr), ctypes.c_size_t(length)) == 0
        if os.name == "nt":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            return bool(
                kernel32.VirtualUnlock(
                    ctypes.c_void_p(addr_ptr), ctypes.c_size_t(length)
                )
            )
    except Exception:
        return False
    return False


def wipe_key(buffer: bytearray) -> None:
    """Zero the bytes and release any memory lock on a derived-key buffer."""
    if buffer is None:
        return
    try_unlock_memory(buffer)
    zero_fill_buffer(buffer)


def secure_random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes"""
    return secrets.token_bytes(length)


def get_password_strength_bar(password: str) -> str:
    """Return visual strength indicator for password"""
    is_valid, _ = validate_password_strength(password)
    entropy = calculate_entropy(password)

    if entropy < 40:
        return "Very Weak"
    elif entropy < 60:
        return "Weak"
    elif entropy < 80:
        return "Fair"
    elif entropy < 100:
        return "Good"
    else:
        return "Excellent"


def secure_derive_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """Derive encryption key from password using PBKDF2-HMAC-SHA256"""
    import hashlib
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        iterations,
        dklen=32
    )
    return key
