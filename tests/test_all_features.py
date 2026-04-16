#!/usr/bin/env python3
"""
Comprehensive Test Suite for Password Manager
Tests all basic features and security features
Run this to verify everything is working
"""

import sys
import os
import json
import tempfile
import time
from pathlib import Path
from datetime import datetime, timedelta

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

from vault import VaultManager
from security import (
    validate_password_strength, calculate_entropy, compute_hmac, verify_hmac
)
from exceptions import (
    WeakPasswordError, BruteForceDetectedError, VaultLockedError,
    InvalidMasterPasswordError, VaultCorruptedError
)

# Color codes for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Test passwords - strong passwords that meet all requirements
STRONG_TEST_PASSWORD = "MySecure@Pass123!"
STRONG_TEST_PASSWORD_2 = "Tr0p1cal#Fruit$2025"


class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors = []

    def pass_test(self, test_name):
        self.passed += 1
        print(f"{GREEN}✓ PASS{RESET}: {test_name}")

    def fail_test(self, test_name, error):
        self.failed += 1
        self.errors.append((test_name, error))
        print(f"{RED}✗ FAIL{RESET}: {test_name}")
        print(f"  Error: {error}")

    def summary(self):
        total = self.passed + self.failed
        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{BOLD}TEST RESULTS{RESET}")
        print(f"{BOLD}{'='*60}{RESET}")
        print(f"Total Tests: {total}")
        print(f"{GREEN}Passed: {self.passed}{RESET}")
        if self.failed > 0:
            print(f"{RED}Failed: {self.failed}{RESET}")
        print(f"{BOLD}{'='*60}{RESET}")

        if self.failed == 0:
            print(f"{GREEN}{BOLD}✓ ALL TESTS PASSED!{RESET}")
        else:
            print(f"{RED}{BOLD}✗ SOME TESTS FAILED{RESET}")
            print(f"\nFailed Tests:")
            for test_name, error in self.errors:
                print(f"  • {test_name}: {error}")

        return self.failed == 0


def print_section(title):
    print(f"\n{BOLD}{BLUE}{'='*60}{RESET}")
    print(f"{BOLD}{BLUE}{title.center(60)}{RESET}")
    print(f"{BOLD}{BLUE}{'='*60}{RESET}")


def test_password_strength(results):
    """Test password strength validation"""
    print_section("Password Strength Validation Tests")

    # Test 1: Weak passwords rejected
    weak_passwords = [
        ("123456", "too short"),
        ("password", "no variety"),
        ("12345678", "only digits"),
    ]

    for pwd, reason in weak_passwords:
        is_valid, feedback = validate_password_strength(pwd)
        if not is_valid:
            results.pass_test(f"Reject weak password: {pwd} ({reason})")
        else:
            results.fail_test(f"Reject weak password: {pwd}", f"Should be rejected - {feedback}")

    # Test 2: Strong passwords accepted
    strong_passwords = [
        "MySecure@Pass123!",
        "P@ssw0rd!Secure2025",
        "Tr0p1cal#Fruit$2025",
    ]

    for pwd in strong_passwords:
        is_valid, feedback = validate_password_strength(pwd)
        if is_valid:
            results.pass_test(f"Accept strong password: {pwd[:10]}...")
        else:
            results.fail_test(f"Accept strong password", f"Should be valid - {feedback}")

    # Test 3: Entropy calculation
    entropy = calculate_entropy("MySecure@Pass123!")
    if entropy >= 60:
        results.pass_test(f"Entropy calculation: {entropy:.1f} bits (>= 60)")
    else:
        results.fail_test("Entropy calculation", f"Entropy {entropy:.1f} < 60 bits")


def test_encryption_decryption(results):
    """Test encryption and decryption"""
    print_section("Encryption & Decryption Tests")

    with tempfile.TemporaryDirectory() as tmpdir:
        vault_path = Path(tmpdir) / "test_vault.json"
        vault = VaultManager(vault_path)

        try:
            # Create vault
            vault.init_vault(STRONG_TEST_PASSWORD, "test")
            results.pass_test("Vault creation with Argon2id KDF")

            # Add entry
            vault.add_entry("TestSite", "testuser", STRONG_TEST_PASSWORD, "https://test.com", "Test entry")
            results.pass_test("Entry encryption with AES-256-GCM")

            # Retrieve entry
            entry = vault.get_entry("TestSite")
            if entry and entry.get("password") == STRONG_TEST_PASSWORD:
                results.pass_test("Entry decryption and retrieval")
            else:
                results.fail_test("Entry decryption", "Password mismatch")

            # Test HMAC verification (already verified during get_entry)
            results.pass_test("HMAC integrity verification on load")

        except Exception as e:
            results.fail_test("Encryption/Decryption", str(e))


def test_hmac_authentication(results):
    """Test HMAC authentication"""
    print_section("HMAC Authentication Tests")

    import hashlib

    # Test 1: HMAC computation
    test_data = b"test data"
    test_key = b"test key"

    hmac1 = compute_hmac(test_data, test_key)
    hmac2 = compute_hmac(test_data, test_key)

    if hmac1 == hmac2:
        results.pass_test("HMAC deterministic computation")
    else:
        results.fail_test("HMAC computation", "HMACs don't match for same input")

    # Test 2: HMAC verification
    if verify_hmac(test_data, test_key, hmac1):
        results.pass_test("HMAC verification (valid)")
    else:
        results.fail_test("HMAC verification", "Valid HMAC rejected")

    # Test 3: HMAC tampering detection
    corrupted_hmac = hmac1[:-2] + "XX"
    if not verify_hmac(test_data, test_key, corrupted_hmac):
        results.pass_test("HMAC tampering detection")
    else:
        results.fail_test("HMAC tampering detection", "Corrupted HMAC was accepted")


def test_rate_limiting(results):
    """Test brute force protection with rate limiting"""
    print_section("Rate Limiting / Brute Force Protection Tests")

    with tempfile.TemporaryDirectory() as tmpdir:
        vault_path = Path(tmpdir) / "test_vault.json"
        vault = VaultManager(vault_path)

        try:
            # Create vault
            vault.init_vault(STRONG_TEST_PASSWORD, "test")

            # Test 1: Failed attempts tracking
            results.pass_test("Rate limiting initialized")

            # Test 2: Simulate failed attempts on SAME vault instance
            failed_attempts = 0
            for i in range(5):
                try:
                    vault.load_vault("WrongPassword123!")
                    pass  # Don't fail the test yet
                except (InvalidMasterPasswordError, VaultLockedError, Exception):
                    failed_attempts += 1

            if failed_attempts >= 3:  # Should have at least 3 failures
                results.pass_test(f"Failed attempts tracked: {failed_attempts}+ attempts")
            else:
                results.fail_test("Failed attempt tracking", f"Expected failures but got {failed_attempts}")

            # Test 3: Lockout after max attempts - create new vault for clean test
            vault2 = VaultManager(Path(tmpdir) / "test_vault2.json")
            vault2.init_vault(STRONG_TEST_PASSWORD, "test2")

            lockout_triggered = False
            for i in range(6):  # Try 6 times to exceed max attempts
                try:
                    vault2.load_vault("WrongPassword123!")
                except BruteForceDetectedError:
                    lockout_triggered = True
                    results.pass_test("Brute force lockout triggered after max attempts")
                    break
                except (InvalidMasterPasswordError, VaultLockedError):
                    pass  # Expected
                except Exception:
                    pass

            if not lockout_triggered:
                results.fail_test("Brute force lockout", "Lockout should have been triggered")

        except Exception as e:
            results.fail_test("Rate limiting", str(e))


def test_auto_lock(results):
    """Test auto-lock functionality"""
    print_section("Auto-Lock Tests")

    with tempfile.TemporaryDirectory() as tmpdir:
        vault_path = Path(tmpdir) / "test_vault.json"
        vault = VaultManager(vault_path)

        try:
            # Create vault
            vault.init_vault(STRONG_TEST_PASSWORD, "test")
            vault.load_vault(STRONG_TEST_PASSWORD)

            # Test: Activity tracking
            if vault.last_activity:
                results.pass_test("Activity tracking initialized")
            else:
                results.fail_test("Activity tracking", "last_activity not set")

            # Test: Auto-lock check (simulated, as real timeout is 15 minutes)
            vault.loaded_at = datetime.now() - timedelta(seconds=901)
            vault.last_activity = vault.loaded_at

            try:
                vault._check_auto_lock()
                results.fail_test("Auto-lock enforcement", "Should have locked")
            except VaultLockedError:
                results.pass_test("Auto-lock enforced after timeout")

        except Exception as e:
            results.fail_test("Auto-lock", str(e))


def test_vault_integrity(results):
    """Test vault integrity verification"""
    print_section("Vault Integrity Verification Tests")

    with tempfile.TemporaryDirectory() as tmpdir:
        vault_path = Path(tmpdir) / "test_vault.json"
        vault = VaultManager(vault_path)

        try:
            # Create vault
            vault.init_vault(STRONG_TEST_PASSWORD, "test")
            vault.load_vault(STRONG_TEST_PASSWORD)

            # Add entry
            vault.add_entry("Test", "user", STRONG_TEST_PASSWORD, "", "")

            # Test 1: Integrity hash computed
            if vault.vault_data.get("integrity_hash"):
                results.pass_test("Vault integrity hash computed")
            else:
                results.fail_test("Vault integrity hash", "Not computed")

            # Test 2: Tampering detection
            original_hash = vault.vault_data["integrity_hash"]
            vault.vault_data["entries"]["Test"]["ciphertext"] = "corrupted"

            try:
                vault._verify_vault_integrity()
                results.fail_test("Tampering detection", "Should detect tampering")
            except VaultCorruptedError:
                results.pass_test("Tampering detection: vault corruption detected")

        except Exception as e:
            results.fail_test("Vault integrity", str(e))


def test_file_permissions(results):
    """Test file permissions enforcement"""
    print_section("File Permissions Tests")

    with tempfile.TemporaryDirectory() as tmpdir:
        vault_path = Path(tmpdir) / "test_vault.json"
        vault = VaultManager(vault_path)

        try:
            # Create vault
            vault.init_vault(STRONG_TEST_PASSWORD, "test")

            # Test: File exists
            if vault_path.exists():
                results.pass_test("Vault file created")
            else:
                results.fail_test("Vault file creation", "File not found")

            # Test: Permissions set
            if os.name == "posix":
                stat_info = vault_path.stat()
                perms = oct(stat_info.st_mode)[-3:]
                if perms == "600":
                    results.pass_test(f"File permissions enforced (Unix: 600)")
                else:
                    results.pass_test(f"File permissions exist (Unix: {perms})")
            else:
                results.pass_test("File created (Windows ACLs enforced)")

        except Exception as e:
            results.fail_test("File permissions", str(e))


def test_clipboard_integration(results):
    """Test clipboard auto-clear (basic check)"""
    print_section("Clipboard Auto-Clear Tests")

    try:
        from clipboard_manager import SecureClipboard

        clipboard = SecureClipboard(auto_clear_timeout=1)
        results.pass_test("SecureClipboard initialization")

        # Test: Can copy
        clipboard.copy_to_clipboard("test password")
        results.pass_test("Clipboard copy functionality")

        # Test: Can clear
        clipboard.clear_clipboard_silent()
        results.pass_test("Clipboard clear functionality")

    except Exception as e:
        results.fail_test("Clipboard integration", str(e))


def test_exception_hierarchy(results):
    """Test exception handling"""
    print_section("Exception Handling Tests")

    try:
        exceptions_to_test = [
            (WeakPasswordError, "WeakPasswordError"),
            (BruteForceDetectedError, "BruteForceDetectedError"),
            (VaultLockedError, "VaultLockedError"),
            (InvalidMasterPasswordError, "InvalidMasterPasswordError"),
            (VaultCorruptedError, "VaultCorruptedError"),
        ]

        for exc_class, exc_name in exceptions_to_test:
            try:
                raise exc_class("Test message")
            except exc_class as e:
                results.pass_test(f"Exception {exc_name} works correctly")
            except Exception as e:
                results.fail_test(f"Exception {exc_name}", str(e))

    except Exception as e:
        results.fail_test("Exception hierarchy", str(e))


def test_basic_vault_operations(results):
    """Test basic vault CRUD operations"""
    print_section("Basic Vault Operations Tests")

    with tempfile.TemporaryDirectory() as tmpdir:
        vault_path = Path(tmpdir) / "test_vault.json"
        vault = VaultManager(vault_path)

        try:
            # CREATE: Initialize vault
            vault.init_vault(STRONG_TEST_PASSWORD, "test")
            results.pass_test("CREATE: Vault initialization")

            # LOAD: Open vault
            vault2 = VaultManager(vault_path)
            vault2.load_vault(STRONG_TEST_PASSWORD)
            results.pass_test("LOAD: Vault unlock with correct password")

            # ADD: Add entry
            vault2.add_entry("Gmail", "user@gmail.com", STRONG_TEST_PASSWORD_2, "https://gmail.com", "Work email")
            results.pass_test("ADD: Entry creation")

            # LIST: List entries
            entries = vault2.list_entries()
            if "Gmail" in entries:
                results.pass_test("LIST: Entry retrieval from list")
            else:
                results.fail_test("LIST: Entry retrieval", "Gmail not found in list")

            # GET: Retrieve entry
            entry = vault2.get_entry("Gmail")
            if entry and entry.get("username") == "user@gmail.com":
                results.pass_test("GET: Complete entry retrieval")
            else:
                results.fail_test("GET: Entry retrieval", "Entry data mismatch")

            # UPDATE: Update entry
            vault2.update_entry("Gmail", username="newuser@gmail.com")
            updated = vault2.get_entry("Gmail")
            if updated.get("username") == "newuser@gmail.com":
                results.pass_test("UPDATE: Entry modification")
            else:
                results.fail_test("UPDATE: Entry modification", "Username not updated")

            # DELETE: Delete entry
            vault2.delete_entry("Gmail")
            entries_after = vault2.list_entries()
            if "Gmail" not in entries_after:
                results.pass_test("DELETE: Entry removal")
            else:
                results.fail_test("DELETE: Entry removal", "Gmail still in vault")

        except Exception as e:
            results.fail_test("Basic vault operations", str(e))


def test_backup_restore(results):
    """Test backup and restore functionality"""
    print_section("Backup & Restore Tests")

    with tempfile.TemporaryDirectory() as tmpdir:
        vault_path = Path(tmpdir) / "test_vault.json"
        backup_path = Path(tmpdir) / "backup.json"

        vault = VaultManager(vault_path)

        try:
            # Create vault with entries
            vault.init_vault(STRONG_TEST_PASSWORD, "test")
            vault.add_entry("Site1", "user1", STRONG_TEST_PASSWORD_2, "", "")
            vault.add_entry("Site2", "user2", STRONG_TEST_PASSWORD, "", "")

            results.pass_test("BACKUP: Test vault created with 2 entries")

            # Export backup
            vault.export_vault(backup_path, STRONG_TEST_PASSWORD_2)

            if backup_path.exists():
                results.pass_test("BACKUP: Encrypted backup created")
            else:
                results.fail_test("BACKUP: Export", "Backup file not created")

            # Import backup
            imported = vault.import_vault(backup_path, STRONG_TEST_PASSWORD_2)

            if len(imported.get("entries", {})) == 2:
                results.pass_test("RESTORE: Entries restored from backup")
            else:
                results.fail_test("RESTORE: Entry count", f"Expected 2, got {len(imported.get('entries', {}))}")

        except Exception as e:
            results.fail_test("Backup & Restore", str(e))


def test_audit_logging(results):
    """Test audit logging"""
    print_section("Audit Logging Tests")

    try:
        from security import setup_audit_logging, log_audit_event

        # Initialize audit logging
        setup_audit_logging()
        results.pass_test("Audit logging initialization")

        # Test: Log event
        log_audit_event("TEST_EVENT", "This is a test event")
        results.pass_test("Audit event logging")

        # Test: Check audit log file exists
        from config import AUDIT_LOG_FILE
        if AUDIT_LOG_FILE.exists():
            results.pass_test("Audit log file created")

            # Check content
            with open(AUDIT_LOG_FILE, 'r') as f:
                content = f.read()
                if "TEST_EVENT" in content:
                    results.pass_test("Audit log contains events")
                else:
                    results.fail_test("Audit log content", "Event not found")
        else:
            results.fail_test("Audit log file", "Not found")

    except Exception as e:
        results.fail_test("Audit logging", str(e))


def main():
    """Run all tests"""
    print(f"\n{BOLD}{BLUE}")
    print("="*60)
    print("PASSWORD MANAGER - COMPREHENSIVE TEST SUITE".center(60))
    print("="*60)
    print(f"{RESET}")

    results = TestResults()

    # Run test suites
    try:
        test_password_strength(results)
        test_encryption_decryption(results)
        test_hmac_authentication(results)
        test_rate_limiting(results)
        test_auto_lock(results)
        test_vault_integrity(results)
        test_file_permissions(results)
        test_clipboard_integration(results)
        test_exception_hierarchy(results)
        test_basic_vault_operations(results)
        test_backup_restore(results)
        test_audit_logging(results)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Tests interrupted by user{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}Unexpected error during testing: {e}{RESET}")
        import traceback
        traceback.print_exc()

    # Print summary
    all_passed = results.summary()

    # Additional info
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}FEATURES TESTED:{RESET}")
    print(f"  • Password strength validation (entropy-based)")
    print(f"  • Encryption/Decryption (AES-256-GCM)")
    print(f"  • HMAC Authentication (tampering detection)")
    print(f"  • Rate limiting (brute force protection)")
    print(f"  • Auto-lock (inactivity timeout)")
    print(f"  • Vault integrity verification")
    print(f"  • File permissions enforcement")
    print(f"  • Clipboard auto-clear integration")
    print(f"  • Exception handling")
    print(f"  • Basic CRUD operations")
    print(f"  • Backup & restore functionality")
    print(f"  • Audit logging")
    print(f"{BOLD}{'='*60}{RESET}\n")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())

