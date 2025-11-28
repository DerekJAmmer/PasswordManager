#!/usr/bin/env python3
"""
Comprehensive Test Suite for Password Vault
QA Agent: Tests each feature for bugs and edge cases
"""

import os
import sys
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
import secrets

# Import the vault module
sys.path.insert(0, str(Path(__file__).parent))
from vault import VaultManager


class TestVaultInitialization(unittest.TestCase):
    """QA Tests: Vault Initialization"""

    def setUp(self):
        """Create temp directory for each test"""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self.temp_dir.name) / "test_vault.json"

    def tearDown(self):
        """Clean up temp directory"""
        self.temp_dir.cleanup()

    def test_init_creates_vault_file(self):
        """✓ Test: init_vault creates file at specified path"""
        vault = VaultManager(self.vault_path)
        result = vault.init_vault("test_password")

        self.assertTrue(result, "init_vault should return True")
        self.assertTrue(self.vault_path.exists(), "Vault file should exist")

    def test_init_creates_valid_json(self):
        """✓ Test: Vault file is valid JSON"""
        vault = VaultManager(self.vault_path)
        vault.init_vault("test_password")

        data = json.loads(self.vault_path.read_text())
        self.assertIn("version", data)
        self.assertIn("salt", data)
        self.assertIn("entries", data)

    def test_init_with_existing_vault_fails(self):
        """✓ Test: Cannot reinit existing vault"""
        vault = VaultManager(self.vault_path)
        vault.init_vault("password1")

        # Try to reinit
        result = vault.init_vault("password2")
        self.assertFalse(result, "Should not reinit existing vault")

    def test_init_password_not_stored_plaintext(self):
        """✓ Test: Password is never stored plaintext"""
        vault = VaultManager(self.vault_path)
        vault.init_vault("secret_password_123")

        vault_content = self.vault_path.read_text()
        self.assertNotIn("secret_password_123", vault_content)

    def test_init_creates_unique_salt(self):
        """✓ Test: Each vault gets unique salt"""
        vault1_path = Path(self.temp_dir.name) / "vault1.json"
        vault2_path = Path(self.temp_dir.name) / "vault2.json"

        vault1 = VaultManager(vault1_path)
        vault2 = VaultManager(vault2_path)

        vault1.init_vault("password")
        vault2.init_vault("password")

        data1 = json.loads(vault1_path.read_text())
        data2 = json.loads(vault2_path.read_text())

        self.assertNotEqual(data1["salt"], data2["salt"], "Salts should be unique")


class TestVaultEncryption(unittest.TestCase):
    """QA Tests: Encryption & Decryption"""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self.temp_dir.name) / "test_vault.json"
        self.vault = VaultManager(self.vault_path)
        self.vault.init_vault("master_password")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_encrypt_decrypt_roundtrip(self):
        """✓ Test: Data survives encrypt/decrypt cycle"""
        plaintext = "This is secret data"
        nonce, ciphertext = self.vault._encrypt_data(plaintext, self.vault.master_key)

        decrypted = self.vault._decrypt_data(nonce, ciphertext, self.vault.master_key)
        self.assertEqual(plaintext, decrypted)

    def test_encryption_produces_different_ciphertexts(self):
        """✓ Test: Same plaintext produces different ciphertexts (nonce randomness)"""
        plaintext = "Same data"

        nonce1, ct1 = self.vault._encrypt_data(plaintext, self.vault.master_key)
        nonce2, ct2 = self.vault._encrypt_data(plaintext, self.vault.master_key)

        # Nonces should differ
        self.assertNotEqual(nonce1, nonce2)
        # Ciphertexts should differ
        self.assertNotEqual(ct1, ct2)

    def test_wrong_password_cannot_decrypt(self):
        """✓ Test: Wrong password fails to decrypt"""
        self.vault.load_vault("master_password")
        self.vault.add_entry("test", "user", "pass")

        # Try with wrong password
        wrong_vault = VaultManager(self.vault_path)
        result = wrong_vault.load_vault("wrong_password")
        self.assertTrue(result)  # Load succeeds, but decrypt should fail

        entry = wrong_vault.get_entry("test")
        self.assertIsNone(entry, "Should fail to decrypt with wrong password")

    def test_key_derivation_consistency(self):
        """✓ Test: Same password + salt = same key"""
        password = "consistent_password"
        salt = secrets.token_bytes(16)

        key1 = self.vault._derive_key(password, salt)
        key2 = self.vault._derive_key(password, salt)

        self.assertEqual(key1, key2, "Key derivation should be deterministic")

    def test_different_passwords_produce_different_keys(self):
        """✓ Test: Different passwords produce different keys"""
        salt = secrets.token_bytes(16)

        key1 = self.vault._derive_key("password1", salt)
        key2 = self.vault._derive_key("password2", salt)

        self.assertNotEqual(key1, key2)


class TestEntryManagement(unittest.TestCase):
    """QA Tests: Add, Get, List, Delete Entries"""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self.temp_dir.name) / "test_vault.json"
        self.vault = VaultManager(self.vault_path)
        self.vault.init_vault("password")
        self.vault.load_vault("password")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_add_entry_succeeds(self):
        """✓ Test: Can add entry to vault"""
        result = self.vault.add_entry("gmail", "user@gmail.com", "password123")
        self.assertTrue(result)

    def test_add_entry_persists_to_disk(self):
        """✓ Test: Entry saved to vault file"""
        self.vault.add_entry("github", "john_doe", "secure_pass")

        # Reload vault and verify
        data = json.loads(self.vault_path.read_text())
        self.assertIn("github", data["entries"])

    def test_get_entry_retrieves_correct_data(self):
        """✓ Test: Retrieved entry matches added data"""
        self.vault.add_entry(
            "test_entry",
            "testuser",
            "testpass",
            "https://example.com",
            "test notes"
        )

        entry = self.vault.get_entry("test_entry")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["username"], "testuser")
        self.assertEqual(entry["password"], "testpass")
        self.assertEqual(entry["url"], "https://example.com")
        self.assertEqual(entry["notes"], "test notes")

    def test_get_nonexistent_entry_returns_none(self):
        """✓ Test: Getting non-existent entry returns None"""
        entry = self.vault.get_entry("does_not_exist")
        self.assertIsNone(entry)

    def test_list_entries_shows_all_added(self):
        """✓ Test: list_entries shows all entries"""
        self.vault.add_entry("entry1", "user1", "pass1")
        self.vault.add_entry("entry2", "user2", "pass2")
        self.vault.add_entry("entry3", "user3", "pass3")

        entries = self.vault.list_entries()
        self.assertEqual(len(entries), 3)
        self.assertIn("entry1", entries)
        self.assertIn("entry2", entries)
        self.assertIn("entry3", entries)

    def test_list_entries_sorted(self):
        """✓ Test: Entries returned in sorted order"""
        self.vault.add_entry("zebra", "u", "p")
        self.vault.add_entry("apple", "u", "p")
        self.vault.add_entry("middle", "u", "p")

        entries = self.vault.list_entries()
        self.assertEqual(entries, sorted(entries))

    def test_delete_entry_succeeds(self):
        """✓ Test: Can delete entry"""
        self.vault.add_entry("to_delete", "user", "pass")
        result = self.vault.delete_entry("to_delete")

        self.assertTrue(result)
        self.assertIsNone(self.vault.get_entry("to_delete"))

    def test_delete_nonexistent_entry_fails(self):
        """✓ Test: Deleting non-existent entry fails"""
        result = self.vault.delete_entry("does_not_exist")
        self.assertFalse(result)

    def test_overwrite_entry_updates(self):
        """✓ Test: Adding entry with same name overwrites"""
        self.vault.add_entry("test", "user1", "pass1")
        self.vault.add_entry("test", "user2", "pass2")

        entry = self.vault.get_entry("test")
        self.assertEqual(entry["username"], "user2")
        self.assertEqual(entry["password"], "pass2")


class TestVaultPersistence(unittest.TestCase):
    """QA Tests: Vault Loading and Persistence"""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self.temp_dir.name) / "test_vault.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_load_vault_with_correct_password(self):
        """✓ Test: Load vault with correct password succeeds"""
        vault1 = VaultManager(self.vault_path)
        vault1.init_vault("correct_password")

        vault2 = VaultManager(self.vault_path)
        result = vault2.load_vault("correct_password")
        self.assertTrue(result)

    def test_vault_data_survives_reload(self):
        """✓ Test: Data persists across vault reloads"""
        # Create and populate vault
        vault1 = VaultManager(self.vault_path)
        vault1.init_vault("password")
        vault1.load_vault("password")
        vault1.add_entry("entry1", "user1", "pass1")
        vault1.add_entry("entry2", "user2", "pass2")

        # Reload and verify
        vault2 = VaultManager(self.vault_path)
        vault2.load_vault("password")

        entries = vault2.list_entries()
        self.assertEqual(len(entries), 2)

        entry = vault2.get_entry("entry1")
        self.assertEqual(entry["username"], "user1")

    def test_corrupted_vault_file_fails_to_load(self):
        """✓ Test: Corrupted JSON fails gracefully"""
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        self.vault_path.write_text("{ invalid json")

        vault = VaultManager(self.vault_path)
        result = vault.load_vault("password")
        self.assertFalse(result)

    def test_missing_vault_file_fails_to_load(self):
        """✓ Test: Loading non-existent vault fails"""
        vault = VaultManager(Path(self.temp_dir.name) / "nonexistent.json")
        result = vault.load_vault("password")
        self.assertFalse(result)


class TestVaultExport(unittest.TestCase):
    """QA Tests: Export Functionality"""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self.temp_dir.name) / "test_vault.json"
        self.export_path = Path(self.temp_dir.name) / "export.json"

        self.vault = VaultManager(self.vault_path)
        self.vault.init_vault("password")
        self.vault.load_vault("password")
        self.vault.add_entry("test", "user", "pass")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_export_creates_file(self):
        """✓ Test: Export creates file"""
        result = self.vault.export_vault(self.export_path, "export_password")

        self.assertTrue(result)
        self.assertTrue(self.export_path.exists())

    def test_export_file_is_valid_json(self):
        """✓ Test: Exported file is valid JSON"""
        self.vault.export_vault(self.export_path, "export_password")

        data = json.loads(self.export_path.read_text())
        self.assertIn("nonce", data)
        self.assertIn("ciphertext", data)

    def test_export_does_not_contain_plaintext_passwords(self):
        """✓ Test: Exported file does not contain plaintext"""
        self.vault.export_vault(self.export_path, "export_password")

        export_content = self.export_path.read_text()
        self.assertNotIn("testuser", export_content)
        self.assertNotIn("pass", export_content)


class TestEdgeCases(unittest.TestCase):
    """QA Tests: Edge Cases and Error Handling"""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self.temp_dir.name) / "test_vault.json"
        self.vault = VaultManager(self.vault_path)
        self.vault.init_vault("password")
        self.vault.load_vault("password")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_empty_entry_name(self):
        """✓ Test: Empty entry name handling"""
        result = self.vault.add_entry("", "user", "pass")
        # Should succeed as empty string is valid key
        self.assertTrue(result)

    def test_special_characters_in_entry_name(self):
        """✓ Test: Special characters in entry names"""
        result = self.vault.add_entry("test@#$%", "user", "pass")
        self.assertTrue(result)

        entry = self.vault.get_entry("test@#$%")
        self.assertIsNotNone(entry)

    def test_unicode_characters_in_passwords(self):
        """✓ Test: Unicode handling in passwords"""
        result = self.vault.add_entry("test", "user", "пароль🔒")
        self.assertTrue(result)

        entry = self.vault.get_entry("test")
        self.assertEqual(entry["password"], "пароль🔒")

    def test_very_long_password(self):
        """✓ Test: Very long passwords"""
        long_pass = "x" * 10000
        result = self.vault.add_entry("test", "user", long_pass)
        self.assertTrue(result)

        entry = self.vault.get_entry("test")
        self.assertEqual(entry["password"], long_pass)

    def test_get_entry_without_loading_fails(self):
        """✓ Test: Operations fail if vault not loaded"""
        vault = VaultManager(self.vault_path)
        result = vault.get_entry("test")
        self.assertIsNone(result)

    def test_add_entry_without_loading_fails(self):
        """✓ Test: Cannot add without loading"""
        vault = VaultManager(self.vault_path)
        result = vault.add_entry("test", "user", "pass")
        self.assertFalse(result)


class TestSecurityProperties(unittest.TestCase):
    """QA Tests: Security-Critical Properties"""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self.temp_dir.name) / "test_vault.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_nonce_uniqueness_across_operations(self):
        """✓ Test: Each encryption uses unique nonce"""
        vault = VaultManager(self.vault_path)
        vault.init_vault("password")
        vault.load_vault("password")

        # Add multiple entries and collect nonces
        nonces = []
        for i in range(5):
            vault.add_entry(f"entry{i}", f"user{i}", f"pass{i}")

        # Extract nonces from vault file
        data = json.loads(self.vault_path.read_text())
        for entry in data["entries"].values():
            nonces.append(entry["nonce"])

        # All nonces should be unique
        self.assertEqual(len(nonces), len(set(nonces)))

    def test_vault_metadata_includes_timestamps(self):
        """✓ Test: Audit trail with timestamps"""
        vault = VaultManager(self.vault_path)
        vault.init_vault("password")
        vault.load_vault("password")
        vault.add_entry("test", "user", "pass")

        data = json.loads(self.vault_path.read_text())
        self.assertIn("created", data)
        self.assertIn("entries", data)

    def test_key_length_is_256bit(self):
        """✓ Test: Derived key is 256-bit (32 bytes)"""
        vault = VaultManager(self.vault_path)
        salt = secrets.token_bytes(16)
        key = vault._derive_key("password", salt)

        self.assertEqual(len(key), 32, "Key must be 32 bytes (256-bit)")


def run_all_tests():
    """Run full test suite"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestVaultInitialization))
    suite.addTests(loader.loadTestsFromTestCase(TestVaultEncryption))
    suite.addTests(loader.loadTestsFromTestCase(TestEntryManagement))
    suite.addTests(loader.loadTestsFromTestCase(TestVaultPersistence))
    suite.addTests(loader.loadTestsFromTestCase(TestVaultExport))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    suite.addTests(loader.loadTestsFromTestCase(TestSecurityProperties))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

