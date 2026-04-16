#!/usr/bin/env python3
"""
Unit tests for VaultManager.

Asserts against the real public surface: vault_data, master_password,
master_password_salt, is_locked, and the public methods. The derived
encryption key is intentionally not persisted on the instance and is
not asserted on directly.
"""

import json
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vault import VaultManager
from exceptions import (
    VaultException,
    VaultNotLoadedError,
    InvalidMasterPasswordError,
    InvalidEntryError,
    WeakPasswordError,
)


# Passwords that satisfy validate_password_strength: 12+ chars, >=60 bits
# entropy, at least 3 of {lower, upper, digit, special}.
MASTER_PW = "MasterPass!2026#Xyz"
MASTER_PW_ALT = "OtherMaster!2026#Abc"
ENTRY_PW_1 = "EntrySecret!2026#1"
ENTRY_PW_2 = "EntrySecret!2026#2"
ENTRY_PW_3 = "EntrySecret!2026#3"
EXPORT_PW = "ExportPass!2026#Zzz"


class VaultTestBase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self.temp_dir.name) / "vault.json"

    def tearDown(self):
        self.temp_dir.cleanup()


class TestVaultInitialization(VaultTestBase):
    def test_init_creates_vault_file(self):
        vault = VaultManager(self.vault_path)
        self.assertTrue(vault.init_vault(MASTER_PW))
        self.assertTrue(self.vault_path.exists())

    def test_init_creates_valid_json(self):
        VaultManager(self.vault_path).init_vault(MASTER_PW)
        data = json.loads(self.vault_path.read_text())
        self.assertIn("version", data)
        self.assertIn("salt", data)
        self.assertIn("entries", data)
        self.assertIn("metadata", data)

    def test_init_rejects_weak_password(self):
        vault = VaultManager(self.vault_path)
        with self.assertRaises(WeakPasswordError):
            vault.init_vault("weak")

    def test_reinit_existing_vault_raises(self):
        vault = VaultManager(self.vault_path)
        vault.init_vault(MASTER_PW)
        with self.assertRaises(VaultException):
            VaultManager(self.vault_path).init_vault(MASTER_PW_ALT)

    def test_password_not_stored_plaintext_on_disk(self):
        vault = VaultManager(self.vault_path)
        vault.init_vault(MASTER_PW)
        self.assertNotIn(MASTER_PW, self.vault_path.read_text())

    def test_each_vault_has_unique_salt(self):
        p1 = Path(self.temp_dir.name) / "v1.json"
        p2 = Path(self.temp_dir.name) / "v2.json"
        VaultManager(p1).init_vault(MASTER_PW)
        VaultManager(p2).init_vault(MASTER_PW)
        self.assertNotEqual(
            json.loads(p1.read_text())["salt"],
            json.loads(p2.read_text())["salt"],
        )


class TestVaultEncryption(VaultTestBase):
    def setUp(self):
        super().setUp()
        self.vault = VaultManager(self.vault_path)
        self.vault.init_vault(MASTER_PW)
        # init_vault already populates master_password; load_vault is not
        # strictly required after init but mirrors real-world usage.
        self.vault.load_vault(MASTER_PW)
        self.key = self.vault._get_derived_key()

    def tearDown(self):
        self.vault.clear_sensitive_data()
        super().tearDown()

    def test_encrypt_decrypt_roundtrip(self):
        nonce, ciphertext = self.vault._encrypt_data("secret data", self.key)
        self.assertEqual(
            self.vault._decrypt_data(nonce, ciphertext, self.key),
            "secret data",
        )

    def test_same_plaintext_different_ciphertexts(self):
        n1, c1 = self.vault._encrypt_data("same", self.key)
        n2, c2 = self.vault._encrypt_data("same", self.key)
        self.assertNotEqual(n1, n2)
        self.assertNotEqual(c1, c2)

    def test_wrong_password_fails_to_load(self):
        self.vault.add_entry("svc", "user", ENTRY_PW_1)
        wrong = VaultManager(self.vault_path)
        with self.assertRaises(InvalidMasterPasswordError):
            wrong.load_vault(MASTER_PW_ALT)

    def test_key_derivation_is_deterministic(self):
        salt = secrets.token_bytes(16)
        self.assertEqual(
            self.vault._derive_key(MASTER_PW, salt),
            self.vault._derive_key(MASTER_PW, salt),
        )

    def test_different_passwords_produce_different_keys(self):
        salt = secrets.token_bytes(16)
        self.assertNotEqual(
            self.vault._derive_key("PasswordOne!2026", salt),
            self.vault._derive_key("PasswordTwo!2026", salt),
        )


class TestEntryManagement(VaultTestBase):
    def setUp(self):
        super().setUp()
        self.vault = VaultManager(self.vault_path)
        self.vault.init_vault(MASTER_PW)
        self.vault.load_vault(MASTER_PW)

    def tearDown(self):
        self.vault.clear_sensitive_data()
        super().tearDown()

    def test_add_entry_succeeds(self):
        self.assertTrue(self.vault.add_entry("gmail", "user@x.com", ENTRY_PW_1))

    def test_add_entry_persists(self):
        self.vault.add_entry("github", "jdoe", ENTRY_PW_1)
        data = json.loads(self.vault_path.read_text())
        self.assertIn("github", data["entries"])

    def test_get_entry_returns_full_record(self):
        self.vault.add_entry(
            "svc", "tuser", ENTRY_PW_1, "https://example.com", "notes text"
        )
        entry = self.vault.get_entry("svc")
        self.assertEqual(entry["username"], "tuser")
        self.assertEqual(entry["password"], ENTRY_PW_1)
        self.assertEqual(entry["url"], "https://example.com")
        self.assertEqual(entry["notes"], "notes text")

    def test_get_nonexistent_entry_raises(self):
        with self.assertRaises(InvalidEntryError):
            self.vault.get_entry("does_not_exist")

    def test_list_entries_returns_all(self):
        self.vault.add_entry("a", "u", ENTRY_PW_1)
        self.vault.add_entry("b", "u", ENTRY_PW_2)
        self.vault.add_entry("c", "u", ENTRY_PW_3)
        self.assertEqual(self.vault.list_entries(), ["a", "b", "c"])

    def test_list_entries_excludes_sentinel(self):
        self.assertEqual(self.vault.list_entries(), [])

    def test_list_entries_sorted(self):
        self.vault.add_entry("zebra", "u", ENTRY_PW_1)
        self.vault.add_entry("apple", "u", ENTRY_PW_2)
        self.vault.add_entry("mango", "u", ENTRY_PW_3)
        self.assertEqual(self.vault.list_entries(), ["apple", "mango", "zebra"])

    def test_delete_entry_succeeds(self):
        self.vault.add_entry("tmp", "u", ENTRY_PW_1)
        self.assertTrue(self.vault.delete_entry("tmp"))
        with self.assertRaises(InvalidEntryError):
            self.vault.get_entry("tmp")

    def test_delete_nonexistent_entry_raises(self):
        with self.assertRaises(InvalidEntryError):
            self.vault.delete_entry("missing")

    def test_cannot_delete_sentinel(self):
        with self.assertRaises(InvalidEntryError):
            self.vault.delete_entry("_sentinel")

    def test_overwrite_entry(self):
        self.vault.add_entry("acct", "old_user", ENTRY_PW_1)
        self.vault.add_entry("acct", "new_user", ENTRY_PW_2)
        entry = self.vault.get_entry("acct")
        self.assertEqual(entry["username"], "new_user")
        self.assertEqual(entry["password"], ENTRY_PW_2)

    def test_add_rejects_weak_entry_password(self):
        with self.assertRaises(WeakPasswordError):
            self.vault.add_entry("acct", "u", "weak")


class TestVaultPersistence(VaultTestBase):
    def test_load_with_correct_password(self):
        VaultManager(self.vault_path).init_vault(MASTER_PW)
        self.assertTrue(VaultManager(self.vault_path).load_vault(MASTER_PW))

    def test_data_survives_reload(self):
        v1 = VaultManager(self.vault_path)
        v1.init_vault(MASTER_PW)
        v1.load_vault(MASTER_PW)
        v1.add_entry("x", "u1", ENTRY_PW_1)
        v1.add_entry("y", "u2", ENTRY_PW_2)
        v1.clear_sensitive_data()

        v2 = VaultManager(self.vault_path)
        v2.load_vault(MASTER_PW)
        self.assertEqual(v2.list_entries(), ["x", "y"])
        self.assertEqual(v2.get_entry("x")["username"], "u1")
        v2.clear_sensitive_data()

    def test_corrupted_json_raises(self):
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        self.vault_path.write_text("{ not json")
        with self.assertRaises(VaultException):
            VaultManager(self.vault_path).load_vault(MASTER_PW)

    def test_missing_vault_file_raises(self):
        with self.assertRaises(VaultException):
            VaultManager(self.vault_path).load_vault(MASTER_PW)


class TestVaultExport(VaultTestBase):
    def setUp(self):
        super().setUp()
        self.export_path = Path(self.temp_dir.name) / "backup.json"
        self.vault = VaultManager(self.vault_path)
        self.vault.init_vault(MASTER_PW)
        self.vault.load_vault(MASTER_PW)
        self.vault.add_entry("svc", "tuser_marker", ENTRY_PW_1)

    def tearDown(self):
        self.vault.clear_sensitive_data()
        super().tearDown()

    def test_export_creates_file(self):
        self.assertTrue(self.vault.export_vault(self.export_path, EXPORT_PW))
        self.assertTrue(self.export_path.exists())

    def test_export_is_valid_v31_envelope(self):
        self.vault.export_vault(self.export_path, EXPORT_PW)
        data = json.loads(self.export_path.read_text())
        self.assertEqual(data["version"], "3.1")
        self.assertIn("file_nonce", data)
        self.assertIn("file_ciphertext", data)
        self.assertIn("file_salt", data)
        self.assertIn("kdf", data)

    def test_export_hides_plaintext_identifiers(self):
        self.vault.export_vault(self.export_path, EXPORT_PW)
        content = self.export_path.read_text()
        self.assertNotIn("tuser_marker", content)
        self.assertNotIn(ENTRY_PW_1, content)


class TestEdgeCases(VaultTestBase):
    def setUp(self):
        super().setUp()
        self.vault = VaultManager(self.vault_path)
        self.vault.init_vault(MASTER_PW)
        self.vault.load_vault(MASTER_PW)

    def tearDown(self):
        self.vault.clear_sensitive_data()
        super().tearDown()

    def test_empty_entry_name_raises(self):
        with self.assertRaises(InvalidEntryError):
            self.vault.add_entry("", "u", ENTRY_PW_1)

    def test_special_characters_in_entry_name(self):
        self.vault.add_entry("name@#$%", "u", ENTRY_PW_1)
        self.assertIsNotNone(self.vault.get_entry("name@#$%"))

    def test_unicode_in_entry_password(self):
        unicode_pw = "Пароль!2026#Secure"
        self.vault.add_entry("svc", "u", unicode_pw)
        self.assertEqual(self.vault.get_entry("svc")["password"], unicode_pw)

    def test_very_long_entry_password(self):
        long_pw = "Xx9!" + "a" * 9996
        self.vault.add_entry("svc", "u", long_pw)
        self.assertEqual(self.vault.get_entry("svc")["password"], long_pw)

    def test_get_without_loading_raises(self):
        fresh = VaultManager(self.vault_path)
        with self.assertRaises(VaultNotLoadedError):
            fresh.get_entry("svc")

    def test_add_without_loading_raises(self):
        fresh = VaultManager(self.vault_path)
        with self.assertRaises(VaultNotLoadedError):
            fresh.add_entry("svc", "u", ENTRY_PW_1)


class TestSecurityProperties(VaultTestBase):
    def test_nonces_are_unique_across_entries(self):
        vault = VaultManager(self.vault_path)
        vault.init_vault(MASTER_PW)
        vault.load_vault(MASTER_PW)
        for i in range(5):
            vault.add_entry(f"e{i}", "u", f"EntryPw!2026#{i}abc")
        data = json.loads(self.vault_path.read_text())
        nonces = [e["nonce"] for e in data["entries"].values()]
        self.assertEqual(len(nonces), len(set(nonces)))
        vault.clear_sensitive_data()

    def test_vault_file_includes_metadata_and_timestamps(self):
        VaultManager(self.vault_path).init_vault(MASTER_PW)
        data = json.loads(self.vault_path.read_text())
        self.assertIn("created", data)
        self.assertIn("modified", data)
        self.assertIn("metadata", data)

    def test_derived_key_is_256_bit(self):
        vault = VaultManager(self.vault_path)
        salt = secrets.token_bytes(16)
        key = vault._derive_key(MASTER_PW, salt)
        self.assertEqual(len(key), 32)

    def test_lock_vault_clears_password(self):
        vault = VaultManager(self.vault_path)
        vault.init_vault(MASTER_PW)
        vault.load_vault(MASTER_PW)
        vault.lock_vault()
        self.assertIsNone(vault.master_password)
        self.assertIsNone(vault.master_password_salt)
        self.assertTrue(vault.is_locked)


if __name__ == "__main__":
    unittest.main(verbosity=2)
