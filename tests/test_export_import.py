#!/usr/bin/env python3
"""
Export/import round-trip tests for the v3.1 dual-layer backup format.

The outer envelope is tagged v3.1 and wraps an inner export_data tagged
v3.0. Both layers carry their own KDF metadata so decryption never has
to guess parameters. These tests confirm a fresh export can be imported
and decrypted back to the original plaintext entries.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vault import VaultManager
from exceptions import VaultException


MASTER_PW = "MasterPass!2026#RoundTrip"
EXPORT_PW = "ExportPass!2026#RoundTrip"


class TestExportImportRoundTrip(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        tmp = Path(self.temp_dir.name)
        self.vault_path = tmp / "source_vault.json"
        self.backup_path = tmp / "backup.json"

        self.vault = VaultManager(self.vault_path)
        self.vault.init_vault(MASTER_PW)
        self.vault.load_vault(MASTER_PW)

        self.entries = {
            "gmail": {
                "username": "alice@example.com",
                "password": "GmailSecret!2026#Xyz",
                "url": "https://mail.google.com",
                "notes": "primary",
            },
            "github": {
                "username": "alice-dev",
                "password": "GitHubSecret!2026#Abc",
                "url": "https://github.com",
                "notes": "work account",
            },
            "unicode_svc": {
                "username": "пользователь",
                "password": "Пароль!2026#Секрет",
                "url": "https://example.ru",
                "notes": "юникод",
            },
        }
        for name, e in self.entries.items():
            self.vault.add_entry(name, e["username"], e["password"], e["url"], e["notes"])

    def tearDown(self):
        self.vault.clear_sensitive_data()
        self.temp_dir.cleanup()

    def test_roundtrip_decrypts_all_entries(self):
        self.vault.export_vault(self.backup_path, EXPORT_PW)

        reader = VaultManager(self.vault_path)
        export_data = reader.import_vault(self.backup_path, EXPORT_PW)

        decrypted = reader.decrypt_backup_entries(
            export_data["entries"],
            EXPORT_PW,
            export_data["_content_salt"],
            export_data["_content_kdf"],
        )

        self.assertEqual(set(decrypted.keys()), set(self.entries.keys()))
        for name, expected in self.entries.items():
            self.assertEqual(decrypted[name]["username"], expected["username"])
            self.assertEqual(decrypted[name]["password"], expected["password"])
            self.assertEqual(decrypted[name]["url"], expected["url"])
            self.assertEqual(decrypted[name]["notes"], expected["notes"])

    def test_outer_envelope_has_version_3_1(self):
        self.vault.export_vault(self.backup_path, EXPORT_PW)
        outer = json.loads(self.backup_path.read_text())
        self.assertEqual(outer["version"], "3.1")
        for field in ("file_nonce", "file_ciphertext", "file_salt", "kdf"):
            self.assertIn(field, outer)

    def test_inner_export_data_has_version_3_0(self):
        self.vault.export_vault(self.backup_path, EXPORT_PW)
        reader = VaultManager(self.vault_path)
        export_data = reader.import_vault(self.backup_path, EXPORT_PW)
        self.assertEqual(export_data["version"], "3.0")
        self.assertIn("_content_kdf", export_data)
        self.assertIn("_content_salt", export_data)

    def test_wrong_export_password_raises(self):
        self.vault.export_vault(self.backup_path, EXPORT_PW)
        reader = VaultManager(self.vault_path)
        with self.assertRaises(VaultException):
            reader.import_vault(self.backup_path, "WrongPass!2026#Bad")

    def test_tampered_backup_detected(self):
        self.vault.export_vault(self.backup_path, EXPORT_PW)

        data = json.loads(self.backup_path.read_text())
        ct = data["file_ciphertext"]
        data["file_ciphertext"] = ("a" if ct[0] != "a" else "b") + ct[1:]

        tampered_path = self.backup_path.with_name("tampered.json")
        tampered_path.write_text(json.dumps(data))

        reader = VaultManager(self.vault_path)
        with self.assertRaises(VaultException):
            reader.import_vault(tampered_path, EXPORT_PW)

    def test_backup_is_fully_encrypted(self):
        self.vault.export_vault(self.backup_path, EXPORT_PW)
        content = self.backup_path.read_text()
        for e in self.entries.values():
            self.assertNotIn(e["username"], content)
            self.assertNotIn(e["password"], content)
            self.assertNotIn(e["notes"], content)

    def test_empty_vault_roundtrip(self):
        empty_path = Path(self.temp_dir.name) / "empty.json"
        empty_backup = Path(self.temp_dir.name) / "empty_backup.json"

        empty = VaultManager(empty_path)
        empty.init_vault(MASTER_PW)
        empty.load_vault(MASTER_PW)
        empty.export_vault(empty_backup, EXPORT_PW)
        empty.clear_sensitive_data()

        reader = VaultManager(empty_path)
        export_data = reader.import_vault(empty_backup, EXPORT_PW)
        decrypted = reader.decrypt_backup_entries(
            export_data["entries"],
            EXPORT_PW,
            export_data["_content_salt"],
            export_data["_content_kdf"],
        )
        self.assertEqual(decrypted, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
