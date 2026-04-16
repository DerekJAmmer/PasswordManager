#!/usr/bin/env python3
"""
KDF + format tests for Phase 1 (v3.0 vaults, v3.1 backups).

Covers:
- Argon2id is actually invoked for a fresh vault when argon2-cffi is available.
- metadata.kdf on disk records the real parameters.
- PBKDF2 fallback runs when the Argon2 flag is off, and metadata records PBKDF2.
- v2.0 vaults are rejected on load.
- Backup round-trip carries kdf metadata at both layers.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import vault as vault_module
from vault import VaultManager
from exceptions import VaultException
from config import (
    ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM,
    PBKDF2_ITERATIONS, KEY_LENGTH,
)


MASTER_PW = "MasterPass!2026#Kdf"
EXPORT_PW = "ExportPass!2026#Kdf"


class TestArgon2idHappyPath(unittest.TestCase):
    """A fresh vault when argon2-cffi is importable must actually use Argon2id."""

    def setUp(self):
        if not vault_module.ARGON2_AVAILABLE:
            self.skipTest("argon2-cffi not available in this environment")
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self.temp_dir.name) / "vault.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_metadata_records_argon2id(self):
        v = VaultManager(self.vault_path)
        v.init_vault(MASTER_PW)
        data = json.loads(self.vault_path.read_text())
        kdf = data["metadata"]["kdf"]
        self.assertEqual(kdf["name"], "Argon2id")
        self.assertEqual(kdf["time_cost"], ARGON2_TIME_COST)
        self.assertEqual(kdf["memory_cost"], ARGON2_MEMORY_COST)
        self.assertEqual(kdf["parallelism"], ARGON2_PARALLELISM)

    def test_argon2_low_level_is_invoked(self):
        spy = mock.MagicMock(
            wraps=vault_module._argon2_low_level.hash_secret_raw
        )
        with mock.patch.object(
            vault_module._argon2_low_level, "hash_secret_raw", spy
        ):
            v = VaultManager(self.vault_path)
            v.init_vault(MASTER_PW)
        self.assertGreater(
            spy.call_count, 0, "Argon2id hash_secret_raw was never called"
        )

    def test_load_roundtrip_with_argon2id(self):
        v = VaultManager(self.vault_path)
        v.init_vault(MASTER_PW)
        v2 = VaultManager(self.vault_path)
        v2.load_vault(MASTER_PW)
        self.assertFalse(v2.is_locked)
        v2.clear_sensitive_data()


class TestPbkdf2Fallback(unittest.TestCase):
    """Patch ARGON2_AVAILABLE off and confirm a real PBKDF2 fallback."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self.temp_dir.name) / "vault.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_metadata_records_pbkdf2_when_argon2_unavailable(self):
        with mock.patch.object(vault_module, "ARGON2_AVAILABLE", False):
            v = VaultManager(self.vault_path)
            v.init_vault(MASTER_PW)
        data = json.loads(self.vault_path.read_text())
        kdf = data["metadata"]["kdf"]
        self.assertEqual(kdf["name"], "PBKDF2-HMAC-SHA256")
        self.assertEqual(kdf["iterations"], PBKDF2_ITERATIONS)
        self.assertEqual(kdf["hash_len"], KEY_LENGTH)

    def test_fallback_vault_loads_back(self):
        with mock.patch.object(vault_module, "ARGON2_AVAILABLE", False):
            v = VaultManager(self.vault_path)
            v.init_vault(MASTER_PW)
            v2 = VaultManager(self.vault_path)
            v2.load_vault(MASTER_PW)
            self.assertFalse(v2.is_locked)
            v2.clear_sensitive_data()

    def test_argon2_never_invoked_during_fallback_init(self):
        if not vault_module.ARGON2_AVAILABLE:
            self.skipTest("argon2-cffi not available, nothing to spy on")
        spy = mock.MagicMock(
            wraps=vault_module._argon2_low_level.hash_secret_raw
        )
        with mock.patch.object(vault_module, "ARGON2_AVAILABLE", False), \
             mock.patch.object(
                 vault_module._argon2_low_level, "hash_secret_raw", spy
             ):
            v = VaultManager(self.vault_path)
            v.init_vault(MASTER_PW)
        self.assertEqual(
            spy.call_count, 0, "Argon2 was called but fallback was requested"
        )


class TestLegacyVersionRejection(unittest.TestCase):
    """v2.0 and v2.1 vault files on disk must be rejected at load time."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self.temp_dir.name) / "legacy.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def _write_legacy_vault(self, version: str):
        # Minimal shaped document. Load should bail on version before parsing.
        payload = {
            "version": version,
            "created": "2025-11-19T12:34:56Z",
            "modified": "2025-11-19T12:34:56Z",
            "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
            "entries": {},
            "metadata": {"vault_name": "legacy"},
        }
        self.vault_path.write_text(json.dumps(payload))

    def test_v2_0_vault_rejected(self):
        self._write_legacy_vault("2.0")
        v = VaultManager(self.vault_path)
        with self.assertRaises(VaultException):
            v.load_vault(MASTER_PW)

    def test_v2_1_vault_rejected(self):
        self._write_legacy_vault("2.1")
        v = VaultManager(self.vault_path)
        with self.assertRaises(VaultException):
            v.load_vault(MASTER_PW)

    def test_v3_0_vault_accepted(self):
        v = VaultManager(self.vault_path)
        v.init_vault(MASTER_PW)
        data = json.loads(self.vault_path.read_text())
        self.assertEqual(data["version"], "3.0")
        v2 = VaultManager(self.vault_path)
        v2.load_vault(MASTER_PW)
        self.assertFalse(v2.is_locked)
        v2.clear_sensitive_data()


class TestBackupEnvelopeCarriesKdf(unittest.TestCase):
    """v3.1 outer envelope and v3.0 inner export_data both record kdf."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.vault_path = Path(self.temp_dir.name) / "src.json"
        self.backup_path = Path(self.temp_dir.name) / "backup.json"
        self.vault = VaultManager(self.vault_path)
        self.vault.init_vault(MASTER_PW)
        self.vault.load_vault(MASTER_PW)
        self.vault.add_entry(
            "gmail", "alice", "GmailSecret!2026#Abc",
            "https://mail.google.com", "primary",
        )

    def tearDown(self):
        self.vault.clear_sensitive_data()
        self.temp_dir.cleanup()

    def test_outer_envelope_has_kdf(self):
        self.vault.export_vault(self.backup_path, EXPORT_PW)
        outer = json.loads(self.backup_path.read_text())
        self.assertEqual(outer["version"], "3.1")
        self.assertIn("kdf", outer)
        self.assertIn("name", outer["kdf"])

    def test_inner_export_data_has_kdf_and_version(self):
        self.vault.export_vault(self.backup_path, EXPORT_PW)
        reader = VaultManager(self.vault_path)
        export_data = reader.import_vault(self.backup_path, EXPORT_PW)
        self.assertEqual(export_data["version"], "3.0")
        self.assertIn("_content_kdf", export_data)
        self.assertIn("_content_salt", export_data)
        self.assertIn("name", export_data["_content_kdf"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
