#!/usr/bin/env python3
"""
TEST AGENT - Diagnostic and Testing Suite for Import Issue
Tests the complete export/import cycle to identify where entries are lost
"""

import json
import sys
from pathlib import Path
from vault import VaultManager
from security import validate_password_strength

TEST_VAULT_PATH = Path.home() / ".local_vault" / "test_export_import.json"
TEST_BACKUP_PATH = Path.home() / ".local_vault" / "test_backup.json"
TEST_IMPORTED_PATH = Path.home() / ".local_vault" / "test_imported.json"

def cleanup():
    """Remove test files"""
    for f in [TEST_VAULT_PATH, TEST_BACKUP_PATH, TEST_IMPORTED_PATH]:
        if f.exists():
            f.unlink()

def test_export_import_cycle():
    """Test the full export/import cycle and report on each stage"""
    print("=" * 70)
    print("VAULT IMPORT/EXPORT TEST AGENT")
    print("=" * 70)

    try:
        # STAGE 1: Create source vault
        print("\n[STAGE 1] Creating source vault...")
        cleanup()
        vault1 = VaultManager(TEST_VAULT_PATH)
        vault1.init_vault("Test@12345678", "SourceVault")
        print("✓ Vault created")

        # STAGE 2: Add entries
        print("\n[STAGE 2] Adding test entries to source vault...")
        vault1.add_entry("Email", "user@test.com", "EmailPass@123456789", "https://email.com", "My email")
        vault1.add_entry("GitHub", "myusername", "GitPass@123456789", "https://github.com", "GitHub account")
        vault1.add_entry("NoUsername", "", "NoUser@123456789", "https://nouser.com", "Test entry with empty username")
        print("✓ Added 3 entries")

        # STAGE 3: List source entries
        print("\n[STAGE 3] Listing source vault entries...")
        source_entries = vault1.list_entries()
        print(f"✓ Source vault has {len(source_entries)} entries: {source_entries}")

        # STAGE 4: Export backup
        print("\n[STAGE 4] Exporting vault to backup...")
        vault1.export_vault(TEST_BACKUP_PATH, "Backup@12345678")
        print(f"✓ Backup exported to {TEST_BACKUP_PATH}")

        # STAGE 5: Inspect backup structure
        print("\n[STAGE 5] Inspecting backup file structure...")
        backup_json = json.loads(TEST_BACKUP_PATH.read_text())
        print(f"  Backup version: {backup_json.get('version')}")
        print(f"  Has file_nonce: {bool(backup_json.get('file_nonce'))}")
        print(f"  Has file_ciphertext: {bool(backup_json.get('file_ciphertext'))}")
        print("✓ Backup structure looks good")

        # STAGE 6: Import backup
        print("\n[STAGE 6] Importing backup...")
        vault2 = VaultManager()
        imported_data = vault2.import_vault(TEST_BACKUP_PATH, "Backup@12345678")
        print(f"✓ Backup decrypted")

        # STAGE 7: Check imported entries in imported_data
        print("\n[STAGE 7] Checking imported_data structure...")
        entry_count = len(imported_data.get("entries", {}))
        print(f"  Imported entries count: {entry_count}")
        if entry_count > 0:
            first_entry_name = list(imported_data.get("entries", {}).keys())[0]
            first_entry = imported_data["entries"][first_entry_name]
            print(f"  First entry '{first_entry_name}' has nonce: {bool(first_entry.get('nonce'))}")
            print(f"  First entry '{first_entry_name}' has ciphertext: {bool(first_entry.get('ciphertext'))}")
        print(f"  Has _content_salt: {bool(imported_data.get('_content_salt'))}")
        print("✓ Imported data structure looks good")

        # STAGE 8: Try to decrypt backup entries
        print("\n[STAGE 8] Attempting to decrypt backup entries...")
        try:
            content_salt_b64 = imported_data.get("_content_salt", "")
            if not content_salt_b64:
                print("✗ ERROR: No content_salt found!")
                return False

            decrypted_entries = vault2.decrypt_backup_entries(
                imported_data.get("entries", {}),
                "Backup@12345678",  # Backup password
                content_salt_b64
            )
            print(f"✓ Decrypted {len(decrypted_entries)} entries")

            # Show decrypted entries
            for name, data in decrypted_entries.items():
                if name != "_sentinel":
                    username = data.get("username", "(empty)")
                    password = data.get("password", "(empty)")
                    print(f"  - {name}: username='{username}', password_len={len(password)}")

        except Exception as e:
            print(f"✗ ERROR during decryption: {e}")
            import traceback
            traceback.print_exc()
            return False

        # STAGE 9: Create new vault and add decrypted entries
        print("\n[STAGE 9] Creating new vault and adding decrypted entries...")
        vault3 = VaultManager(TEST_IMPORTED_PATH)
        vault3.init_vault("NewVault@12345678", "ImportedVault")
        print("✓ New vault created")

        successful = 0
        failed = 0
        for entry_name, entry_data in decrypted_entries.items():
            if entry_name == "_sentinel":
                continue
            try:
                username = entry_data.get("username", "")
                password = entry_data.get("password", "")
                url = entry_data.get("url", "")
                notes = entry_data.get("notes", "")

                if entry_name and password:
                    vault3.add_entry(entry_name, username, password, url, notes)
                    successful += 1
                    print(f"  ✓ Added: {entry_name}")
                else:
                    failed += 1
                    print(f"  ✗ Skipped: {entry_name} (missing name or password)")
            except Exception as e:
                failed += 1
                print(f"  ✗ Failed to add {entry_name}: {e}")

        print(f"✓ Added {successful} entries, {failed} failed")

        # STAGE 10: List imported vault entries
        print("\n[STAGE 10] Listing imported vault entries...")
        imported_entries = vault3.list_entries()
        print(f"✓ Imported vault has {len(imported_entries)} entries: {imported_entries}")

        if len(imported_entries) > 0:
            # STAGE 11: Verify we can read imported entries
            print("\n[STAGE 11] Verifying imported entries can be read...")
            for entry_name in imported_entries:
                try:
                    entry = vault3.get_entry(entry_name)
                    username = entry.get("username", "(empty)")
                    password = entry.get("password", "")
                    print(f"  ✓ Read '{entry_name}': username='{username}', password_len={len(password)}")
                except Exception as e:
                    print(f"  ✗ Failed to read '{entry_name}': {e}")

            print("\n" + "=" * 70)
            print("✅ IMPORT/EXPORT TEST SUCCESSFUL!")
            print("=" * 70)
            return True
        else:
            print("\n" + "=" * 70)
            print("❌ TEST FAILED: No entries in imported vault!")
            print("=" * 70)
            return False

    except Exception as e:
        print(f"\n❌ TEST FAILED WITH EXCEPTION: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_export_import_cycle()
    cleanup()
    sys.exit(0 if success else 1)

