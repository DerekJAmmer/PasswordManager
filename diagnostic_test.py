#!/usr/bin/env python3
"""
TESTER AGENT - Diagnostic Script
Runs actual import test to identify where entries are lost
"""

import json
import sys
from pathlib import Path
from vault import VaultManager

TEST_VAULT = Path.home() / ".local_vault" / "diagnostic_test.json"
TEST_BACKUP = Path.home() / ".local_vault" / "diagnostic_backup.json"
TEST_IMPORTED = Path.home() / ".local_vault" / "diagnostic_imported.json"

def cleanup():
    for f in [TEST_VAULT, TEST_BACKUP, TEST_IMPORTED]:
        if f.exists():
            f.unlink()

def run_diagnostic():
    """Run diagnostic test and report findings"""
    cleanup()

    print("\n" + "="*70)
    print("TESTER AGENT - DIAGNOSTIC TEST")
    print("="*70)

    try:
        # STAGE 1: Create and populate source vault
        print("\n[STAGE 1] Creating source vault with test entry...")
        v1 = VaultManager(TEST_VAULT)
        v1.init_vault("Test@12345678", "SourceVault")
        v1.add_entry("TestEntry", "testuser", "TestPass@123456789", "https://test.com", "Test notes")
        entries = v1.list_entries()
        print(f"✓ Source vault has {len(entries)} entries: {entries}")

        # STAGE 2: Export backup
        print("\n[STAGE 2] Exporting backup...")
        v1.export_vault(TEST_BACKUP, "Backup@12345678")
        print(f"✓ Backup created")

        # STAGE 3: Import backup
        print("\n[STAGE 3] Importing backup...")
        v2 = VaultManager()
        imported_data = v2.import_vault(TEST_BACKUP, "Backup@12345678")
        print(f"✓ Import returned {len(imported_data.get('entries', {}))} entries in imported_data")

        # STAGE 4: Check content_salt
        print("\n[STAGE 4] Checking content_salt...")
        content_salt = imported_data.get("_content_salt", "")
        if content_salt:
            print(f"✓ content_salt found: {content_salt[:20]}...")
        else:
            print(f"✗ ERROR: No _content_salt in imported_data!")
            print(f"   Available keys: {list(imported_data.keys())}")
            return False

        # STAGE 5: Try to decrypt entries
        print("\n[STAGE 5] Attempting to decrypt entries...")
        try:
            decrypted = v2.decrypt_backup_entries(
                imported_data.get("entries", {}),
                "Backup@12345678",
                content_salt
            )
            print(f"✓ Decrypted {len(decrypted)} entries")
            for name in decrypted:
                if name != "_sentinel":
                    print(f"  - {name}")
        except Exception as e:
            print(f"✗ ERROR during decryption: {e}")
            import traceback
            traceback.print_exc()
            return False

        # STAGE 6: Check if add_entry_from_import exists
        print("\n[STAGE 6] Checking for add_entry_from_import method...")
        if hasattr(v2, 'add_entry_from_import'):
            print(f"✓ Method exists")
        else:
            print(f"✗ ERROR: add_entry_from_import method NOT FOUND!")
            print(f"   Available methods: {[m for m in dir(v2) if not m.startswith('_') and 'entry' in m.lower()]}")
            return False

        # STAGE 7: Create new vault and try to add entries
        print("\n[STAGE 7] Creating new vault and adding decrypted entries...")
        v3 = VaultManager(TEST_IMPORTED)
        v3.init_vault("NewVault@12345678", "ImportedVault")
        print(f"✓ New vault created")

        added = 0
        for name, data in decrypted.items():
            if name == "_sentinel":
                continue
            try:
                print(f"  Adding: {name}")
                print(f"    Username: '{data.get('username', '')}'")
                print(f"    Password: '{data.get('password', '')}'")
                v3.add_entry_from_import(
                    name,
                    data.get("username", ""),
                    data.get("password", ""),
                    data.get("url", ""),
                    data.get("notes", "")
                )
                added += 1
                print(f"    ✓ Added")
            except Exception as e:
                print(f"    ✗ ERROR: {e}")

        print(f"✓ Added {added} entries to new vault")

        # STAGE 8: List entries in new vault
        print("\n[STAGE 8] Listing entries in imported vault...")
        final_entries = v3.list_entries()
        print(f"✓ Imported vault has {len(final_entries)} entries: {final_entries}")

        if len(final_entries) > 0:
            print("\n" + "="*70)
            print("✅ SUCCESS - Entries imported!")
            print("="*70)
            return True
        else:
            print("\n" + "="*70)
            print("❌ FAILURE - 0 entries in imported vault")
            print("="*70)
            return False

    except Exception as e:
        print(f"\n❌ DIAGNOSTIC FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        cleanup()

if __name__ == "__main__":
    success = run_diagnostic()
    sys.exit(0 if success else 1)

