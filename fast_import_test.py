#!/usr/bin/env python3
"""
FAST IMPORT TEST - Command line diagnostic
Tests import without GUI - identifies exactly where entries are lost
"""

import json
import sys
from pathlib import Path
from vault import VaultManager

# Use simple strong passwords for testing
SOURCE_VAULT = Path.home() / ".local_vault" / "fast_test_source.json"
BACKUP_FILE = Path.home() / ".local_vault" / "fast_test_backup.json"
IMPORT_VAULT = Path.home() / ".local_vault" / "fast_test_imported.json"

def cleanup():
    for f in [SOURCE_VAULT, BACKUP_FILE, IMPORT_VAULT]:
        if f.exists():
            f.unlink()

def test_import():
    """Fast import test - identifies exact problem"""
    cleanup()

    print("\n" + "="*70)
    print("FAST IMPORT TEST")
    print("="*70)

    try:
        # STAGE 1: Create source vault with entry
        print("\n[1] Creating source vault...")
        v1 = VaultManager(SOURCE_VAULT)
        v1.init_vault("Source@12345678901", "SourceVault")
        v1.add_entry("TestEntry", "testuser", "TestPass@12345678901", "https://test.com", "Test")
        print(f"    Entries in source: {v1.list_entries()}")

        # STAGE 2: Export backup
        print("\n[2] Exporting backup...")
        v1.export_vault(BACKUP_FILE, "Backup@12345678901")
        print(f"    Backup file size: {BACKUP_FILE.stat().st_size} bytes")

        # STAGE 3: Import backup structure
        print("\n[3] Importing backup (step 1: decrypt structure)...")
        v2 = VaultManager()
        imported_data = v2.import_vault(BACKUP_FILE, "Backup@12345678901")
        print(f"    Imported data keys: {list(imported_data.keys())}")
        print(f"    Entry count in imported_data: {len(imported_data.get('entries', {}))}")

        # STAGE 4: Check content_salt
        print("\n[4] Checking content_salt...")
        content_salt = imported_data.get("_content_salt", "")
        if not content_salt:
            print("    ERROR: No _content_salt!")
            return False
        print(f"    content_salt present: YES")

        # STAGE 5: Decrypt entries
        print("\n[5] Decrypting entries (step 2: decrypt each entry)...")
        try:
            decrypted = v2.decrypt_backup_entries(
                imported_data.get("entries", {}),
                "Backup@12345678901",  # BACKUP PASSWORD
                content_salt
            )
            print(f"    Decrypted count: {len(decrypted)}")
            for name, data in decrypted.items():
                if name != "_sentinel":
                    pwd_len = len(data.get("password", ""))
                    print(f"    - {name}: pwd_len={pwd_len}, user={data.get('username', 'EMPTY')}")
        except Exception as e:
            print(f"    ERROR: {e}")
            import traceback
            traceback.print_exc()
            return False

        # STAGE 6: Create new vault and add entries
        print("\n[6] Creating new vault and adding entries (step 3: add_entry_from_import)...")
        v3 = VaultManager(IMPORT_VAULT)
        v3.init_vault("Import@12345678901", "ImportedVault")

        added = 0
        for name, data in decrypted.items():
            if name == "_sentinel":
                continue
            try:
                v3.add_entry_from_import(
                    name,
                    data.get("username", ""),
                    data.get("password", ""),
                    data.get("url", ""),
                    data.get("notes", "")
                )
                added += 1
                print(f"    Added: {name}")
            except Exception as e:
                print(f"    ERROR adding {name}: {e}")

        print(f"    Total added: {added}")

        # STAGE 7: Check vault contents
        print("\n[7] Checking imported vault contents...")
        final_entries = v3.list_entries()
        print(f"    Entries in imported vault: {final_entries}")

        if len(final_entries) > 0:
            print(f"    Entry details: {final_entries[0]}")
            entry_data = v3.get_entry(final_entries[0])
            print(f"    Username: {entry_data.get('username', 'EMPTY')}")
            print(f"    Password: {entry_data.get('password', 'EMPTY')}")

            print("\n" + "="*70)
            print("SUCCESS! Entries imported correctly")
            print("="*70)
            return True
        else:
            print("\n" + "="*70)
            print("FAILURE - No entries in imported vault!")
            print("="*70)
            return False

    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        cleanup()

if __name__ == "__main__":
    success = test_import()
    sys.exit(0 if success else 1)

