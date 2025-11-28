#!/usr/bin/env python3
"""
Complete import workflow test
Tests the entire import process: create vault -> backup -> import -> verify
"""

import json
from pathlib import Path
from vault import VaultManager

def test_complete_import_workflow():
    """Test complete workflow: source vault -> backup -> import"""

    test_dir = Path.home() / ".local_vault" / "test_workflow"
    test_dir.mkdir(parents=True, exist_ok=True)

    source_vault_path = test_dir / "source.json"
    backup_path = test_dir / "backup.json"
    imported_vault_path = test_dir / "imported.json"

    # Cleanup
    for f in [source_vault_path, backup_path, imported_vault_path]:
        if f.exists():
            f.unlink()

    try:
        print("\n" + "="*80)
        print("COMPLETE IMPORT WORKFLOW TEST")
        print("="*80)

        # STAGE 1: Create source vault with multiple entries
        print("\n[STAGE 1] Creating source vault with 3 entries...")
        source_vault = VaultManager(source_vault_path)
        source_vault.init_vault("SourceVault@123456789", "SourceVault")

        entries_to_add = [
            ("Gmail", "user@gmail.com", "Gmail@12345678901", "https://gmail.com", "Google email"),
            ("GitHub", "github_user", "GitHubPass@12345678901", "https://github.com", "Code repo"),
            ("BankAccount", "bankuser", "BankPass@12345678901", "https://bank.com", "Bank login"),
        ]

        for name, user, pwd, url, notes in entries_to_add:
            source_vault.add_entry(name, user, pwd, url, notes)
            print(f"  ✓ Added: {name}")

        # STAGE 2: Export backup
        print("\n[STAGE 2] Exporting backup...")
        source_vault.export_vault(backup_path, "Backup@123456789")
        backup_size = backup_path.stat().st_size
        print(f"  ✓ Backup created: {backup_size} bytes")

        # STAGE 3: Import backup structure (decrypt file)
        print("\n[STAGE 3] Importing backup structure...")
        import_vault_obj = VaultManager()
        imported_data = import_vault_obj.import_vault(backup_path, "Backup@123456789")
        print(f"  ✓ Backup decrypted")
        print(f"    - Exported version: {imported_data.get('version')}")
        print(f"    - Entries in backup: {len(imported_data.get('entries', {}))}")
        print(f"    - Metadata: {imported_data.get('metadata', {})}")

        # STAGE 4: Decrypt entries from backup
        print("\n[STAGE 4] Decrypting backup entries...")
        content_salt_b64 = imported_data.get("_content_salt", "")
        if not content_salt_b64:
            print("  ✗ ERROR: No content_salt found!")
            return False

        decrypted_entries = import_vault_obj.decrypt_backup_entries(
            imported_data.get("entries", {}),
            "Backup@123456789",
            content_salt_b64
        )

        if not decrypted_entries:
            print("  ✗ ERROR: No entries decrypted!")
            return False

        print(f"  ✓ Decrypted {len(decrypted_entries)} entries")
        for name, data in decrypted_entries.items():
            if name != "_sentinel":
                print(f"    - {name}: user='{data.get('username')}', pwd_len={len(data.get('password', ''))}")

        # STAGE 5: Create new vault and add entries
        print("\n[STAGE 5] Creating new vault and adding decrypted entries...")
        new_vault = VaultManager(imported_vault_path)
        new_vault.init_vault("ImportedVault@123456789", "ImportedVault")

        imported_count = 0
        for entry_name, entry_data in decrypted_entries.items():
            if entry_name == "_sentinel":
                continue

            # This is what the GUI does
            new_vault.add_entry_from_import(
                entry_name,
                entry_data.get("username", ""),
                entry_data.get("password", ""),
                entry_data.get("url", ""),
                entry_data.get("notes", "")
            )
            imported_count += 1
            print(f"  ✓ Added imported entry: {entry_name}")

        # STAGE 6: Verify imported entries
        print("\n[STAGE 6] Verifying imported entries...")
        final_entries = new_vault.list_entries()
        print(f"  Entry list: {final_entries}")

        if len(final_entries) != imported_count:
            print(f"  ✗ ERROR: Expected {imported_count} entries but got {len(final_entries)}")
            return False

        all_match = True
        for entry_name in final_entries:
            entry_data = new_vault.get_entry(entry_name)
            expected_data = decrypted_entries.get(entry_name)

            if not expected_data:
                print(f"  ✗ Entry '{entry_name}' not found in decrypted data")
                all_match = False
                continue

            if (entry_data.get("username") != expected_data.get("username") or
                entry_data.get("password") != expected_data.get("password")):
                print(f"  ✗ Entry '{entry_name}' data mismatch")
                all_match = False
            else:
                print(f"  ✓ {entry_name}: {entry_data.get('username')} / password verified")

        if not all_match:
            return False

        print("\n" + "="*80)
        print("✓ COMPLETE WORKFLOW TEST PASSED")
        print("="*80)
        print(f"\nSummary:")
        print(f"  Source vault entries: {len(entries_to_add)}")
        print(f"  Backup file size: {backup_size} bytes")
        print(f"  Imported vault entries: {len(final_entries)}")
        print(f"  All data verified: YES")
        return True

    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Cleanup
        try:
            import shutil
            if test_dir.exists():
                shutil.rmtree(test_dir)
        except:
            pass

if __name__ == "__main__":
    success = test_complete_import_workflow()
    exit(0 if success else 1)

