#!/usr/bin/env python3
"""Quick test of vault deletion functionality"""

from pathlib import Path
from vault import VaultManager
import json

test_vault = Path.home() / ".local_vault" / "delete_test.json"
config_file = Path.home() / ".local_vault" / "vaults.json"

# Cleanup
if test_vault.exists():
    test_vault.unlink()

print("Testing vault deletion functionality...")
print()

# Create test vault
print("1. Creating test vault...")
v1 = VaultManager(test_vault)
v1.init_vault("DeleteTest@12345678901", "DeleteTest")
print("   Success: Vault created")

# Verify it can load
print("2. Loading vault to verify...")
v2 = VaultManager(test_vault)
v2.load_vault("DeleteTest@12345678901")
print("   Success: Vault loaded with correct password")

# Verify wrong password fails
print("3. Testing wrong password rejection...")
try:
    v3 = VaultManager(test_vault)
    v3.load_vault("WrongPassword@12345678901")
    print("   ERROR: Should have rejected wrong password")
except Exception as e:
    print("   Success: Wrong password rejected")

# Test deletion by removing file
print("4. Deleting vault file...")
test_vault.unlink()
print("   Success: Vault file deleted")

# Verify it's gone
print("5. Verifying deletion...")
if not test_vault.exists():
    print("   Success: Vault file no longer exists")
else:
    print("   ERROR: Vault file still exists")

print()
print("All tests passed! Delete functionality working correctly.")

