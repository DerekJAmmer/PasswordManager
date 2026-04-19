# PasswordManager

A local-first password manager in Python. AES-256-GCM vault on disk, Argon2id key derivation, Tk GUI and CLI. No server, no cloud, no account.

## Why I built it

I wanted a real project to practice applied crypto and desktop-app fundamentals end to end, not a tutorial clone. Keeping it local meant I had to be honest about the threat model instead of hiding behind a backend.

## What it does

- Unlock a vault with a master password.
- Add, edit, delete, and search password entries.
- Copy a password to the clipboard, with an automatic clear after 15 seconds.
- Export and import encrypted backups with a separate backup password.
- Auto-lock after 15 minutes of inactivity.
- Rate-limit failed unlock attempts with exponential backoff and on-disk lockout.
- Write every sensitive operation to an audit log.

## How it works

The master password runs through Argon2id (OWASP 2023 parameters) to produce a 32-byte key. Each entry is encrypted with AES-256-GCM under its own nonce and tagged with HMAC-SHA256. The vault file is versioned, and vault-level timestamps live inside an encrypted metadata blob so the on-disk file does not leak when the vault was created or last touched. Derived keys are held in a `bytearray`, locked into RAM where the OS allows it (`mlock` / `VirtualLock`), and zero-filled as soon as the operation is done.

For the full picture see [DOCUMENTATION.md](DOCUMENTATION.md) and [SECURITY_SUMMARY.md](SECURITY_SUMMARY.md).

## Run it

```
git clone https://github.com/DerekJAmmer/PasswordManager.git
cd PasswordManager
pip install -r requirements.txt
python vault.py           # GUI
python vault.py --help    # CLI
```

Developed and tested on Python 3.13 (Windows). `cryptography`, `argon2-cffi`, and `pyperclip` are the only runtime dependencies.

## Project shape

| File | Role |
|------|------|
| `vault.py` | Vault format, encryption, CLI entry point |
| `security.py` | KDF helpers, memory locking, file permissions, audit log |
| `gui.py` | Tk GUI |
| `clipboard_manager.py` | Clipboard copy with auto-clear |
| `config.py` | Paths, crypto parameters, version constants |
| `exceptions.py` | Domain exceptions |

## Engineering notes

- I work the project in phases. Each phase follows plan, implement, verify, fix, push. A phase is not done until it is on the remote.
- 69 unit tests cover the crypto paths, backup round-trip, file permissions, memory wipe, and the encrypted metadata block.
- Phase 1 was an honesty pass on the crypto. Earlier versions advertised Argon2id but the code ran PBKDF2. I wired up real Argon2id, bumped the vault format, and rewrote the docs to match.
- Phase 2 was security remediation. I hardened key-in-RAM handling, dropped vault files to `0o400` at rest, replaced three `shell=True` `icacls` calls with a list-form subprocess, moved timestamps into the encrypted metadata block, and wrote a per-finding status report against the audit.
- Phase 3 is next: architecture cleanup ahead of a modular package restructure.

## Further reading

- [DOCUMENTATION.md](DOCUMENTATION.md) — user guide and developer notes
- [SECURITY_SUMMARY.md](SECURITY_SUMMARY.md) — threat model, crypto choices, per-finding remediation status
- [Vulnerability_Assessment_November_21_2025.md](Vulnerability_Assessment_November_21_2025.md) — the original audit I am working against

## Status

Active personal project. Not a product. Use at your own risk.
