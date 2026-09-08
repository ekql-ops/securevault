# 🔐 SecureVault — CLI Password Manager

[![tests](https://github.com/ekql-ops/securevault/actions/workflows/tests.yml/badge.svg)](https://github.com/ekql-ops/securevault/actions/workflows/tests.yml)
![coverage](https://img.shields.io/badge/coverage-74%25-green)
![python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)

A command-line password manager built in Python that stores all credentials with **AES-256 encryption**. Your passwords are never written to disk in plaintext.

---

## Features

- 🔑 **Master password** protected — one password to rule them all
- 🔒 **AES-256 encryption** via Fernet (symmetric encryption)
- 🧂 **PBKDF2-SHA256** key derivation with 480,000 iterations (OWASP compliant)
- 🎲 **Cryptographically secure password generator** (customisable length + symbols)
- 💪 **Password strength checker** built in
- 🔍 **Search** entries by name, URL, or username
- ➕ **Add, get, list, search, delete** entries
- 💾 All data stored locally in `~/.securevault/` — nothing is sent anywhere

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.10+ |
| Encryption | `cryptography` (Fernet / AES-256) |
| Key Derivation | PBKDF2-HMAC-SHA256 |
| Storage | Encrypted JSON |

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/ekql-ops/securevault.git
cd securevault
```

### 2. Install dependencies

```bash
pip install cryptography
```

### 3. Run

```bash
python vault.py
```

---

## Usage

On first run, you'll be prompted to set a master password. After that, the vault is unlocked each session with your master password.

```
╔══════════════════════════════╗
║       SecureVault v1.0       ║
╚══════════════════════════════╝

  ┌─ Commands ────────────────────┐
  │  [1]  Add / Update entry      │
  │  [2]  Get entry               │
  │  [3]  List all entries        │
  │  [4]  Search entries          │
  │  [5]  Delete entry            │
  │  [6]  Generate password       │
  │  [q]  Quit                    │
  └───────────────────────────────┘
```

### Adding an entry

```
Service name: GitHub
Username / Email: bakri20041@outlook.com
Password options:
  [g] Generate a strong password
  [m] Enter manually
Choice: g
Length (default 20): 24
Generated: X7@kqP!2mNvRsLd#9WzYtA4j
Strength:  ✓ Strong
```

---

## Security Notes

- The master password is **never stored** — only a salted hash is kept for verification
- A unique 32-byte salt is generated on vault creation
- The encryption key is derived fresh each session from your master password + salt
- Vault data is encrypted before being written to disk
- If you lose your master password, the vault **cannot be recovered**

---

## File Structure

```
securevault/
├── vault.py          # Main application
├── requirements.txt  # Dependencies
└── README.md
```

---

## Requirements

```
cryptography>=41.0.0
```

---

## Tests

64 tests covering key derivation, encryption, the vault lifecycle, entry
CRUD, the password generator and the interactive CLI. Every test that touches
the filesystem uses `tmp_path`, so the suite never reads or writes the real
`~/.securevault` directory.

```bash
pip install pytest pytest-cov
pytest                                      # run everything
pytest --cov=vault --cov-report=term-missing   # with coverage
```

Current coverage is 74%. The uncovered portion is the interactive prompt
loop in `initialise()` and `main()`, which are not worth mocking.

**The test that matters most** is `test_master_password_is_never_stored` — it
asserts the master password appears nowhere in either file on disk. If a
refactor ever broke that, everything else about this project would be
pointless.

### What writing the tests changed

The `Vault` class originally read its paths from module-level globals, which
meant there was no way to exercise it without touching the real vault in your
home directory. It now takes an optional `vault_dir`, defaulting to the same
place as before. Two methods were also split so the logic is separable from
the prompts: `create()` and `unlock_with()` do the work, while `initialise()`
and `unlock()` handle the interactive input around them.

That is a fair illustration of why tests are worth writing even on a small
project — they surface designs that only work in one context.

## Continuous integration

`.github/workflows/tests.yml` runs on every push and pull request:

- Tests across Python 3.10, 3.11 and 3.12
- Lint with `ruff`
- Coverage report uploaded as a build artifact

Rules are pinned in `ruff.toml` rather than relying on defaults, so a future
ruff release adding new rules cannot turn the build red without a code change.

---

## Author

**Abubakar Albakri** — BSc Computer Science, Manchester Metropolitan University  
[GitHub](https://github.com/ekql-ops)
