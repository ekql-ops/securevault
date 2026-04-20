# 🔐 SecureVault — CLI Password Manager

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
git clone https://github.com/AbubakarAli8/securevault.git
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

## Author

**Abubakar Albakri** — BSc Computer Science, Manchester Metropolitan University  
[GitHub](https://github.com/AbubakarAli8)
