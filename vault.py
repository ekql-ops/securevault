"""
╔══════════════════════════════════════════════════════════════╗
║               SecureVault — CLI Password Manager             ║
║                     Abubakar Albakri, 2026                   ║
╚══════════════════════════════════════════════════════════════╝

A command-line password manager that encrypts all stored credentials
using AES-256 encryption via the Fernet symmetric encryption scheme.
Passwords are never stored in plaintext.
"""

import getpass
import hashlib
import json
import secrets
import string
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import base64

    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("[ERROR] Missing dependency: cryptography")
    print("  Run: pip install cryptography")
    sys.exit(1)


# ─── Constants ────────────────────────────────────────────────
VAULT_FILE   = Path.home() / ".securevault" / "vault.enc"
CONFIG_FILE  = Path.home() / ".securevault" / "config.json"
SALT_SIZE    = 32
ITERATIONS   = 480_000  # OWASP recommended minimum for PBKDF2-SHA256


# ─── Crypto Helpers ───────────────────────────────────────────

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from the master password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def hash_master(master_password: str, salt: bytes) -> str:
    """Hash the master password for verification (separate from encryption key)."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode(),
        salt,
        ITERATIONS
    ).hex()


def encrypt_data(data: dict, key: bytes) -> bytes:
    """Serialize and encrypt vault data."""
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode())


def decrypt_data(encrypted: bytes, key: bytes) -> dict:
    """Decrypt and deserialize vault data."""
    f = Fernet(key)
    return json.loads(f.decrypt(encrypted).decode())


# ─── Vault Management ─────────────────────────────────────────

class Vault:
    def __init__(self, vault_dir: Path | None = None):
        """
        vault_dir defaults to ~/.securevault. It is injectable so that tests
        can point at a temporary directory instead of the real home folder —
        writing tests is what surfaced this; the paths used to be module-level
        globals and there was no way to exercise the class without touching
        the user's actual vault.
        """
        self.vault_dir  = Path(vault_dir) if vault_dir else VAULT_FILE.parent
        self.vault_file  = self.vault_dir / "vault.enc"
        self.config_file = self.vault_dir / "config.json"
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        self.key = None
        self.data = {}

    def is_initialised(self) -> bool:
        return self.vault_file.exists() and self.config_file.exists()

    def initialise(self):
        """First-time setup: create master password and encrypt an empty vault."""
        print("\n  Welcome to SecureVault!")
        print("  ─────────────────────────────────────")
        print("  You need to set a master password.")
        print("  This password CANNOT be recovered if lost.\n")

        while True:
            pw  = getpass.getpass("  Set master password: ")
            pw2 = getpass.getpass("  Confirm master password: ")
            if pw != pw2:
                print("  [!] Passwords do not match. Try again.\n")
                continue
            if len(pw) < 8:
                print("  [!] Password must be at least 8 characters.\n")
                continue
            break

        self.create(pw)
        print("\n  [✓] Vault created successfully.\n")

    def create(self, master_password: str):
        """Create a new vault with the given master password. No I/O prompts,
        so this is callable from tests and from initialise() alike."""
        salt = secrets.token_bytes(SALT_SIZE)
        self.key = derive_key(master_password, salt)

        config = {
            "salt": salt.hex(),
            "master_hash": hash_master(master_password, salt),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.config_file.write_text(json.dumps(config, indent=2))
        self.data = {"entries": {}}
        self._save()

    def unlock(self) -> bool:
        """Prompt for master password and unlock the vault."""
        pw = getpass.getpass("  Master password: ")
        if not self.unlock_with(pw):
            print("\n  [✗] Incorrect master password, or the vault is corrupted.\n")
            return False
        return True

    def unlock_with(self, master_password: str) -> bool:
        """Verify a master password and decrypt the vault. Returns False on a
        wrong password or unreadable data. No prompts, so tests can call it."""
        config = json.loads(self.config_file.read_text())
        salt = bytes.fromhex(config["salt"])

        if hash_master(master_password, salt) != config["master_hash"]:
            return False

        self.key = derive_key(master_password, salt)
        try:
            self.data = decrypt_data(self.vault_file.read_bytes(), self.key)
        except (InvalidToken, json.JSONDecodeError, ValueError, OSError):
            return False
        return True

    def _save(self):
        """Encrypt and write vault to disk."""
        self.vault_file.write_bytes(encrypt_data(self.data, self.key))

    # ─── CRUD Operations ──────────────────────────────────────

    def add_entry(self, name: str, username: str, password: str, url: str = "", notes: str = ""):
        """Add or update a password entry."""
        self.data["entries"][name] = {
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save()

    def get_entry(self, name: str) -> dict | None:
        return self.data["entries"].get(name)

    def delete_entry(self, name: str) -> bool:
        if name in self.data["entries"]:
            del self.data["entries"][name]
            self._save()
            return True
        return False

    def list_entries(self) -> list[str]:
        return sorted(self.data["entries"].keys())

    def search_entries(self, query: str) -> list[str]:
        q = query.lower()
        return [
            name for name in self.data["entries"]
            if q in name.lower()
            or q in self.data["entries"][name].get("url", "").lower()
            or q in self.data["entries"][name].get("username", "").lower()
        ]


# ─── Password Generator ───────────────────────────────────────

def generate_password(length: int = 20, use_symbols: bool = True) -> str:
    """Generate a cryptographically secure random password."""
    chars = string.ascii_letters + string.digits
    if use_symbols:
        chars += string.punctuation

    while True:
        pw = "".join(secrets.choice(chars) for _ in range(length))
        # Ensure at least one of each required character type
        has_upper  = any(c.isupper() for c in pw)
        has_lower  = any(c.islower() for c in pw)
        has_digit  = any(c.isdigit() for c in pw)
        has_symbol = any(c in string.punctuation for c in pw) if use_symbols else True
        if has_upper and has_lower and has_digit and has_symbol:
            return pw


def password_strength(password: str) -> tuple[str, str]:
    """Return a strength label and colour hint for a password."""
    checks = (
        len(password) >= 12,
        len(password) >= 20,
        any(c.isupper() for c in password),
        any(c.islower() for c in password),
        any(c.isdigit() for c in password),
        any(c in string.punctuation for c in password),
    )
    score = sum(checks)

    if score <= 2:
        return "Weak", "⚠"
    if score <= 4:
        return "Medium", "~"
    return "Strong", "✓"


# ─── CLI Interface ────────────────────────────────────────────

def print_header():
    print("\n  ╔══════════════════════════════╗")
    print("  ║       SecureVault v1.0       ║")
    print("  ╚══════════════════════════════╝")


def print_menu():
    print("\n  ┌─ Commands ────────────────────┐")
    print("  │  [1]  Add / Update entry      │")
    print("  │  [2]  Get entry               │")
    print("  │  [3]  List all entries        │")
    print("  │  [4]  Search entries          │")
    print("  │  [5]  Delete entry            │")
    print("  │  [6]  Generate password       │")
    print("  │  [q]  Quit                    │")
    print("  └───────────────────────────────┘")


def cmd_add(vault: Vault):
    print("\n  ── Add Entry ──")
    name     = input("  Service name (e.g. 'GitHub'): ").strip()
    if not name:
        print("  [!] Name cannot be empty.")
        return

    existing = vault.get_entry(name)
    if existing:
        print(f"  [!] Entry '{name}' already exists. Updating it.")

    username = input("  Username / Email: ").strip()

    print("  Password options:")
    print("    [g] Generate a strong password")
    print("    [m] Enter manually")
    choice = input("  Choice: ").strip().lower()

    if choice == "g":
        try:
            length = int(input("  Length (default 20): ").strip() or "20")
        except ValueError:
            length = 20
        password = generate_password(length)
        strength, icon = password_strength(password)
        print(f"  Generated: {password}")
        print(f"  Strength:  {icon} {strength}")
    else:
        password = getpass.getpass("  Password: ")
        strength, icon = password_strength(password)
        print(f"  Strength:  {icon} {strength}")

    url   = input("  URL (optional): ").strip()
    notes = input("  Notes (optional): ").strip()

    vault.add_entry(name, username, password, url, notes)
    print(f"\n  [✓] Entry '{name}' saved.\n")


def cmd_get(vault: Vault):
    print("\n  ── Get Entry ──")
    name = input("  Service name: ").strip()
    entry = vault.get_entry(name)
    if not entry:
        print(f"  [!] No entry found for '{name}'.\n")
        return

    print(f"\n  ┌─ {name} ─{'─' * max(0, 28 - len(name))}┐")
    print(f"  │  Username : {entry['username']}")
    print(f"  │  Password : {entry['password']}")
    if entry.get("url"):
        print(f"  │  URL      : {entry['url']}")
    if entry.get("notes"):
        print(f"  │  Notes    : {entry['notes']}")
    print(f"  │  Saved    : {entry['created_at'][:10]}")
    print(f"  └{'─' * 35}┘\n")


def cmd_list(vault: Vault):
    entries = vault.list_entries()
    if not entries:
        print("\n  [!] Vault is empty.\n")
        return

    print(f"\n  ── All Entries ({len(entries)}) ──")
    for i, name in enumerate(entries, 1):
        entry = vault.get_entry(name)
        url_str = f"  {entry.get('url', '')}" if entry.get("url") else ""
        print(f"  {i:>3}.  {name}{url_str}")
    print()


def cmd_search(vault: Vault):
    print("\n  ── Search ──")
    query   = input("  Search query: ").strip()
    results = vault.search_entries(query)
    if not results:
        print(f"  [!] No entries match '{query}'.\n")
        return

    print(f"\n  Found {len(results)} result(s):")
    for name in results:
        entry = vault.get_entry(name)
        print(f"    • {name} ({entry.get('username', '')})")
    print()


def cmd_delete(vault: Vault):
    print("\n  ── Delete Entry ──")
    name = input("  Service name to delete: ").strip()
    entry = vault.get_entry(name)
    if not entry:
        print(f"  [!] No entry found for '{name}'.\n")
        return

    confirm = input(f"  Are you sure you want to delete '{name}'? (yes/no): ").strip().lower()
    if confirm == "yes":
        vault.delete_entry(name)
        print(f"  [✓] Entry '{name}' deleted.\n")
    else:
        print("  [!] Deletion cancelled.\n")


def cmd_generate():
    print("\n  ── Generate Password ──")
    try:
        length = int(input("  Length (default 20): ").strip() or "20")
    except ValueError:
        length = 20

    use_sym = input("  Include symbols? (y/n, default y): ").strip().lower()
    symbols = use_sym != "n"

    pw = generate_password(length, symbols)
    strength, icon = password_strength(pw)
    print(f"\n  Password : {pw}")
    print(f"  Strength : {icon} {strength}")
    print(f"  Length   : {len(pw)} characters\n")


# ─── Entry Point ──────────────────────────────────────────────

def main():
    print_header()

    vault = Vault()

    if not vault.is_initialised():
        vault.initialise()
    else:
        print("\n  Unlocking vault...")
        if not vault.unlock():
            sys.exit(1)
        print("  [✓] Vault unlocked.\n")

    while True:
        print_menu()
        choice = input("  > ").strip().lower()

        if choice == "1":
            cmd_add(vault)
        elif choice == "2":
            cmd_get(vault)
        elif choice == "3":
            cmd_list(vault)
        elif choice == "4":
            cmd_search(vault)
        elif choice == "5":
            cmd_delete(vault)
        elif choice == "6":
            cmd_generate()
        elif choice in ("q", "quit", "exit"):
            print("\n  Vault locked. Goodbye.\n")
            break
        else:
            print("  [!] Unknown command.\n")


if __name__ == "__main__":
    main()
