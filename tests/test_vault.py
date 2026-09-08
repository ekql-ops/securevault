"""
Tests for SecureVault.

Run with:
    pytest -v
    pytest --cov=vault --cov-report=term-missing

Every test that touches the filesystem uses pytest's tmp_path fixture, so
the suite never reads or writes the real ~/.securevault directory.
"""

import json
import secrets
import string

import pytest
from cryptography.fernet import InvalidToken

from vault import (
    ITERATIONS,
    SALT_SIZE,
    Vault,
    decrypt_data,
    derive_key,
    encrypt_data,
    generate_password,
    hash_master,
    password_strength,
)

# ─────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────

MASTER = "correct-horse-battery-staple"


@pytest.fixture
def vault(tmp_path):
    """An initialised vault in a throwaway directory."""
    v = Vault(vault_dir=tmp_path / "vault")
    v.create(MASTER)
    return v


@pytest.fixture
def salt():
    return secrets.token_bytes(SALT_SIZE)


# ─────────────────────────────────────────────────────────────
# Key derivation
# ─────────────────────────────────────────────────────────────

class TestKeyDerivation:

    def test_same_password_and_salt_gives_same_key(self, salt):
        assert derive_key(MASTER, salt) == derive_key(MASTER, salt)

    def test_different_password_gives_different_key(self, salt):
        assert derive_key(MASTER, salt) != derive_key("something-else", salt)

    def test_same_password_different_salt_gives_different_key(self):
        a, b = secrets.token_bytes(SALT_SIZE), secrets.token_bytes(SALT_SIZE)
        assert derive_key(MASTER, a) != derive_key(MASTER, b)

    def test_key_is_valid_fernet_length(self, salt):
        # Fernet expects a 32-byte key, urlsafe-base64 encoded to 44 chars
        assert len(derive_key(MASTER, salt)) == 44

    def test_iteration_count_meets_owasp_floor(self):
        assert ITERATIONS >= 480_000

    def test_verification_hash_is_not_the_encryption_key(self, salt):
        """The hash stored on disk must not be derivable into the key —
        otherwise anyone reading config.json could decrypt the vault."""
        key = derive_key(MASTER, salt)
        digest = hash_master(MASTER, salt)
        assert digest.encode() not in key
        assert key not in digest.encode()


# ─────────────────────────────────────────────────────────────
# Encryption
# ─────────────────────────────────────────────────────────────

class TestEncryption:

    def test_roundtrip_preserves_data(self, salt):
        key = derive_key(MASTER, salt)
        original = {"entries": {"GitHub": {"username": "akira", "password": "hunter2"}}}
        assert decrypt_data(encrypt_data(original, key), key) == original

    def test_ciphertext_does_not_contain_plaintext(self, salt):
        key = derive_key(MASTER, salt)
        blob = encrypt_data({"entries": {"x": {"password": "SuperSecret123"}}}, key)
        assert b"SuperSecret123" not in blob
        assert b"password" not in blob

    def test_wrong_key_cannot_decrypt(self, salt):
        good = derive_key(MASTER, salt)
        bad = derive_key(MASTER, secrets.token_bytes(SALT_SIZE))
        blob = encrypt_data({"entries": {}}, good)
        with pytest.raises(InvalidToken):
            decrypt_data(blob, bad)

    def test_encrypting_twice_gives_different_ciphertext(self, salt):
        """Fernet includes a timestamp and random IV, so identical plaintext
        must not produce identical output."""
        key = derive_key(MASTER, salt)
        payload = {"entries": {}}
        assert encrypt_data(payload, key) != encrypt_data(payload, key)

    def test_tampered_ciphertext_is_rejected(self, salt):
        key = derive_key(MASTER, salt)
        blob = bytearray(encrypt_data({"entries": {}}, key))
        blob[-6] ^= 0x01           # flip a bit
        with pytest.raises(InvalidToken):
            decrypt_data(bytes(blob), key)


# ─────────────────────────────────────────────────────────────
# Vault lifecycle
# ─────────────────────────────────────────────────────────────

class TestVaultLifecycle:

    def test_new_vault_is_not_initialised(self, tmp_path):
        assert Vault(vault_dir=tmp_path / "empty").is_initialised() is False

    def test_create_writes_both_files(self, vault):
        assert vault.vault_file.exists()
        assert vault.config_file.exists()
        assert vault.is_initialised() is True

    def test_master_password_is_never_stored(self, vault):
        """The single most important test in this file."""
        config = vault.config_file.read_text()
        assert MASTER not in config
        assert MASTER.encode() not in vault.vault_file.read_bytes()

    def test_config_contains_salt_and_hash_only(self, vault):
        config = json.loads(vault.config_file.read_text())
        assert set(config) == {"salt", "master_hash", "created_at"}
        assert len(bytes.fromhex(config["salt"])) == SALT_SIZE

    def test_unlock_with_correct_password(self, vault, tmp_path):
        reopened = Vault(vault_dir=tmp_path / "vault")
        assert reopened.unlock_with(MASTER) is True

    def test_unlock_with_wrong_password_fails(self, vault, tmp_path):
        reopened = Vault(vault_dir=tmp_path / "vault")
        assert reopened.unlock_with("not-the-password") is False

    def test_wrong_password_leaves_data_inaccessible(self, vault, tmp_path):
        vault.add_entry("GitHub", "akira", "hunter2")
        reopened = Vault(vault_dir=tmp_path / "vault")
        reopened.unlock_with("wrong")
        assert reopened.data == {}

    def test_data_survives_a_reopen(self, vault, tmp_path):
        vault.add_entry("GitHub", "akira", "hunter2", "github.com", "work account")
        reopened = Vault(vault_dir=tmp_path / "vault")
        reopened.unlock_with(MASTER)
        entry = reopened.get_entry("GitHub")
        assert entry["username"] == "akira"
        assert entry["password"] == "hunter2"
        assert entry["url"] == "github.com"

    def test_corrupted_vault_fails_cleanly(self, vault, tmp_path):
        vault.vault_file.write_bytes(b"this is not encrypted data")
        reopened = Vault(vault_dir=tmp_path / "vault")
        assert reopened.unlock_with(MASTER) is False


# ─────────────────────────────────────────────────────────────
# Entry CRUD
# ─────────────────────────────────────────────────────────────

class TestEntries:

    def test_add_and_get(self, vault):
        vault.add_entry("GitHub", "akira", "hunter2")
        assert vault.get_entry("GitHub")["username"] == "akira"

    def test_get_missing_returns_none(self, vault):
        assert vault.get_entry("Nope") is None

    def test_add_existing_name_overwrites(self, vault):
        vault.add_entry("GitHub", "old", "old-pw")
        vault.add_entry("GitHub", "new", "new-pw")
        assert vault.get_entry("GitHub")["username"] == "new"
        assert len(vault.list_entries()) == 1

    def test_delete_removes_entry(self, vault):
        vault.add_entry("GitHub", "akira", "hunter2")
        assert vault.delete_entry("GitHub") is True
        assert vault.get_entry("GitHub") is None

    def test_delete_missing_returns_false(self, vault):
        assert vault.delete_entry("Nope") is False

    def test_list_is_sorted(self, vault):
        for name in ["Zoom", "Amazon", "Monzo"]:
            vault.add_entry(name, "u", "p")
        assert vault.list_entries() == ["Amazon", "Monzo", "Zoom"]

    def test_entry_records_timestamps(self, vault):
        vault.add_entry("GitHub", "akira", "hunter2")
        entry = vault.get_entry("GitHub")
        assert "created_at" in entry and "updated_at" in entry

    @pytest.mark.parametrize("query,expected", [
        ("git",     ["GitHub"]),      # matches name
        ("GITHUB",  ["GitHub"]),      # case insensitive
        ("monzo.c", ["Monzo"]),       # matches url
        ("akira",   ["GitHub"]),      # matches username
        ("zzz",     []),              # no match
    ])
    def test_search(self, vault, query, expected):
        vault.add_entry("GitHub", "akira", "p", "github.com")
        vault.add_entry("Monzo", "other", "p", "monzo.com")
        assert vault.search_entries(query) == expected

    def test_deletion_persists(self, vault, tmp_path):
        vault.add_entry("GitHub", "akira", "hunter2")
        vault.delete_entry("GitHub")
        reopened = Vault(vault_dir=tmp_path / "vault")
        reopened.unlock_with(MASTER)
        assert reopened.list_entries() == []


# ─────────────────────────────────────────────────────────────
# Password generator
# ─────────────────────────────────────────────────────────────

class TestGenerator:

    @pytest.mark.parametrize("length", [8, 16, 20, 24, 64, 128])
    def test_respects_length(self, length):
        assert len(generate_password(length)) == length

    def test_includes_every_character_class(self):
        for _ in range(25):
            pw = generate_password(20)
            assert any(c.isupper() for c in pw)
            assert any(c.islower() for c in pw)
            assert any(c.isdigit() for c in pw)
            assert any(c in string.punctuation for c in pw)

    def test_without_symbols_is_alphanumeric(self):
        for _ in range(25):
            pw = generate_password(20, use_symbols=False)
            assert all(c.isalnum() for c in pw)

    def test_passwords_are_unique(self):
        """1000 draws from a 94-char alphabet at length 20 should never
        collide. If they do, the RNG is broken."""
        assert len({generate_password(20) for _ in range(1000)}) == 1000


class TestStrength:

    @pytest.mark.parametrize("password,expected", [
        ("abc",                    "Weak"),
        ("password",               "Weak"),
        ("Password1",              "Medium"),
        ("Password123",            "Medium"),
        ("X7@kqP!2mNvRsLd#9WzYtA", "Strong"),
    ])
    def test_labels(self, password, expected):
        assert password_strength(password)[0] == expected

    def test_generated_passwords_always_rate_strong(self):
        for _ in range(25):
            assert password_strength(generate_password(20))[0] == "Strong"

    def test_returns_label_and_icon(self):
        label, icon = password_strength("abc")
        assert isinstance(label, str) and isinstance(icon, str)
