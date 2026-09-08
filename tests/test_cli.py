"""
Tests for the interactive CLI layer.

The command functions read from input() and getpass(), so each test
monkeypatches those with a scripted list of responses. This covers the
branches that the pure-logic tests in test_vault.py cannot reach.
"""

import pytest

import vault as v
from vault import Vault

MASTER = "correct-horse-battery-staple"


@pytest.fixture
def vlt(tmp_path):
    obj = Vault(vault_dir=tmp_path / "vault")
    obj.create(MASTER)
    return obj


@pytest.fixture
def answers(monkeypatch):
    """Script a sequence of input() responses."""
    def _script(responses, passwords=None):
        queue = list(responses)
        pw_queue = list(passwords or [])
        monkeypatch.setattr("builtins.input", lambda *a, **k: queue.pop(0))
        monkeypatch.setattr(v.getpass, "getpass", lambda *a, **k: pw_queue.pop(0))
    return _script


# ─────────────────────────────────────────────────────────────

class TestAddCommand:

    def test_adds_entry_with_manual_password(self, vlt, answers, capsys):
        answers(["GitHub", "akira", "m", "github.com", "work account"],
                passwords=["hunter2"])
        v.cmd_add(vlt)
        entry = vlt.get_entry("GitHub")
        assert entry["username"] == "akira"
        assert entry["password"] == "hunter2"
        assert entry["url"] == "github.com"

    def test_adds_entry_with_generated_password(self, vlt, answers):
        answers(["Monzo", "akira", "g", "24", "monzo.com", ""])
        v.cmd_add(vlt)
        entry = vlt.get_entry("Monzo")
        assert len(entry["password"]) == 24

    def test_generator_falls_back_to_default_length_on_bad_input(self, vlt, answers):
        answers(["Amazon", "akira", "g", "not-a-number", "", ""])
        v.cmd_add(vlt)
        assert len(vlt.get_entry("Amazon")["password"]) == 20

    def test_rejects_empty_name(self, vlt, answers, capsys):
        answers([""])
        v.cmd_add(vlt)
        assert "cannot be empty" in capsys.readouterr().out
        assert vlt.list_entries() == []


class TestGetCommand:

    def test_prints_entry(self, vlt, answers, capsys):
        vlt.add_entry("GitHub", "akira", "hunter2", "github.com", "note here")
        answers(["GitHub"])
        v.cmd_get(vlt)
        out = capsys.readouterr().out
        assert "akira" in out and "hunter2" in out and "note here" in out

    def test_reports_missing_entry(self, vlt, answers, capsys):
        answers(["Nope"])
        v.cmd_get(vlt)
        assert "No entry found" in capsys.readouterr().out


class TestListCommand:

    def test_reports_empty_vault(self, vlt, capsys):
        v.cmd_list(vlt)
        assert "empty" in capsys.readouterr().out

    def test_lists_all_entries(self, vlt, capsys):
        vlt.add_entry("GitHub", "a", "p")
        vlt.add_entry("Monzo", "b", "p")
        v.cmd_list(vlt)
        out = capsys.readouterr().out
        assert "GitHub" in out and "Monzo" in out


class TestSearchCommand:

    def test_finds_match(self, vlt, answers, capsys):
        vlt.add_entry("GitHub", "akira", "p")
        answers(["git"])
        v.cmd_search(vlt)
        assert "GitHub" in capsys.readouterr().out

    def test_reports_no_match(self, vlt, answers, capsys):
        answers(["zzz"])
        v.cmd_search(vlt)
        assert "No entries match" in capsys.readouterr().out


class TestDeleteCommand:

    def test_deletes_on_confirmation(self, vlt, answers):
        vlt.add_entry("GitHub", "a", "p")
        answers(["GitHub", "yes"])
        v.cmd_delete(vlt)
        assert vlt.get_entry("GitHub") is None

    def test_keeps_entry_when_not_confirmed(self, vlt, answers, capsys):
        vlt.add_entry("GitHub", "a", "p")
        answers(["GitHub", "no"])
        v.cmd_delete(vlt)
        assert vlt.get_entry("GitHub") is not None
        assert "cancelled" in capsys.readouterr().out

    def test_reports_missing_entry(self, vlt, answers, capsys):
        answers(["Nope"])
        v.cmd_delete(vlt)
        assert "No entry found" in capsys.readouterr().out


class TestGenerateCommand:

    def test_prints_a_password_of_requested_length(self, answers, capsys):
        answers(["32", "y"])
        v.cmd_generate()
        assert "32 characters" in capsys.readouterr().out

    def test_can_exclude_symbols(self, answers, capsys):
        answers(["20", "n"])
        v.cmd_generate()
        assert "Strength" in capsys.readouterr().out
