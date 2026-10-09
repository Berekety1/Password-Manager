import json
import string

import pytest

from vault import Vault, WrongPassword, generate_password

MASTER = "correct horse battery staple"


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "vault.json"


def test_entries_survive_reopening(vault_path):
    v = Vault.create(vault_path, MASTER)
    v.add("github.com", "bereket", "s3cret!")
    reopened = Vault.open(vault_path, MASTER)
    assert reopened.entries == [{"site": "github.com", "username": "bereket", "password": "s3cret!"}]


def test_wrong_password_is_rejected(vault_path):
    Vault.create(vault_path, MASTER)
    with pytest.raises(WrongPassword):
        Vault.open(vault_path, "not the password")


def test_file_reveals_nothing_about_accounts(vault_path):
    v = Vault.create(vault_path, MASTER)
    v.add("github.com", "bereket", "s3cret!")
    raw = vault_path.read_text()
    for secret in ("github.com", "bereket", "s3cret!", MASTER):
        assert secret not in raw


def test_no_password_hash_is_stored(vault_path):
    Vault.create(vault_path, MASTER)
    stored = json.loads(vault_path.read_text())
    assert set(stored) == {"version", "kdf", "data"}


def test_tampering_is_detected(vault_path):
    Vault.create(vault_path, MASTER).add("github.com", "bereket", "s3cret!")
    stored = json.loads(vault_path.read_text())
    token = stored["data"]
    stored["data"] = token[:-5] + ("A" if token[-5] != "A" else "B") + token[-4:]
    vault_path.write_text(json.dumps(stored))
    with pytest.raises(WrongPassword):
        Vault.open(vault_path, MASTER)


def test_cannot_overwrite_an_existing_vault(vault_path):
    Vault.create(vault_path, MASTER)
    with pytest.raises(FileExistsError):
        Vault.create(vault_path, "another password")


def test_find_is_case_insensitive_and_partial(vault_path):
    v = Vault.create(vault_path, MASTER)
    v.add("GitHub.com", "a", "1")
    v.add("gitlab.com", "b", "2")
    v.add("google.com", "c", "3")
    assert [e["site"] for e in v.find("git")] == ["GitHub.com", "gitlab.com"]
    assert v.find("nothing here") == []


def test_delete(vault_path):
    v = Vault.create(vault_path, MASTER)
    v.add("a.com", "a", "1")
    v.add("b.com", "b", "2")
    v.delete(v.find("a.com")[0])
    assert [e["site"] for e in Vault.open(vault_path, MASTER).entries] == ["b.com"]


def test_change_master_password(vault_path):
    v = Vault.create(vault_path, MASTER)
    v.add("a.com", "a", "1")
    old_salt = json.loads(vault_path.read_text())["kdf"]["salt"]
    v.change_master_password("a brand new password")
    assert json.loads(vault_path.read_text())["kdf"]["salt"] != old_salt
    with pytest.raises(WrongPassword):
        Vault.open(vault_path, MASTER)
    assert Vault.open(vault_path, "a brand new password").entries[0]["site"] == "a.com"


def test_generated_passwords():
    for length in (4, 16, 40):
        p = generate_password(length)
        assert len(p) == length
        assert any(c in string.ascii_lowercase for c in p)
        assert any(c in string.ascii_uppercase for c in p)
        assert any(c in string.digits for c in p)
        assert any(c in string.punctuation for c in p)
    assert len({generate_password() for _ in range(100)}) == 100
    with pytest.raises(ValueError):
        generate_password(3)
