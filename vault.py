"""Encrypted password vault.

The vault file is JSON with two parts:

    {"version": 1, "kdf": {"name": "scrypt", "salt": ..., "n": ..., "r": ..., "p": ...},
     "data": "<Fernet token>"}

Everything about the saved accounts (sites, usernames, passwords) lives inside
the Fernet token, so the file reveals nothing but the KDF settings.

* The encryption key is derived from the master password with scrypt, a slow,
  memory-hard function, so every guess an attacker makes is expensive.
* No hash of the master password is stored. A password is correct exactly when
  the token decrypts: Fernet authenticates its data with an HMAC, so a wrong
  key, or a file that has been tampered with, is rejected.
"""
import base64
import hashlib
import json
import os
import secrets
import string
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

VERSION = 1

# scrypt cost (OWASP recommendation): 2**17 * 8 * 128 bytes = 128 MiB of memory per guess
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1


class WrongPassword(Exception):
    """The master password is wrong, or the vault file has been modified."""


def derive_key(master_password, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    raw = hashlib.scrypt(master_password.encode(), salt=salt, n=n, r=r, p=p,
                         maxmem=256 * 1024 * 1024, dklen=32)
    return base64.urlsafe_b64encode(raw)  # Fernet wants a base64-encoded 32-byte key


def generate_password(length=16):
    """Random password with at least one lowercase, uppercase, digit and symbol."""
    if length < 4:
        raise ValueError("length must be at least 4")
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation]
    chars = [secrets.choice(pool) for pool in pools]
    everything = ''.join(pools)
    chars += [secrets.choice(everything) for _ in range(length - len(pools))]
    secrets.SystemRandom().shuffle(chars)
    return ''.join(chars)


class Vault:
    def __init__(self, path, key, kdf, entries):
        self.path = Path(path)
        self._key = key
        self._kdf = kdf
        self.entries = entries  # list of {"site", "username", "password"}

    # ---- creating and opening ------------------------------------------------

    @classmethod
    def create(cls, path, master_password):
        path = Path(path)
        if path.exists():
            raise FileExistsError(f"a vault already exists at {path}")
        kdf = {"name": "scrypt", "salt": base64.b64encode(os.urandom(16)).decode(),
               "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P}
        vault = cls(path, cls._key_for(master_password, kdf), kdf, [])
        vault.save()
        return vault

    @classmethod
    def open(cls, path, master_password):
        with open(path) as f:
            stored = json.load(f)
        if stored.get("version") != VERSION:
            raise ValueError(f"unsupported vault version: {stored.get('version')}")
        kdf = stored["kdf"]
        key = cls._key_for(master_password, kdf)
        try:
            plaintext = Fernet(key).decrypt(stored["data"].encode())
        except InvalidToken:
            raise WrongPassword("wrong master password (or the vault file was modified)") from None
        return cls(path, key, kdf, json.loads(plaintext))

    @staticmethod
    def _key_for(master_password, kdf):
        return derive_key(master_password, base64.b64decode(kdf["salt"]), kdf["n"], kdf["r"], kdf["p"])

    # ---- saving --------------------------------------------------------------

    def save(self):
        token = Fernet(self._key).encrypt(json.dumps(self.entries).encode()).decode()
        content = json.dumps({"version": VERSION, "kdf": self._kdf, "data": token}, indent=2)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Write to a temporary file and swap it in, so a crash mid-write
        # can never leave a half-written (and unreadable) vault behind.
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".vault-")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
            os.chmod(tmp, 0o600)  # owner read/write only (ignored on Windows)
            os.replace(tmp, self.path)
        except BaseException:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise

    def change_master_password(self, new_password):
        """Re-encrypt everything under a new password and a fresh salt."""
        self._kdf = {**self._kdf, "salt": base64.b64encode(os.urandom(16)).decode()}
        self._key = self._key_for(new_password, self._kdf)
        self.save()

    # ---- entries -------------------------------------------------------------

    def add(self, site, username, password):
        self.entries.append({"site": site, "username": username, "password": password})
        self.save()

    def find(self, query):
        """Entries whose site contains `query`, ignoring case."""
        query = query.lower()
        return [e for e in self.entries if query in e["site"].lower()]

    def delete(self, entry):
        self.entries.remove(entry)
        self.save()
