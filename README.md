# Password Manager

A command-line password manager in Python. All your accounts are kept in a single encrypted vault file that can only be opened with your master password.

```
=== Password Manager ===
1. Add a password
2. List saved accounts
3. Show a password
4. Generate a random password
5. Delete a password
6. Change master password
0. Quit
> 3
Website (or part of it): git
  1. github.com  (bereket)
Number to show (Enter to cancel): 1
  Website:  github.com
  Username: bereket
  Password: myGHpass!
```

## Features

- Add, list, search, show and delete saved passwords
- Generate strong random passwords (at least one lowercase letter, uppercase letter, digit and symbol)
- Change the master password, which re-encrypts the whole vault
- The master password is never shown on screen while you type it
- Three wrong attempts and the program exits

## Run it

```bash
pip install -r requirements.txt
python main.py                          # vault is stored in ~/.password_manager/vault.json
python main.py --vault path/to/vault.json
```

The first run asks you to choose a master password and creates the vault.

## How the vault is protected

This is what `vault.json` looks like on disk:

```json
{
  "version": 1,
  "kdf": {"name": "scrypt", "salt": "dE47QTOOadG4HyC0OjHJTg==", "n": 131072, "r": 8, "p": 1},
  "data": "gAAAAABqyLQizziR4Mm6KrygDFxxMrnydnvb..."
}
```

**1. The key comes from the master password via scrypt.**

```
key = scrypt(master_password, salt, N=2^17, r=8, p=1)
```

scrypt is deliberately slow and memory-hungry: each attempt takes about 0.3 s and 128 MiB of memory (the OWASP-recommended setting). Unlocking your own vault takes a fraction of a second, but an attacker who steals the file can only test a few guesses per second per CPU core, and GPUs don't help much because of the memory requirement. A random 16-byte salt makes every vault's key different, even with the same password.

**2. The whole vault is encrypted with Fernet.**

[Fernet](https://cryptography.io/en/latest/fernet/) (from the `cryptography` library) uses AES-128-CBC for encryption and HMAC-SHA256 for authentication. Site names and usernames are encrypted together with the passwords, so the file reveals nothing about which accounts you have.

**3. No password hash is stored.**

The program never stores a hash of the master password. A password is correct exactly when the vault decrypts and its HMAC checks out. A stored hash would give an attacker a shortcut: they could test guesses against the hash instead of going through scrypt. If the file has been modified, the HMAC check fails and the vault refuses to open.

**4. Saving can't corrupt the vault.**

Changes are written to a temporary file that then replaces the vault in one step, so a crash halfway through a save leaves the old vault intact. On Linux and macOS the file is only readable by its owner.

### Limitations

This is a learning project and has not been security-audited, so use a mainstream password manager for your real accounts. In particular:

- While the vault is unlocked, passwords sit in memory as ordinary Python strings, and "Show" prints them in the terminal.
- A weak master password is still weak: scrypt slows guessing down but can't make "password123" safe.
- Anyone who can run code on your computer (for example, a keylogger) can steal the master password.

## Tests

```bash
python -m pytest
```

The tests check, among other things, that entries survive reopening the vault, that wrong passwords and tampered files are rejected, that the file on disk contains no site names, usernames or passwords, and that changing the master password locks out the old one.

## Project structure

```
vault.py             encryption, key derivation and storage (the Vault class)
main.py              the menu you interact with
tests/test_vault.py  tests
```
