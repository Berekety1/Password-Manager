"""Command-line password manager.

    python main.py                      # vault at ~/.password_manager/vault.json
    python main.py --vault my_vault.json
"""
import argparse
import os
from getpass import getpass
from pathlib import Path

from vault import Vault, WrongPassword, generate_password

DEFAULT_VAULT = Path(os.environ.get("PASSWORD_MANAGER_VAULT",
                                    Path.home() / ".password_manager" / "vault.json"))
MAX_ATTEMPTS = 3

MENU = """
=== Password Manager ===
1. Add a password
2. List saved accounts
3. Show a password
4. Generate a random password
5. Delete a password
6. Change master password
0. Quit"""


def ask(prompt):
    return input(prompt).strip()


def new_master_password():
    while True:
        password = getpass("Choose a master password: ")
        if len(password) < 8:
            print("Use at least 8 characters.")
        elif password != getpass("Repeat it: "):
            print("The passwords did not match, try again.")
        else:
            return password


def unlock(path):
    if not path.exists():
        print(f"No vault found at {path}. Let's create one.")
        vault = Vault.create(path, new_master_password())
        print("Vault created.")
        return vault
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return Vault.open(path, getpass("Master password: "))
        except WrongPassword:
            print(f"Wrong master password ({attempt}/{MAX_ATTEMPTS}).")
    return None


def choose(entries, action):
    """Let the user pick one entry from a numbered list."""
    for i, e in enumerate(entries, 1):
        print(f"  {i}. {e['site']}  ({e['username']})")
    choice = ask(f"Number to {action} (Enter to cancel): ")
    if choice.isdigit() and 1 <= int(choice) <= len(entries):
        return entries[int(choice) - 1]
    return None


def search(vault, action):
    matches = vault.find(ask("Website (or part of it): "))
    if not matches:
        print("No matching accounts.")
        return None
    return choose(matches, action)


def add(vault):
    site = ask("Website: ")
    if not site:
        print("A website is required.")
        return
    username = ask("Username: ")
    password = getpass("Password (leave empty to generate one): ")
    if not password:
        password = generate_password()
        print(f"Generated password: {password}")
    vault.add(site, username, password)
    print(f"Saved {site}.")


def list_accounts(vault):
    if not vault.entries:
        print("The vault is empty.")
    for e in sorted(vault.entries, key=lambda e: e["site"].lower()):
        print(f"  {e['site']}  ({e['username']})")


def show(vault):
    entry = search(vault, "show")
    if entry:
        print(f"  Website:  {entry['site']}\n  Username: {entry['username']}\n  Password: {entry['password']}")


def generate():
    length = ask("Length (default 16): ")
    try:
        print(generate_password(int(length) if length else 16))
    except ValueError:
        print("Enter a whole number of at least 4.")


def delete(vault):
    entry = search(vault, "delete")
    if entry and ask(f"Delete {entry['site']} ({entry['username']})? (y/n): ").lower() == "y":
        vault.delete(entry)
        print("Deleted.")


def change_master(vault):
    vault.change_master_password(new_master_password())
    print("Master password changed.")


def main():
    parser = argparse.ArgumentParser(description="Command-line password manager")
    parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT, help="path to the vault file")
    args = parser.parse_args()

    vault = unlock(args.vault)
    if vault is None:
        print("Too many wrong attempts.")
        return

    actions = {"1": add, "2": list_accounts, "3": show, "5": delete, "6": change_master}
    while True:
        print(MENU)
        choice = ask("> ")
        if choice == "0":
            print("Bye!")
            break
        elif choice == "4":
            generate()
        elif choice in actions:
            actions[choice](vault)
        else:
            print("Please choose one of the numbers above.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nBye!")
