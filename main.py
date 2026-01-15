from pathlib import Path
import json
import hashlib
import os
import base64
from cryptography.fernet import Fernet

vault_path = Path.home() / "password_manager" / "vault.json"
def CURD():
       print('Welcome back to Password Manager')
       print("=== Password Manager ===")
       print("1. Add New Password")
       print("2. View All Passwords")
       print("3. Search Password")
       print("4. Generate Random Passowrd")
       print("5. Delete Password")
       print("9. Logout")
       

def login(data):
    user_master_key = input("ENTER YOUR MASTER KEY>> ")
    salt = data.get('salt',[])
    salt = base64.b64decode(salt)
    user_master_key_hashed = hashlib.sha256(salt+user_master_key.encode()).hexdigest()
    if user_master_key_hashed == data.get('master_password',{}):
        encryption_key = generate_encryption_key(user_master_key,salt)
        return True, encryption_key
    else:
        return False, None
    
def signup():
    user_master_key = input("ENTER YOUR MASTER KEY>> ")
    salt = os.urandom(16)

    hashed_password = hashlib.sha256(salt+user_master_key.encode()).hexdigest()

    data = {
        "master_password" : hashed_password,
        "salt": base64.b64encode(salt).decode(),
        "passwords": []

    }
    write_json(data)
    return True

def write_json(data,path = vault_path):
    with open(path,'w') as f:
        json.dump(data,f)

def read_json(path = vault_path):
    with open(path,'r') as f:
        data = json.load(f)
    return data

def generate_encryption_key(password,salt,iterations=100000, algorithm = 'sha256'):
        password_bytes = password.encode()
        
        key = hashlib.pbkdf2_hmac(
        algorithm,
        password_bytes,
        salt,
        iterations
    )
        return key
    


def encrypt_pass(key,password):
     key = base64.b64encode(key)
     password = password.encode()
     f = Fernet(key)
     e_password = f.encrypt(password)
     return e_password


def decrypt_pass(key,e_password):
     key = base64.b64encode(key)
     f = Fernet(key)
     password = f.decrypt(base64.b64decode(e_password)).decode()
     return password


def addNewPassword(key,data,password, site = '', username=''):
     passwords = data.get('passwords', [])
     new_password = {"Website": site, "Username":username, "Password": base64.b64encode(encrypt_pass(key,password)).decode()}
     passwords.append(new_password)
     data['passwords'] = passwords
     return data # maybe directly write 


     

def view_all_passwords(key, data):
     passwords = data.get('passwords',[])
     for d in passwords:
        print(f'Website: {d.get("Website")}')
        print(f'Username: {d.get("Username")}')
        print(f'Password: {decrypt_pass(key, d.get("Password"))}')
        x = input("DO YOU WANT TO SEE NEXT PASSWORD(y/n): ")
        if x.capitalize() == 'Y':
               continue
        else:
               break

     
     





if vault_path.exists() and vault_path.is_file():
     with open(vault_path, 'r') as f:
          data = json.load(f)
     is_login, key = login(data)
     while is_login:
          CURD()
          x = int(input(">>"))
          if x == 1:
               site = input("site: ")
               username = input("username: ")
               password = input("password: ")
               new_data = addNewPassword(key,data,password,site,username)
               write_json(new_data)
          elif x == 2:
               view_all_passwords(key,data)
else:
     vault_path.parent.mkdir()
     vault_path.write_text("")
     signup()
     with open(vault_path, 'r') as f:
          data = json.load(f)
     is_login, key = login(data)
     while is_login:
          CURD()
          x = int(input(">>"))
          if x == 1:
               site = input("site: ")
               username = input("username: ")
               password = input("password: ")
               new_data = addNewPassword(key,data,password,site,username)
               write_json(new_data)
          elif x == 2:
               view_all_passwords(key,data)
        

          




























