import base64
import json
import os
from crypto_utils import derive_key, generate_salt, encrypt, decrypt

VAULT_FILE = 'vault.json'

# Load vault hoặc tạo mới
def load_vault():
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, 'r') as f:
            return json.load(f)
    else:
        salt = generate_salt()
        vault = {"salt": base64.urlsafe_b64encode(salt).decode(), "passwords": []}
        with open(VAULT_FILE, 'w') as f:
            json.dump(vault, f, indent=4)
        return vault

def save_vault(vault):
    with open(VAULT_FILE, 'w') as f:
        json.dump(vault, f, indent=4)

# ----------------------------

vault = load_vault()
salt = base64.urlsafe_b64decode(vault['salt'])
master_password = input("Enter master password: ")
key = derive_key(master_password, salt)

def add_password():
    site = input("Site: ")
    username = input("Username: ")
    pwd = input("Password: ")
    encrypted_pwd = encrypt(pwd, key)
    vault['passwords'].append({
        "site": site,
        "username": username,
        "password": encrypted_pwd
    })
    save_vault(vault)
    print("Password added!")

def view_passwords():
    for entry in vault['passwords']:
        try:
            decrypted_pwd = decrypt(entry['password'], key)
            print(f"{entry['site']} | {entry['username']} | {decrypted_pwd}")
        except:
            print(f"{entry['site']} | {entry['username']} | [Failed to decrypt]")

while True:
    print("\n1) Add password\n2) View passwords\n0) Exit")
    choice = input("Choice: ")
    if choice == '1':
        add_password()
    elif choice == '2':
        view_passwords()
    elif choice == '0':
        break
    else:
        print("Invalid choice")
