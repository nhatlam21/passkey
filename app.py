from flask import Flask, render_template, request, redirect, url_for, send_file
import json
import os
import base64
import io
import csv
import secrets
import string

from crypto_utils import derive_key, generate_salt, encrypt, decrypt

app = Flask(__name__)

VAULT_FILE = 'vault.json'

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

vault = load_vault()

def pad_base64(s):
    return s + '=' * (-len(s) % 4)

salt = base64.urlsafe_b64decode(pad_base64(vault['salt']))

# For simplicity: use 1 fixed master password (you can extend with login later)
MASTER_PASSWORD = "master123"  # đổi tùy ý
key = derive_key(MASTER_PASSWORD, salt)

def generate_strong_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

@app.route("/")
def index():
    decrypted_passwords = []
    for entry in vault['passwords']:
        try:
            decrypted_pwd = decrypt(entry['password'], key)
            decrypted_passwords.append({
                "site": entry['site'],
                "username": entry['username'],
                "password": decrypted_pwd
            })
        except:
            decrypted_passwords.append({
                "site": entry['site'],
                "username": entry['username'],
                "password": "[Failed to decrypt]"
            })
    return render_template("index.html", passwords=decrypted_passwords)

@app.route("/add", methods=['GET', 'POST'])
def add():
    if request.method == 'POST':
        site = request.form['site']
        username = request.form['username']
        password = request.form['password']

        encrypted_pwd = encrypt(password, key)
        vault['passwords'].append({
            "site": site,
            "username": username,
            "password": encrypted_pwd
        })
        save_vault(vault)
        return redirect(url_for('index'))
    return render_template("add.html")

@app.route("/generate")
def generate():
    strong_password = generate_strong_password(16)
    return {"password": strong_password}

@app.route("/export")
def export_csv():
    # Tạo CSV trong memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Site', 'Username', 'Password'])
    for entry in vault['passwords']:
        try:
            pwd = decrypt(entry['password'], key)
        except:
            pwd = "[Failed to decrypt]"
        writer.writerow([entry['site'], entry['username'], pwd])
    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name='passwords.csv'
    )

@app.route("/delete/<site>")
def delete(site):
    vault['passwords'] = [e for e in vault['passwords'] if e['site'] != site]
    save_vault(vault)
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(debug=True)
