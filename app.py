from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_session import Session
import json
import os
import base64
import io
import csv
import secrets
import string

from crypto_utils import derive_key, generate_salt, encrypt, decrypt

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Bất kỳ chuỗi ngẫu nhiên
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

VAULT_FILE = 'vault.json'
MASTER_PASSWORD = "Nhatlam21072003$"

# Load or create vault
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
print(f"Salt value: {vault['salt']}")

def pad_base64(s):
    return s + '=' * (-len(s) % 4)

salt = base64.urlsafe_b64decode(pad_base64(vault['salt']))

# --- Routes ---

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        pwd = request.form['password']
        if pwd == MASTER_PASSWORD:
            key = derive_key(pwd, salt)
            session['key'] = key.decode()
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Wrong password!', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'key' not in session:
        return redirect(url_for('login'))

    key = session['key'].encode()
    decrypted_passwords = []
    for entry in vault['passwords']:
        try:
            pwd = decrypt(entry['password'], key)
        except:
            pwd = "[Failed to decrypt]"
        decrypted_passwords.append({
            "site": entry['site'],
            "username": entry['username'],
            "password": pwd
        })
    return render_template('dashboard.html', passwords=decrypted_passwords)

@app.route('/add', methods=['GET', 'POST'])
def add():
    if 'key' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        site = request.form['site']
        username = request.form['username']
        password = request.form['password']
        key = session['key'].encode()
        encrypted_pwd = encrypt(password, key)
        vault['passwords'].append({
            "site": site,
            "username": username,
            "password": encrypted_pwd
        })
        save_vault(vault)
        flash('Password added!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add.html')

@app.route('/generate_password')
def generate_password():
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(chars) for _ in range(16))
    return {"password": password}

@app.route('/export')
def export_csv():
    if 'key' not in session:
        return redirect(url_for('login'))

    key = session['key'].encode()
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
        download_name='vault_export.csv'
    )

@app.route('/delete/<site>')
def delete(site):
    if 'key' not in session:
        return redirect(url_for('login'))

    vault['passwords'] = [e for e in vault['passwords'] if e['site'] != site]
    save_vault(vault)
    flash(f"Deleted entry for {site}", 'info')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out!', 'info')
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
