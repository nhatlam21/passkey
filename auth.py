from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, send_file
from models import db, User, Password, Tag, AuditLog
import pyotp
import random
from mail_utils import send_otp_email
from crypto_utils import derive_key, generate_salt
import csv
import io

auth_bp = Blueprint('auth', __name__)

# ------------------------------
# Register
# ------------------------------
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
            return redirect(url_for('auth.register'))

        otp_secret = pyotp.random_base32()
        salt = generate_salt()
        password_hash = derive_key(password, salt).decode()

        user = User(email=email, password=password_hash, salt=salt, otp_secret=otp_secret)
        db.session.add(user)
        db.session.commit()
        flash('Registered successfully! Please login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('register.html')

# ------------------------------
# Login
# ------------------------------
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('User not found.', 'danger')
            return redirect(url_for('auth.login'))

        password_hash = derive_key(password, user.salt).decode()
        if user.password != password_hash:
            flash('Incorrect password.', 'danger')
            return redirect(url_for('auth.login'))

        email_otp = random.randint(100000, 999999)
        session['email_otp'] = str(email_otp)
        session['login_user'] = user.id

        send_otp_email(current_app, user.email, email_otp)
        flash('Email OTP sent!', 'info')
        return redirect(url_for('auth.verify_otp'))

    return render_template('login.html')

# ------------------------------
# Verify OTP
# ------------------------------
@auth_bp.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        email_otp = request.form['email_otp']
        user = User.query.get(session['login_user'])

        if email_otp != session.get('email_otp'):
            flash('Invalid email OTP.', 'danger')
            return redirect(url_for('auth.verify_otp'))

        session['user_id'] = user.id
        session.pop('email_otp', None)
        session.pop('login_user', None)
        flash('2FA Verified! Logged in.', 'success')
        return redirect(url_for('auth.dashboard'))

    return render_template('verify_otp.html')

# ------------------------------
# Dashboard
# ------------------------------
@auth_bp.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    passwords = Password.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', passwords=passwords)

# ------------------------------
# Add Password
# ------------------------------
@auth_bp.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    tags = Tag.query.filter_by(user_id=session['user_id']).all()

    if request.method == 'POST':
        site = request.form['site']
        username = request.form['username']
        password = request.form['password']
        tag_id = request.form.get('tag_id') or None

        new_pass = Password(site=site, username=username, password=password, user_id=session['user_id'], tag_id=tag_id)
        db.session.add(new_pass)
        db.session.commit()
        flash('Password added successfully!', 'success')
        return redirect(url_for('auth.dashboard'))

    return render_template('add_password.html', tags=tags)

# ------------------------------
# Edit Password
# ------------------------------
@auth_bp.route('/edit_password/<int:pass_id>', methods=['GET', 'POST'])
def edit_password(pass_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    password = Password.query.get_or_404(pass_id)
    if password.user_id != session['user_id']:
        flash('Unauthorized!', 'danger')
        return redirect(url_for('auth.dashboard'))

    tags = Tag.query.filter_by(user_id=session['user_id']).all()

    if request.method == 'POST':
        password.site = request.form['site']
        password.username = request.form['username']
        password.password = request.form['password']
        tag_id = request.form.get('tag_id')
        password.tag_id = tag_id if tag_id else None

        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('auth.dashboard'))

    return render_template('edit_password.html', password=password, tags=tags)

# ------------------------------
# Delete Password
# ------------------------------
@auth_bp.route('/delete_password/<int:pass_id>')
def delete_password(pass_id):
    password = Password.query.get_or_404(pass_id)
    if password.user_id != session['user_id']:
        flash('Unauthorized!', 'danger')
        return redirect(url_for('auth.dashboard'))
    db.session.delete(password)
    db.session.commit()
    flash('Password deleted!', 'success')
    return redirect(url_for('auth.dashboard'))

# ------------------------------
# Export CSV
# ------------------------------
@auth_bp.route('/export_csv')
def export_csv():
    passwords = Password.query.filter_by(user_id=session['user_id']).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Site', 'Username', 'Password', 'Tag'])
    for p in passwords:
        writer.writerow([p.site, p.username, p.password, p.tag.name if p.tag else ''])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='passwords.csv')

# ------------------------------
# Manage Tags (CRUD)
# ------------------------------
@auth_bp.route('/tags', methods=['GET', 'POST'])
def manage_tags():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        name = request.form['name']
        tag = Tag(name=name, user_id=session['user_id'])
        db.session.add(tag)
        db.session.commit()
        flash('Tag added!', 'success')
        return redirect(url_for('auth.manage_tags'))

    tags = Tag.query.filter_by(user_id=session['user_id']).all()
    return render_template('tags.html', tags=tags)

@auth_bp.route('/delete_tag/<int:tag_id>')
def delete_tag(tag_id):
    tag = Tag.query.get_or_404(tag_id)
    if tag.user_id != session['user_id']:
        flash('Unauthorized!', 'danger')
        return redirect(url_for('auth.manage_tags'))
    db.session.delete(tag)
    db.session.commit()
    flash('Tag deleted!', 'success')
    return redirect(url_for('auth.manage_tags'))

@auth_bp.route('/audit_log')
def audit_log():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    logs = AuditLog.query.filter_by(user_id=session['user_id']).order_by(AuditLog.timestamp.desc()).all()
    return render_template('audit_log.html', logs=logs)

# ------------------------------
# Profile
# ------------------------------
@auth_bp.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        new_password = request.form['new_password']
        if new_password:
            salt = generate_salt()
            password_hash = derive_key(new_password, salt).decode()
            user.password = password_hash
            user.salt = salt
            db.session.commit()
            flash('Password updated!', 'success')
            return redirect(url_for('auth.profile'))

    return render_template('profile.html', user=user)



# ------------------------------
# Logout
# ------------------------------
@auth_bp.route('/logout')
def logout():
    session.clear()
    flash('Logged out!', 'info')
    return redirect(url_for('auth.login'))
