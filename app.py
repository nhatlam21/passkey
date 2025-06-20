from flask import Flask
from flask_session import Session
from flask_mail import Mail
from models import db
from auth import auth_bp
from mail_utils import mail

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# DB config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passkey.db'
db.init_app(app)

# Mail config (Gmail example)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'lamnhatle357@gmail.com'
app.config['MAIL_PASSWORD'] = 'epdb gipo hvej qjxe'
app.config['MAIL_DEFAULT_SENDER'] = 'lamnhatle357@gmail.com'

mail.init_app(app)

# Register Blueprint
app.register_blueprint(auth_bp)

@app.route('/')
def home():
    return 'Welcome! Go to /register or /login'

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
