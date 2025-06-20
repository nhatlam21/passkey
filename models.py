from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    otp_secret = db.Column(db.String(32), nullable=False)

class Password(db.Model):
    __tablename__ = 'password'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    site = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(256), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('passwords', lazy=True))
class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, server_default=db.func.now())

    user = db.relationship('User', backref='audit_logs')


if __name__ != "__main__":
    # Định nghĩa các model ở đây
    class Password(db.Model):
        __tablename__ = 'password'
        __table_args__ = {'extend_existing': True}
        # ...fields...
        pass

