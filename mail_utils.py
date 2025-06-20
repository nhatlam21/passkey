from flask_mail import Mail, Message

mail = Mail()

def send_otp_email(app, to_email, otp):
    with app.app_context():
        msg = Message("Your Login OTP",
                      recipients=[to_email],
                      body=f"Your OTP is: {otp}")
        mail.send(msg)
