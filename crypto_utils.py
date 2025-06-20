import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Tạo key AES từ master password + salt.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def generate_salt() -> bytes:
    """
    Sinh salt random (16 bytes).
    """
    return os.urandom(16)

def encrypt(message: str, key: bytes) -> str:
    """
    Mã hoá message bằng key AES.
    """
    f = Fernet(key)
    return f.encrypt(message.encode()).decode()

def decrypt(token: str, key: bytes) -> str:
    """
    Giải mã ciphertext bằng key AES.
    """
    f = Fernet(key)
    return f.decrypt(token.encode()).decode()
