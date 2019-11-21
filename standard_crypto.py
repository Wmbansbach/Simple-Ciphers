import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import msgbox

class Encryption:
    def __init__(self):
        pass
    def AES(self, mode, msg, pw):
        salt = b'011358'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(pw))
        f = Fernet(key)
        if mode:
            token = f.encrypt(msg)
        else:
            token = f.decrypt(msg)
        return token.decode('ascii')

class Hashes:
    def __init__(self):
        pass
    def setHash(self, msg, alg):
        hasher = eval("hashlib." + alg + "()")
        hasher.update(bytes(msg, "utf-8"))
        msgbox.App(alg, hasher.hexdigest())


