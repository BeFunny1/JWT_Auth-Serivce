import hashlib

from config.settings import HASH_SALT


def hash_password(user_password):
    return hashlib.pbkdf2_hmac('sha256', user_password.encode(), HASH_SALT.encode(), 100000).hex()