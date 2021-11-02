from datetime import timedelta
import os

from app.pkg.jwt.jwt_config import JWTConfig

API_SECRET = os.getenv('API_SECRET')
JWT_SECRET = os.getenv('JWT_SECRET')
HASH_SALT = os.getenv('HASH_SALT')

jwt_config = JWTConfig(
    secret=JWT_SECRET,
    access_token_ttl=timedelta(seconds=60*15),
    refresh_token_ttl=timedelta(seconds=60*60*24*30)
)
