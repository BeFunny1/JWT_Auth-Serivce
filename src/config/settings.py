import os

from pydantic import BaseModel


ACCESS_TOKEN_TTL = 15
REFRESH_TOKEN_TTL = 12 * 24 * 60

API_SECRET = os.environ['API_SECRET']
# JWT_SECRET = os.environ['JWT_SECRET']
HASH_SALT = os.environ['HASH_SALT']


class Settings(BaseModel):
    authjwt_secret_key: str = os.environ['JWT_SECRET']
