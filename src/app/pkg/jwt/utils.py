import uuid

from datetime import datetime, timedelta
from calendar import timegm

from app.pkg.jwt.jwt_config import JWTConfig


def generate_secret():
    return str(uuid.uuid4().hex)


def generate_plug_config(
    secret=generate_secret(),
    algorithm='HS256',
    access_token_ttl=timedelta(seconds=25),
    refresh_token_ttl=timedelta(seconds=50)
):
    return JWTConfig(secret, algorithm, access_token_ttl, refresh_token_ttl)


def convert_to_timestamp(datetime: datetime):
        return timegm(datetime.utctimetuple())
