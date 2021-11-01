import time
import jwt
import pytest

from datetime import datetime, timedelta, timezone
from jwt.exceptions import ExpiredSignatureError, ImmatureSignatureError

from app.pkg.jwt.jwt_auth import JWTAuth
from app.pkg.jwt.utils import convert_to_timestamp, generate_plug_config


def test_can_generate_tokens():
    auth = JWTAuth(generate_plug_config())
    assert auth.generate_access_token('me')
    assert auth.generate_refresh_token('me')


def test_can_generate_tokens__different_algorithms():
    auth = JWTAuth(generate_plug_config())
    assert auth.generate_access_token('me')
    assert auth.generate_refresh_token('me')



@pytest.mark.parametrize("payload", [
    {'cat': 'Floppa'},
    {'cat': 'Floppa', 'dog': 'Joppa'},
    ]
)
def test_generate_token__with_user_info_in_payload(payload):
    config = generate_plug_config(access_token_ttl=None)
    auth = JWTAuth(config)
    encoded_tokens = auth.generate_access_token('me', payload.copy()), auth.generate_refresh_token('me', payload.copy())
    for encoded_token in encoded_tokens:
        decoded_token = jwt.decode(encoded_token, options={"verify_signature": False})
        for key in payload:
            assert payload[key] == decoded_token[key]


@pytest.mark.parametrize("payload,specified", [
    ({}, False),
    ({'nbf': 100}, True),
    ]
)
def test_generate_token__nbf_specified(payload, specified):
    auth = JWTAuth(generate_plug_config(access_token_ttl=None))
    encoded_tokens = auth.generate_access_token('me', payload.copy()), auth.generate_refresh_token('me', payload.copy())
    for encoded_token in encoded_tokens:
        decoded_token = jwt.decode(encoded_token, options={"verify_signature": False})
        assert (decoded_token['nbf'] != decoded_token['iat']) == specified


@pytest.mark.parametrize("key,can_overwrite", [
    ('iss', False),
    ('exp', False),
    ('jti', False),
    ('iat', False),
    ('sub', False),
    ('aud', True),
    ]
)
def test_generate_token__user_overwrite_special_keys(key, can_overwrite):
    auth = JWTAuth(generate_plug_config())
    payload={key: 'some_incorrect_data'}
    encoded_tokens = auth.generate_access_token('me', payload.copy()), auth.generate_refresh_token('me', payload.copy())
    for encoded_token in encoded_tokens:
        decoded_token = jwt.decode(encoded_token, options={"verify_signature": False})
        assert (payload[key] == decoded_token[key]) == can_overwrite


@pytest.mark.parametrize("config", [
    generate_plug_config(access_token_ttl=None, refresh_token_ttl=None),
    generate_plug_config(),
    ]
)
def test_verify_token(config):
    auth = JWTAuth(config)
    access_token = auth.generate_access_token('me')
    refresh_token = auth.generate_refresh_token('me')
    assert auth.verify_token(access_token)
    assert auth.verify_token(refresh_token)


def test_verify_token__expired():
    config = generate_plug_config(
        access_token_ttl=timedelta(seconds=1),
        refresh_token_ttl=timedelta(seconds=1)
    )
    auth = JWTAuth(config)
    access_token = auth.generate_access_token('me')
    refresh_token = auth.generate_refresh_token('me')
    time.sleep(2)
    
    with pytest.raises(ExpiredSignatureError):
        assert auth.verify_token(access_token)
        assert auth.verify_token(refresh_token)


def test_verify_token__nbf_has_not_come_yet():
    config = generate_plug_config(
        access_token_ttl=timedelta(seconds=1),
        refresh_token_ttl=timedelta(seconds=1)
    )
    auth = JWTAuth(config)
    
    payload = {'nbf': convert_to_timestamp(datetime.now(tz=timezone.utc)) + 1000}
    
    access_token = auth.generate_access_token('me', payload)
    refresh_token = auth.generate_refresh_token('me', payload)
    
    with pytest.raises(ImmatureSignatureError):
        assert auth.verify_token(access_token)
        assert auth.verify_token(refresh_token)
