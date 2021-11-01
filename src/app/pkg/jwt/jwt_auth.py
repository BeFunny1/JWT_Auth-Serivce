
import jwt
import uuid

from typing import Any, Dict
from datetime import datetime, timedelta, timezone

from app.pkg.jwt.jwt_config import JWTConfig
from app.pkg.jwt.utils import convert_to_timestamp


class JWTAuth:
    def __init__(self, config: JWTConfig):
        self._config: JWTConfig = config

    def generate_access_token(self, subject, payload: Dict[str, Any]={}):
        return self.__sign_token(
            type='access', subject=subject, payload=payload, ttl=self._config.access_token_ttl
        )
    
    def generate_refresh_token(self, subject, payload: Dict[str, Any]={}):
        return self.__sign_token(
            type='refresh', subject=subject, payload=payload, ttl=self._config.refresh_token_ttl
        )
    
    def __sign_token(self,
        type: str, subject: str,
        payload: Dict[str, Any]={},
        ttl: timedelta=None
    ):
        current_timestamp = convert_to_timestamp(datetime.now(tz=timezone.utc))
        
        data = dict(
            iss='befunny@auth_service',
            sub=subject,
            type=type,
            jti=self.__generate_jti(),
            iat=current_timestamp,
            nbf=payload['nbf'] if payload.get('nbf') else current_timestamp
        )
        data.update(dict(exp=data['nbf'] + ttl.seconds)) if ttl else None
        payload.update(data)
        return jwt.encode(payload, self._config.secret, algorithm=self._config.algorithm)

    @staticmethod
    def __generate_jti() -> str:
        return str(uuid.uuid4())

    def verify_token(self, token):
        return jwt.decode(token, self._config.secret, algorithms=[self._config.algorithm])
