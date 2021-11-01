from datetime import timedelta


class JWTConfig:
    def __init__(
        self, 
        secret: str, algorithm: str = 'HS256',
        access_token_ttl: timedelta = None, refresh_token_ttl: timedelta = None,
        ):
        self.secret = secret
        self.algorithm = algorithm
        self.access_token_ttl = access_token_ttl
        self.refresh_token_ttl = refresh_token_ttl
