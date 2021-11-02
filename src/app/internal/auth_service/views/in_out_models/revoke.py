from pydantic import BaseModel


class RevokeTokenInput(BaseModel):
    refresh_token: str
