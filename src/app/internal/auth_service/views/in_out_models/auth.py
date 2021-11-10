from pydantic import BaseModel


class AuthInput(BaseModel):
    login: str
    password: str


class AuthOutput(BaseModel):
    access_token: str
    refresh_token: str
