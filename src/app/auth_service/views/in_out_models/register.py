from pydantic import BaseModel


class RegisterInput(BaseModel):
    login: str
    password: str


class RegisterOutput(BaseModel):
    access_token: str
    refresh_token: str
