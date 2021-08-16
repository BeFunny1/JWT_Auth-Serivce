from pydantic import BaseModel


class DeregisterInput(BaseModel):
    login: str
    password: str


class DeregisterOutput(BaseModel):
    success: bool
