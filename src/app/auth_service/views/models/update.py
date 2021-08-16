from pydantic import BaseModel


class UpdateTokensInput(BaseModel):
    refresh_token: str


class UpdateTokensOutput(BaseModel):
    access_token: str
    refresh_token: str
