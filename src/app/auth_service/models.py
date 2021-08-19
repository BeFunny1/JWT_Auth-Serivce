from tortoise.models import Model
from tortoise import fields


class AuthenticatedUser(Model):
    login = fields.TextField(pk=True)
    password_hash = fields.TextField()
    refresh_token = fields.TextField()
    
    def __str__(self) -> str:
        return self.login
