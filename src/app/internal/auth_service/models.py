from tortoise.models import Model
from tortoise import fields


class AuthenticatedUser(Model):
    login = fields.TextField(pk=True)
    password_hash = fields.TextField()
    
    def __str__(self) -> str:
        return self.login


class IssuedToken(Model):
    subject = fields.ForeignKeyField('models.AuthenticatedUser', related_name='refresh_tokens')
    jti = fields.CharField(max_length=255, pk=True)
    device_id = fields.CharField(max_length=255)
    revoked = fields.BooleanField(default=False)
    expired_time = fields.IntField()

    def __str__(self) -> str:
        return f'{self.jti}'
