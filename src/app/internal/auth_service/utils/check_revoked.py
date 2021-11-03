from app.internal.auth_service.models import IssuedToken


async def check_revoked(jti):
    return await IssuedToken.filter(jti=jti, revoked=True).exists()
