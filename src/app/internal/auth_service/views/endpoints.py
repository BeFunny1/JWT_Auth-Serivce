from fastapi import FastAPI, Depends
from starlette.responses import Response

from app.pkg.jwt.jwt_auth import JWTAuth

from app.internal.utils.error_response import error_response

from app.internal.dependencies import required_api_secret
from app.internal.middlewares import check_api_secret

from app.internal.auth_service.models import AuthenticatedUser, IssuedToken

from app.internal.auth_service.utils.password_hash import hash_password
from app.internal.auth_service.utils.check_token_invalid import check_token_invalid

from app.internal.auth_service.views.in_out_models.update import UpdateTokensInput, UpdateTokensOutput
from app.internal.auth_service.views.in_out_models.auth import AuthInput, AuthOutput
from app.internal.auth_service.views.in_out_models.revoke import RevokeTokenInput

from config.settings import jwt_config


auth_api = FastAPI(dependencies=[Depends(required_api_secret)])
auth_api.middleware("http")(check_api_secret)

jwt_auth = JWTAuth(jwt_config)

@auth_api.post(
    '/register',
    response_model=AuthOutput,
)
# Регистрирует пользователя, создаёт под него access/refresh-токены
async def register(body: AuthInput):
    if await AuthenticatedUser.filter(login=body.login).exists():
        return error_response(error='AuthError', error_description='This login is already occupied')
    
    user = await AuthenticatedUser.create(
        login=body.login,
        password_hash=hash_password(body.password),
    )
    
    access_token = jwt_auth.generate_access_token(subject=user.login)
    refresh_token = jwt_auth.generate_refresh_token(subject=user.login)
    
    await IssuedToken.create(subject=user, jti=jwt_auth.get_jti(refresh_token))
    
    return AuthOutput(access_token=access_token, refresh_token=refresh_token)


@auth_api.post(
    '/login',
    response_model=AuthOutput,
)
# Вход пользователя в систему по логину/паролю, возвращает новые access/refresh-токены, деактивирует старые refresh-токены 
async def login(body: AuthInput):
    if not await AuthenticatedUser.filter(login=body.login).exists():
        return error_response(error='AuthError', error_description='There is no user with this login')
    
    user = await AuthenticatedUser.filter(login=body.login).first()
    await IssuedToken.filter(subject=user).update(revoked=True)
    
    access_token = jwt_auth.generate_access_token(subject=user.login)
    refresh_token = jwt_auth.generate_refresh_token(subject=user.login)
    
    await IssuedToken.create(subject=user, jti=jwt_auth.get_jti(refresh_token))
    
    return AuthOutput(access_token=access_token, refresh_token=refresh_token)


@auth_api.put(
    '/update_tokens',
    response_model=UpdateTokensOutput,
)
# Получает refresh-токен, возвращает пару access/refresh 
async def update_tokens(body: UpdateTokensInput):
    payload, error = check_token_invalid(jwt_auth, body.refresh_token)
    if error:
        return error
    
    if payload['type'] == 'access':
        return error_response(error='InvalidToken', error_description='A refresh-token was passed, but access-token was expected')
    
    user = await AuthenticatedUser.filter(login=payload['sub']).first()
    
    # Если обновленный токен пробуют обновить ещё раз, нужно отменить все выущенные на пользователя токены и вернуть ошибку
    if await IssuedToken.filter(jti=payload['jti'], revoked=True).exists():
        await IssuedToken.filter(subject=user).update(revoked=True)
        return error_response(error='RevokedTokenError', error_description='This token has already been revoked')
    
    await IssuedToken.filter(jti=payload['jti']).update(revoked=True)
    
    access_token = jwt_auth.generate_access_token(subject=user.login)
    refresh_token = jwt_auth.generate_refresh_token(subject=user.login)
    
    await IssuedToken.create(subject=user, jti=jwt_auth.get_jti(refresh_token))
    
    return UpdateTokensOutput(access_token=access_token, refresh_token=refresh_token)


@auth_api.post('/revoke_token')
# Отзывает токен пользователя
async def revoke_token(body: RevokeTokenInput):
    sub = jwt_auth.get_sub(body.refresh_token)
    user = await AuthenticatedUser.filter(login=sub).first()
    await IssuedToken.filter(subject=user).update(revoked=True)
    return Response(status_code=200)
