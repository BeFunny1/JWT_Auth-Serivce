import uuid

from fastapi import FastAPI, Depends, Header
from fastapi.responses import JSONResponse

from app.pkg.jwt.jwt_auth import JWTAuth

from app.internal.utils.error_response import error_response

from app.internal.dependencies import required_api_secret
from app.internal.middlewares import check_api_secret

from app.internal.auth_service.models import AuthenticatedUser, IssuedToken

from app.internal.auth_service.utils.password_hash import hash_password
from app.internal.auth_service.utils.try_decode_token import try_decode_token
from app.internal.auth_service.utils.token_type_enum import TokenType
from app.internal.auth_service.utils.check_revoked import check_revoked
from app.internal.utils.try_to_get_clear_token import try_to_get_clear_token

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
    
    device_id = __generate_device_id()
    
    access_token = jwt_auth.generate_access_token(subject=user.login, payload={'device_id': device_id})
    refresh_token = jwt_auth.generate_refresh_token(subject=user.login, payload={'device_id': device_id})
    
    await IssuedToken.create(subject=user, jti=jwt_auth.get_jti(access_token), device_id=device_id)
    await IssuedToken.create(subject=user, jti=jwt_auth.get_jti(refresh_token), device_id=device_id)
    
    return AuthOutput(access_token=access_token, refresh_token=refresh_token)


@auth_api.post(
    '/login',
    response_model=AuthOutput,
)
# Вход пользователя в систему по логину/паролю, возвращает access/refresh-токены для этого устройства
async def login(body: AuthInput):
    if not await AuthenticatedUser.filter(login=body.login).exists():
        return error_response(error='AuthError', error_description='There is no user with this login')
    
    user = await AuthenticatedUser.filter(login=body.login).first()
    # await IssuedToken.filter(subject=user, device_id=device_id).update(revoked=True)
    
    device_id = __generate_device_id()
    
    access_token = jwt_auth.generate_access_token(subject=user.login, payload={'device_id': device_id})
    refresh_token = jwt_auth.generate_refresh_token(subject=user.login, payload={'device_id': device_id})
    
    await IssuedToken.create(subject=user, jti=jwt_auth.get_jti(access_token), device_id=device_id)
    await IssuedToken.create(subject=user, jti=jwt_auth.get_jti(refresh_token), device_id=device_id)
    
    return AuthOutput(access_token=access_token, refresh_token=refresh_token)


@auth_api.post('/logout')
# Выход пользователя из сети; обнуляет все токены на этот device_id
async def logout(authentication: str = Header(...)):
    clear_token, error = try_to_get_clear_token(authentication)
    if error:
        return error
    
    payload, error = try_decode_token(jwt_auth, clear_token)
    if error:
        return error
    
    if payload['type'] != TokenType.ACCESS:
        return error_response(error='InvalidToken', error_description='A access-token was passed, but refresh-token was expected')
    
    device_id = payload['device_id']
    await IssuedToken.filter(device_id=device_id).update(revoked=True)
    
    return JSONResponse(status_code=200, content={'message': 'Success'})


@auth_api.put(
    '/update_tokens',
    response_model=UpdateTokensOutput,
)
# Получает refresh-токен, возвращает пару access/refresh, ануллируя все выпущенные на устройство пользователя токены
async def update_tokens(body: UpdateTokensInput):
    payload, error = try_decode_token(jwt_auth, body.refresh_token)
    if error:
        return error
    
    if payload['type'] != TokenType.REFRESH:
        return error_response(error='InvalidToken', error_description='A refresh-token was passed, but access-token was expected')
    
    user = await AuthenticatedUser.filter(login=payload['sub']).first()
    
    # Если обновленный токен пробуют обновить ещё раз, нужно отменить все выущенные на пользователя токены и вернуть ошибку
    if await check_revoked(payload['jti']):
        await IssuedToken.filter(subject=user).update(revoked=True)
        return error_response(error='RevokedTokenError', error_description='This token has already been revoked')
    
    device_id = jwt_auth.get_raw_jwt(body.refresh_token)['device_id']
    await IssuedToken.filter(subject=user, device_id=device_id).update(revoked=True)
    
    access_token = jwt_auth.generate_access_token(subject=user.login, payload={'device_id': device_id})
    refresh_token = jwt_auth.generate_refresh_token(subject=user.login, payload={'device_id': device_id})
    
    await IssuedToken.create(subject=user, jti=jwt_auth.get_jti(access_token), device_id=device_id)
    await IssuedToken.create(subject=user, jti=jwt_auth.get_jti(refresh_token), device_id=device_id)
    
    return UpdateTokensOutput(access_token=access_token, refresh_token=refresh_token)


@auth_api.post('/revoke_all_tokens')
# Отзывает все токены пользователя
async def revoke_all_tokens(body: RevokeTokenInput):
    payload, error = try_decode_token(jwt_auth, body.refresh_token)
    if error:
        return error
    
    if payload['type'] != TokenType.REFRESH:
        return error_response(error='InvalidToken', error_description='A refresh-token was passed, but access-token was expected')
    
    if await check_revoked(jwt_auth.get_jti(body.refresh_token)):
        return error_response(error='RevokeToken', error_description='This token already revoked')
    
    user = await AuthenticatedUser.filter(login=payload['sub']).first()
    await IssuedToken.filter(subject=user).update(revoked=True)
    return JSONResponse(status_code=200, content={'message': 'Success'})


def __generate_device_id():
    return str(uuid.uuid4())
