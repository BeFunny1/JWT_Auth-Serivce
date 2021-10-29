from typing import List
from app.auth_service.views.in_out_models.user import UserOutput

from fastapi import APIRouter, HTTPException, Depends

from fastapi_jwt_auth import AuthJWT

from starlette import status
from starlette.responses import Response

from app.auth_service.models import AuthenticatedUser
from app.auth_service.utils.password_hash import hash_password

from app.auth_service.views.in_out_models.update import UpdateTokensInput, UpdateTokensOutput
from app.auth_service.views.in_out_models.register import RegisterInput, RegisterOutput

from config.settings import redis, settings


router = APIRouter(prefix='/auth_service')


@AuthJWT.load_config
def get_config():
    return settings


@AuthJWT.token_in_denylist_loader
def check_if_token_in_denylist(decrypted_token):
    jti = decrypted_token['jti']
    entry = redis.get(jti)
    return entry and entry == 'true'


@router.post(
    '/register',
    response_model=RegisterOutput,
)
# Регистрирует пользователя, создаёт под него access/refresh-токены
async def register(body: RegisterInput):
    if await AuthenticatedUser.filter(login=body.login).exists():
        raise HTTPException(status_code=400, detail='This login is already occupied')
    
    user = await AuthenticatedUser.create(
        login=body.login,
        password_hash=hash_password(body.password),
    )
    
    return RegisterOutput(access_token='access_token', refresh_token='refresh_token')


@router.put(
    '/update_tokens',
    response_model=UpdateTokensOutput,
)
# Получает refresh-токен, возвращает пару access/refresh 
async def update_tokens(body: UpdateTokensInput):
    return UpdateTokensOutput(access_token='access_token', refresh_token='refresh_token')

