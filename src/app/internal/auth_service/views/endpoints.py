from typing import List

from fastapi import APIRouter, HTTPException, Depends

from starlette import status
from starlette.responses import Response

from app.internal.auth_service.models import AuthenticatedUser
from app.internal.auth_service.utils.password_hash import hash_password

from app.internal.auth_service.views.in_out_models.update import UpdateTokensInput, UpdateTokensOutput
from app.internal.auth_service.views.in_out_models.register import RegisterInput, RegisterOutput

from config.settings import redis


router = APIRouter(prefix='/auth_service')


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

