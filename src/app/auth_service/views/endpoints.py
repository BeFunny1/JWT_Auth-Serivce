from app.auth_service.models import AuthenticatedUser
from app.auth_service.utils.password_hash import hash_password
from fastapi import Depends, APIRouter, HTTPException
from starlette import status
from starlette.responses import Response

from app.auth_service.views.in_out_models.update import UpdateTokensInput, UpdateTokensOutput
from app.auth_service.views.in_out_models.deregister import DeregisterInput, DeregisterOutput
from app.auth_service.views.in_out_models.register import RegisterInput, RegisterOutput


router = APIRouter(prefix='/auth_service')


@router.post(
    '/register',
    response_model=RegisterOutput,
)
async def register(body: RegisterInput):
    await AuthenticatedUser.create(
        login=body.login,
        password_hash=hash_password(body.password),
        refresh_token='plug_refresh_token'
    )
    return Response(status_code=201)


@router.delete(
    '/deregister',
    response_model=DeregisterOutput,
)
async def deregister(body: DeregisterInput):
    user = await AuthenticatedUser.filter(login=body.login).delete()
    if hash_password(body.password) == user.password_hash:
        # user.delete()
        return Response(status_code=status.HTTP_200_OK)
    raise HTTPException(status_code=400, detail="Incorrect password")


@router.post(
    '/update_tokens',
    response_model=UpdateTokensOutput,
)
async def update_tokens(body: UpdateTokensInput):
    return Response(status_code=status.HTTP_200_OK)
