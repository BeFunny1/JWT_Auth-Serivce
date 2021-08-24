from fastapi import APIRouter, HTTPException, Depends

from fastapi_jwt_auth import AuthJWT

from starlette import status
from starlette.responses import Response

from app.auth_service.models import AuthenticatedUser
from app.auth_service.utils.password_hash import hash_password

from app.auth_service.views.in_out_models.update import UpdateTokensInput, UpdateTokensOutput
from app.auth_service.views.in_out_models.deregister import DeregisterInput, DeregisterOutput
from app.auth_service.views.in_out_models.register import RegisterInput, RegisterOutput

from config.settings import Settings


router = APIRouter(prefix='/auth_service')


@AuthJWT.load_config
def get_config():
    return Settings()


@router.put(
    '/register',
    response_model=RegisterOutput,
)
async def register(body: RegisterInput, Authorize: AuthJWT = Depends()):
    _, created = await AuthenticatedUser.get_or_create(
        login=body.login,
        password_hash=hash_password(body.password),
    )
    if not created:
        raise HTTPException(status_code=400, detail='This login is already occupied')
    
    access_token = Authorize.create_access_token(subject=body.login)
    refresh_token = 'plug_refresh_token'
    
    return RegisterOutput(access_token=access_token, refresh_token=refresh_token)


@router.delete(
    '/deregister',
    response_model=DeregisterOutput,
)
async def deregister(body: DeregisterInput):
    user = await AuthenticatedUser.filter(login=body.login).first()
    if user and hash_password(body.password) == user.password_hash:
        await user.delete()
        return Response(status_code=status.HTTP_200_OK)
    raise HTTPException(status_code=400, detail="Incorrect password")


@router.post(
    '/update_tokens',
    response_model=UpdateTokensOutput,
)
async def update_tokens(body: UpdateTokensInput):
    return Response(status_code=status.HTTP_200_OK)
