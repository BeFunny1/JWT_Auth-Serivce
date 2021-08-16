from fastapi import Depends, APIRouter
from starlette import status
from starlette.responses import Response

from src.app.auth_service.models.update import UpdateTokensInput, UpdateTokensOutput
from src.app.auth_service.models.deregister import DeregisterInput, DeregisterOutput
from src.app.auth_service.models.register import RegisterInput, RegisterOutput
from src.app.auth_service.views.middlewares import check_api_secret

router = APIRouter(
    prefix='/auth_service',
    dependencies=[Depends(check_api_secret)]
)


@router.post(
    '/register',
    response_model=RegisterOutput,
)
async def register(body: RegisterInput):
    return Response(status_code=status.HTTP_200_OK)


@router.post(
    '/deregister',
    response_model=DeregisterOutput,
)
async def deregister(body: DeregisterInput):
    return Response(status_code=status.HTTP_200_OK)


@router.post(
    '/update_tokens',
    response_model=UpdateTokensOutput,
)
async def update_tokens(body: UpdateTokensInput):
    return Response(status_code=status.HTTP_200_OK)
