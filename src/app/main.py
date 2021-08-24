from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse

from fastapi_jwt_auth.exceptions import AuthJWTException

from tortoise.contrib.fastapi import register_tortoise

from redis import Redis

from app.middlewares import check_api_secret

from config.settings import *

from app.auth_service.views.endpoints import router as auth

redis = Redis(host='localhost', port=6379, db=0, decode_responses=True)

auth_service = FastAPI()
auth_service.include_router(auth, tags=['auth_service'], dependencies=[Depends(check_api_secret)])


@auth_service.exception_handler(AuthJWTException)
def auth_jwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )


register_tortoise(
    auth_service,
    db_url=os.getenv("DATABASE_URL"),
    modules={"models": ["app.auth_service.models"]},
    generate_schemas=True,
    add_exception_handlers=True,
)