from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse

from tortoise.contrib.fastapi import register_tortoise

from config.settings import *

from app.internal.auth_service.views.endpoints import router as auth
from app.internal.main_app.endpoints import router as main_app
from app.internal.middlewares import check_api_secret, check_access_token


auth_service = FastAPI()
auth_service.include_router(auth, tags=['auth_service'], dependencies=[Depends(check_api_secret)])
auth_service.include_router(main_app, tags=['main_app'], dependencies=[Depends(check_access_token)])


register_tortoise(
    auth_service,
    db_url=os.getenv("DATABASE_URL"),
    modules={"models": ["app.internal.auth_service.models"]},
    generate_schemas=True,
    add_exception_handlers=True,
)