from fastapi import FastAPI

from tortoise.contrib.fastapi import register_tortoise

from app.internal.auth_service.views.endpoints import auth_api as auth_api
from app.internal.main_app.endpoints import main_app_api as main_app_api

from config.settings import *


auth_service = FastAPI()

auth_service.mount('/auth_service', auth_api)
auth_service.mount('/main_app', main_app_api)


register_tortoise(
    auth_service,
    db_url=os.getenv("DATABASE_URL"),
    modules={"models": ["app.models"]},
    generate_schemas=True,
    add_exception_handlers=True,
)
