from fastapi import FastAPI
from tortoise.contrib.fastapi import register_tortoise

from config.settings import *
from app.auth_service.views.endpoints import router as auth

auth_service = FastAPI()
auth_service.include_router(auth, tags=['auth_service'])

register_tortoise(
    auth_service,
    db_url=os.getenv("DATABASE_URL"),
    modules={"models": ["app.auth_service.models"]},
    generate_schemas=True,
    add_exception_handlers=True,
)