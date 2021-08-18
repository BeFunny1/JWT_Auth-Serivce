import uvicorn

from fastapi import FastAPI

from config.settings import *
from app.auth_service.views.endpoints import router as auth

auth_service = FastAPI()
auth_service.include_router(auth, tags=['auth_service'])
