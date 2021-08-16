import uvicorn

from fastapi import FastAPI

from src.config.settings import *
from src.app.auth_service.views.endpoints import router as auth

auth_service = FastAPI()
auth_service.include_router(auth, tags=['auth_service'])


if __name__ == '__main__':
    uvicorn.run(auth_service, host=HOST, port=PORT)
