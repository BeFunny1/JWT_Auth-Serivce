from fastapi import FastAPI, Depends
from starlette.responses import Response

from app.internal.dependencies import required_access_token
from app.internal.middlewares import check_access_token


main_app_api = FastAPI(dependencies=[Depends(required_access_token)])
main_app_api.middleware("http")(check_access_token)


@main_app_api.get('/get_content')
async def get_content():
    return Response('SECRET CONTENT', status_code=200)
