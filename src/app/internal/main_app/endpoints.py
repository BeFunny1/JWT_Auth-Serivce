from fastapi import APIRouter
from starlette.responses import Response


router = APIRouter(prefix='/main_app')

@router.get('/get_content')
async def get_content():
    return Response('SECRET CONTENT', status_code=200)
