import jwt

from fastapi import Request
from jwt.exceptions import InvalidTokenError

from app.internal.utils.error_response import error_response
from config.settings import JWT_SECRET, API_SECRET


def is_docs_call(request):
    return request.url.path.split('/')[-1] in ['docs', 'openapi.json']


async def check_api_secret(request: Request, call_next):
    if not is_docs_call(request):
        print(request.headers, flush=True)
        secret_header = request.headers.get('x-api-secret')
        if secret_header != API_SECRET:
            return error_response(error='AccessError', error_description='Api-Secret-Token header invalid', status_code=403)
        
    return await call_next(request)


async def check_access_token(request: Request, call_next):
    if not is_docs_call(request):
        authentication_header = request.headers.get('authentication')
        if authentication_header is None:
            return error_response(error='AuthError', error_description='JWT token is not specified in the header', status_code=403)
        
        if 'Bearer ' not in authentication_header:
            return error_response(error='AuthError', error_description='Access-token must have the form "Bearer <TOKEN>"', status_code=403)
        
        clear_token = authentication_header.replace('Bearer ', '')
        try:
            payload = jwt.decode(clear_token, JWT_SECRET, algorithms=["HS256", "RS256"])
            if payload['type'] != 'access':
                return error_response(error='AuthError', error_description='A refresh-token was passed, but access-token was expected', status_code=403)
        except InvalidTokenError as e:
            return error_response(error='AuthError', error_description=str(e), status_code=403)

    return await call_next(request)
