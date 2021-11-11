import jwt

from fastapi import Request
from jwt.exceptions import InvalidTokenError

from app.internal.auth_service.utils.check_revoked import check_revoked
from app.internal.utils.try_to_get_clear_token import try_to_get_clear_token
from app.internal.utils.error_response import error_response
from app.internal.auth_service.utils.token_type_enum import TokenType
from config.settings import JWT_SECRET, API_SECRET


def is_docs_call(request):
    return request.url.path.split('/')[-1] in ['docs', 'openapi.json']


async def check_api_secret(request: Request, call_next):
    if not is_docs_call(request):
        secret_header = request.headers.get('x-api-secret')
        if secret_header != API_SECRET:
            return error_response(error='AccessError', error_description='Api-Secret-Token header invalid', status_code=403)
        
    return await call_next(request)


async def check_access_token(request: Request, call_next):
    if not is_docs_call(request):
        authentication_header = request.headers.get('authentication')
        
        clear_token, error = try_to_get_clear_token(authentication_header)
        if error:
            return error
        
        try:
            payload = jwt.decode(clear_token, JWT_SECRET, algorithms=["HS256", "RS256"])
            if payload['type'] != TokenType.ACCESS:
                return error_response(error='AuthError', error_description='The transferred token is not an access-token', status_code=403)
        except InvalidTokenError as e:
            return error_response(error='AuthError', error_description=str(e), status_code=403)
        
        if await check_revoked(payload['jti']):
            return error_response(error='AuthError', error_description='This token has revoked', status_code=403)

    return await call_next(request)
