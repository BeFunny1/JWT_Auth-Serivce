import jwt

from fastapi import Header, HTTPException
from jwt.exceptions import InvalidTokenError
from config.settings import API_SECRET, JWT_SECRET


async def check_api_secret(X_API_SECRET: str = Header(...)):
    if X_API_SECRET != API_SECRET:
        raise HTTPException(status_code=403, detail="Api-Secret-Token header invalid")


async def check_access_token(AUTHENTICATION: str = Header(...)):
    if 'Bearer ' not in AUTHENTICATION:
        raise HTTPException(status_code=400, detail='Access-token must have the form "Bearer <TOKEN>"')
    
    clear_token = AUTHENTICATION.replace('Bearer ', '')
    try:
        payload = jwt.decode(clear_token, JWT_SECRET, algorithms=["HS256", "RS256"])
        if payload['type'] != 'access':
            raise HTTPException(status_code=403, detail='A refresh-token was passed, but access-token was expected')
    except InvalidTokenError as e:
        raise HTTPException(status_code=403, detail=str(e))
