from fastapi import Header, HTTPException

from src.config.settings import API_SECRET


async def check_api_secret(X_API_SECRET: str = Header(...)):
    if X_API_SECRET != API_SECRET:
        raise HTTPException(status_code=403, detail="Api-Secret-Token header invalid")
