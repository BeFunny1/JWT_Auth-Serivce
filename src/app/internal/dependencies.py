from fastapi import Header


async def required_api_secret(X_API_SECRET: str = Header(...)):
    pass


async def required_access_token(AUTHENTICATION: str = Header(...)):
    pass
