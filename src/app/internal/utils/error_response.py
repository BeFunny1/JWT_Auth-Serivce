from fastapi.responses import JSONResponse


def error_response(error, error_description, status_code=400):
    return JSONResponse(
        status_code=status_code,
        content={
            "error": error,
            "error_description": error_description
            }
        )
