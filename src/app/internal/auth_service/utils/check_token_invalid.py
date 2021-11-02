from jwt.exceptions import InvalidTokenError


from app.internal.utils.error_response import error_response


# return (payload, error)
def check_token_invalid(jwt_auth, token):
    try:
        payload = jwt_auth.verify_token(token)
        return payload, None
    except InvalidTokenError as e:
        error = error_response(error='InvalidTokenError', error_description=str(e))
        return None, error
