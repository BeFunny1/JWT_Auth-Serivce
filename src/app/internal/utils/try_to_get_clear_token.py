from app.internal.utils.error_response import error_response


def try_to_get_clear_token(authentication_header):
    if authentication_header is None:
        return None, error_response(error='AuthError', error_description='Access-token header is not set')
        
    if 'Bearer ' not in authentication_header:
        return None, error_response(error='AuthError', error_description='Access-token must have the form "Bearer <TOKEN>"', status_code=403)
    
    clear_token = authentication_header.replace('Bearer ', '')
    return clear_token, None
