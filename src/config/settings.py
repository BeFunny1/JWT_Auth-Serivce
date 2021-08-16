import os

ACCESS_TOKEN_TTL = 15
REFRESH_TOKEN_TTL = 12 * 24 * 60

HOST = os.environ.get('HOST', 'localhost')
PORT = int(os.environ.get('PORT', 8000))
API_SECRET = os.environ['API_SECRET']
JWT_SECRET = os.environ['JWT_SECRET']
