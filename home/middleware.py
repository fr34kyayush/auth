from django.conf import settings
from django.contrib.auth import logout
from jwt.exceptions import DecodeError, ExpiredSignatureError
import jwt

class JWTAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = request.COOKIES.get('token')
        if token:
            try:
                payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=['HS256'])
                user_id = payload['user_id']
                request.user_id = user_id
                request.username = payload.get('username')
            except (DecodeError, ExpiredSignatureError):
                # Token is invalid or expired, log out the user
                logout(request)

        response = self.get_response(request)

        # Check if the token has been modified after the response is processed
        if token and response.status_code == 200:
            new_token = response.cookies.get('token')
            if not new_token or new_token != token:
                # Token has been tampered with, log out the user
                logout(request)

        return response
