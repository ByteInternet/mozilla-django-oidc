"""
Classes/functions for integrating with Django REST Framework.
"""

from django.core.exceptions import SuspiciousOperation
from rest_framework import authentication, exceptions

from mozilla_django_oidc.auth import OIDCAuthenticationBackend


class OIDCAuthentication(authentication.BaseAuthentication):
    """
    Provide OpenID authentication for DRF.
    """

    def __init__(self, backend=None):
        self.backend = backend or OIDCAuthenticationBackend()

    def authenticate(self, request):
        """
        Authenticate the request and return a tuple of (user, token).
        """
        access_token = self.get_access_token(request)

        if not access_token:
            return (None, None)

        try:
            user = self.backend.get_or_create_user(access_token, None, None)
        except SuspiciousOperation as exc:
            msg = 'Failed retrieving user from the OpenID backend: %s' % exc
            raise exceptions.AuthenticationFailed(msg)

        if not user:
            return (None, None)

        return user, access_token

    def get_access_token(self, request):
        """
        Get the access token based on a request.

        Returns None if no authentication details were provided. Raises
        AuthenticationFailed if the token is incorrect.
        """
        header = authentication.get_authorization_header(request).decode('ascii')
        if not header:
            return None

        auth = header.split()

        if auth[0].lower() != 'bearer':
            return None

        if len(auth) == 1:
            msg = 'Invalid "bearer" header. No credentials provided.'
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = 'Invalid "bearer" header. Credentials string should not contain spaces.'
            raise exceptions.AuthenticationFailed(msg)

        return auth[1]

    def authenticate_header(self, request):
        """
        Returning None here makes DRF send a 403 instead of 401.
        """
        return None
