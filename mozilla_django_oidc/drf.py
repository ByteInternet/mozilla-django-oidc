"""
Classes/functions for integrating with Django REST Framework.
"""

from django.contrib.auth import get_backends
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from rest_framework import authentication, exceptions
from requests.exceptions import HTTPError

from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.utils import parse_www_authenticate_header


def guess_oidc_backend():
    """
    Look through AUTH_BACKENDS to find one that is or extends the mozilla
    OIDC backend class.
    """
    backends = [
        backend for backend in get_backends()
        if isinstance(backend, OIDCAuthenticationBackend)
    ]
    if not backends:
        raise ImproperlyConfigured('no backends extending OIDCAuthenticationBackend found!')
    if len(backends) > 1:
        raise ImproperlyConfigured('more than one OIDCAuthenticationBackend found!')
    return backends[0]


class OIDCAuthentication(authentication.BaseAuthentication):
    """
    Provide OpenID authentication for DRF.
    """

    def __init__(self, backend=None):
        self.backend = backend or guess_oidc_backend()

    def authenticate(self, request):
        """
        Authenticate the request and return a tuple of (user, token) or None
        if there was no authentication attempt.
        """
        access_token = self.get_access_token(request)

        if not access_token:
            return None

        try:
            user = self.backend.get_or_create_user(access_token, None, None)
        except HTTPError as exc:
            resp = exc.response

            # if the oidc provider returns 401, it means the token is invalid.
            # in that case, we want to return the upstream error message (which
            # we can get from the www-authentication header) in the response.
            if resp.status_code == 401 and 'www-authenticate' in resp.headers:
                data = parse_www_authenticate_header(resp.headers['www-authenticate'])
                raise exceptions.AuthenticationFailed(data['error_description'])

            # for all other http errors, just re-raise the exception.
            raise
        except SuspiciousOperation as exc:
            # trust that the message in the exception is presentable to the user
            raise exceptions.AuthenticationFailed('Login failed: %s' % exc)

        if not user:
            raise exceptions.AuthenticationFailed('Login failed: No user found '
                                                  'for the given access token.')

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
