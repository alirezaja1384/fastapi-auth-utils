"""Authentication backend for starlette's AuthenticationMiddleware."""

import logging
from typing import Awaitable, Callable, Sequence, Type

import jwt
from starlette.authentication import (
    AuthenticationBackend,
    AuthCredentials,
    BaseUser as StarletteBaseUser,
    UnauthenticatedUser,
)
from starlette.requests import HTTPConnection

from auth_utils.utils import BaseUser


class JWTAuthBackend(AuthenticationBackend):
    """
    An authentication backend for starlette's `AuthenticationMiddleware` which
        relies on JWT bearer tokens.
    """

    key: str
    decode_algorithms: list[str]
    audience: str | None
    issuer: str | None

    user_class: Type[BaseUser] | None
    get_user: Callable[[dict], Awaitable[BaseUser | None]] | None

    def __init__(
        self,
        key: str,
        decode_algorithms: list[str],
        audience: str | None = None,
        issuer: str | None = None,
        user_class: Type[BaseUser] | None = None,
        get_user: Callable[[dict], Awaitable[BaseUser | None]] | None = None,
    ) -> None:
        """
        Args:
            key (str): the JWT decode key.

            decode_algorithms (list[str]): Allowed decode algorithms.

            audience (str | None, optional): Valid jwt audience.
                Defaults to None.

            issuer (str | None, optional): Valid jwt issuer. Defaults to None.

            user_class (Type[BaseUser]): A BaseUser subclass which accepts
                payload data as kwargs. Has priority over get_user.
                Defaults to None.

            get_user (
                Callable[[dict], Awaitable[BaseUser | None]] | None, optional
            ):
                An async function which returns the authenticated user when
                    payload data is valid and `None` if not. Defaults to None.
        """

        if not (user_class or get_user):
            raise ValueError(
                f"{self.__class__.__name__}: Neither `user_class`"
                " nor `get_user` provided!"
            )

        self.key = key
        self.decode_algorithms = decode_algorithms
        self.user_class = user_class
        self.audience = audience
        self.issuer = issuer
        self.get_user = get_user

        self.logger = logging.getLogger("jwt-auth-backend")

    async def get_user_instance(self, payload: dict) -> BaseUser | None:
        """Returns the user instance using the jwt payload.

        NOTE: `user_class` has priority over `get_user`.

        Args:
            payload (dict): The JWT token's payload.

        Returns:
            BaseUser | None: The instance of `user_class` or result of
                `get_user(payload)`.
        """
        if self.user_class:
            return self.user_class(**payload)
        elif self.get_user:
            return await self.get_user(payload)

    def get_payload(
        self, token: str, fail_silently: bool, log_errors: bool = True
    ) -> dict | None:
        """Returns the payload of VALID token.

        Args:
            token (str): JWT token.
            fail_silently (bool): Returns `None` on errors instead of raising.
            log_errors (bool, optional): Logs PyJWT exceptions if True.

        Returns:
            dict | None: Decoded payload for valid tokens and
                None for invalid ones.
        """
        try:
            return jwt.decode(
                token,
                key=self.key,
                algorithms=self.decode_algorithms,
                audience=self.audience,
                issuer=self.issuer,
            )

        except jwt.PyJWTError as exc:
            if log_errors:
                self.logger.log(
                    level=(
                        logging.DEBUG
                        if isinstance(exc, jwt.ExpiredSignatureError)
                        else logging.WARNING
                    ),
                    msg=repr(exc),
                    exc_info=False,
                )

            if fail_silently:
                return None

            raise

    async def authenticate(
        self, conn: HTTPConnection
    ) -> tuple[AuthCredentials, BaseUser | UnauthenticatedUser] | None:
        """Authenticates the users who have a valid JWT token.

        Args:
            conn (HTTPConnection): The http request.

        Returns:
            tuple[AuthCredentials, BaseUser | UnauthenticatedUser] | None:
                Authentication result.
        """
        auth_header = conn.headers.get("Authorization")

        # When request does not provide a bearer token, there's
        #   no reason for this backend to get involved.
        if not auth_header:
            return None

        scheme, _, credentials = auth_header.partition(" ")
        if scheme.lower() != "bearer":
            return None

        token = credentials.strip()
        if not token or " " in token:
            # Malformed bearer header; treat as an auth failure to prevent
            # falling through to other backends.
            return (AuthCredentials(), UnauthenticatedUser())

        try:
            payload = self.get_payload(
                token=token, fail_silently=True, log_errors=True
            )

            # Authenticate the user if token is valid
            if payload and (user := await self.get_user_instance(payload)):
                return (AuthCredentials(["authenticated"]), user)
            return (AuthCredentials(), UnauthenticatedUser())

        # If parsing payload data fails, fail closed (do not fall through).
        except (ValueError, TypeError) as err:
            self.logger.log(logging.ERROR, err, exc_info=True)
            return (AuthCredentials(), UnauthenticatedUser())


class APIKeyAuthBackend(AuthenticationBackend):
    api_key_header: str
    get_user: Callable[[str], Awaitable[BaseUser | None]]

    def __init__(
        self,
        get_user: Callable[[str], Awaitable[BaseUser | None]],
        api_key_header: str = "X-API-Key",
    ):
        """
        Args:
            get_user (Callable[[str], Awaitable[BaseUser  |  None]]): An async
                function which returns the authenticated user given the
                API key.

            api_key_header (str, optional): The header which contains the
                API key. Defaults to "X-API-Key".
        """
        self.get_user = get_user
        self.api_key_header = api_key_header

    async def authenticate(
        self, conn: HTTPConnection
    ) -> tuple[AuthCredentials, BaseUser | UnauthenticatedUser] | None:
        """
        Retrieves the API key from the request header and authenticates
            the returned user from `get_user(api_key)` if not None.

        Returns:
            tuple[AuthCredentials, BaseUser | UnauthenticatedUser] | None:
                The authentication result.
        """
        api_key = conn.headers.get(self.api_key_header, None)

        # When request does not provide an API key, there's no reason for
        #   this backend to get involved.
        if not api_key:
            return

        if user := await self.get_user(api_key):
            return (AuthCredentials(["authenticated"]), user)
        else:
            return (AuthCredentials(), UnauthenticatedUser())


class AuthBackendsWrapper(AuthenticationBackend):
    """
    A helper class which wraps multiple auth backends and returns
        the first authentication result returned by the given backends
        respectively.
    """

    backends: Sequence[AuthenticationBackend]

    def __init__(self, *backends: AuthenticationBackend) -> None:
        self.backends = backends

    async def authenticate(
        self, conn: HTTPConnection
    ) -> tuple["AuthCredentials", "StarletteBaseUser"] | None:
        """
        Calls each backend's authenticate() respectively and return the
            first non-None result. Whether it is authenticated or not.

        Returns:
            tuple["AuthCredentials", "StarletteBaseUser"] | None: The
                first returned authentication result.
        """
        for backend in self.backends:
            if (
                auth_result := await backend.authenticate(conn=conn)
            ) is not None:
                return auth_result
