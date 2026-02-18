from __future__ import annotations

from http import HTTPStatus
from typing import (
    Annotated,
    Any,
    Callable,
    Generic,
    Sequence,
    TypeGuard,
    TypeVar,
)

from fastapi import Depends, HTTPException, Request
from starlette.authentication import (
    BaseUser as StarletteBaseUser,
    UnauthenticatedUser,
)


PermT = TypeVar("PermT")
UserT = TypeVar("UserT", bound="BaseUser[Any]")


class BaseUser(StarletteBaseUser, Generic[PermT]):
    """Base user class

    Raises:
        NotImplementedError: has_perm must be implemented by user
            in order to use permission checks.
    """

    @property
    def is_authenticated(self) -> bool:
        return True

    def has_perm(self, perm: PermT) -> bool:
        """Checks if user has a specific permission or not.

        Args:
            perm (PermT): The permission

        Raises:
            NotImplementedError: This method must be implemented by user.
        """
        raise NotImplementedError()

    def has_perms(self, perms: Sequence[PermT]) -> bool:
        """Checks if user has all given permissions or not.
        Calls has_perm() for each permission by default.

        Args:
            perm (Sequence[str]): The permissions sequence.
        """
        return all(map(self.has_perm, perms))


def get_user(request: Request) -> BaseUser[Any] | UnauthenticatedUser:
    """Returns the current user

    NOTE: This function DOES NOT authenticate the user by itself.
        An UnauthenticatedUser will be returned when user is not authenticated.
        You have to check `is_authenticated` yourself or use auth_required().

    Args:
        request (Request): User's http request.

    Returns:
        BaseUser[Any] | UnauthenticatedUser: Current user.
    """
    return request.user


def _is_authenticated_user(
    user: StarletteBaseUser, user_class: type[UserT]
) -> TypeGuard[UserT]:
    return bool(user.is_authenticated) and isinstance(user, user_class)


def auth_required(
    permissions: Sequence[Any] | None = None,
    user_class: type[BaseUser[Any]] = BaseUser,
) -> Callable[[Annotated[StarletteBaseUser, Depends(get_user)]], None]:
    """Enforces authentication and authorization for current user.

    Args:
        permissions (Sequence[Any] | None, optional): The permissions user
            MUST have. Defaults to none.
        user_class (type[BaseUser[Any]], optional): The user class to check.
            Defaults to BaseUser.

    Returns:
        Callable[[Annotated[StarletteBaseUser, Depends(get_user)]], None]:
            A dependency function which checks if the user is authenticated
            and authorized.
    """

    def auth_checker(
        user: Annotated[StarletteBaseUser, Depends(get_user)],
    ) -> None:
        # If user is not authenticated or its authentication type is invalid
        if not _is_authenticated_user(user, user_class):
            raise HTTPException(HTTPStatus.UNAUTHORIZED)

        # If user is not authorized
        if not user.has_perms(permissions or []):
            raise HTTPException(HTTPStatus.FORBIDDEN)

    return auth_checker
