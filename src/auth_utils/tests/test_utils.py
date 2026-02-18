import uuid
from http import HTTPStatus

import jwt
from pydantic import BaseModel
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.authentication import AuthenticationMiddleware

from auth_utils.utils import BaseUser, auth_required
from auth_utils.backends import (
    APIKeyAuthBackend,
    AuthBackendsWrapper,
    JWTAuthBackend,
)


JWT_ALGORITHM = "HS256"
JWT_KEY = str(uuid.uuid4())

RANDOM_CLAIM = str(uuid.uuid4())
RANDOM_ROLE = str(uuid.uuid4())

API_KEY = str(uuid.uuid4())
RANDOM_SCOPE = str(uuid.uuid4())
API_KEY_SCOPES = {API_KEY: [RANDOM_SCOPE]}


class JWTUser(BaseModel, BaseUser[str]):
    """A test user class which has sub and claims"""

    sub: str
    roles: list[str]
    claims: list[str]

    def has_perm(self, perm: str) -> bool:
        perm_type, perm_val = perm.split(":")

        match perm_type:
            case "role":
                return perm_val in self.roles  # Required role
            case "claim":
                return perm_val in self.claims  # Required claim
            case _:
                return False


class APIKeyUser(BaseUser[str]):
    _api_key: str
    _scopes: list[str]

    def __init__(self, api_key: str, scopes: list[str]) -> None:
        self._api_key = api_key
        self._scopes = scopes

    def has_perm(self, perm: str) -> bool:
        perm_type, perm_val = perm.split(":")

        match perm_type:
            case "scope":
                return perm_val in self._scopes
            case _:
                return False


async def get_api_key_user(api_key: str):
    if api_key == API_KEY:
        return APIKeyUser(
            api_key=api_key, scopes=API_KEY_SCOPES.get(api_key, [])
        )


app = FastAPI()
app.add_middleware(
    AuthenticationMiddleware,
    backend=AuthBackendsWrapper(
        JWTAuthBackend(
            key=JWT_KEY, decode_algorithms=[JWT_ALGORITHM], user_class=JWTUser
        ),
        APIKeyAuthBackend(get_user=get_api_key_user),
    ),
)


@app.get("/auth_no_perm", dependencies=[Depends(auth_required())])
def auth_no_perm():
    """Only requires user to be authenticated"""
    return {"msg": "Well done!"}


@app.get(
    "/auth_with_perm",
    dependencies=[
        Depends(
            # Requires user to have both RANDOM_CLAIM and RANDOM_ROLE
            auth_required(
                permissions=[f"claim:{RANDOM_CLAIM}", f"role:{RANDOM_ROLE}"]
            )
        )
    ],
)
def auth_with_perm():
    """Requires the user to have `RANDOM_PERMISSION` claim as well."""
    return {"msg": "Well done!"}


@app.get(
    "/auth_api_key",
    dependencies=[
        Depends(
            auth_required(
                permissions=[f"scope:{RANDOM_SCOPE}"], user_class=APIKeyUser
            )
        )
    ],
)
def auth_api_key_only():
    """
    Requires the user to be an APIKeyUser which has the `RANDOM_SCOPE` scope.
    """
    return {"msg": "Well done!"}


client = TestClient(app=app)


def get_jwt_headers(
    *,
    sub: str,
    roles: list[str] | None = None,
    claims: list[str] | None = None,
) -> dict:
    token = jwt.encode(
        {"sub": sub, "roles": roles or [], "claims": claims or []},
        JWT_KEY,
        JWT_ALGORITHM,
    )

    return {"Authorization": f"Bearer {token}"}


def test_auth_no_perm_unauthenticated():
    response = client.get("/auth_no_perm")
    assert response.status_code == HTTPStatus.UNAUTHORIZED  # 401


def test_auth_no_perm_authenticated():
    response = client.get(
        "/auth_no_perm", headers=get_jwt_headers(sub="test", claims=[])
    )

    assert response.status_code == HTTPStatus.OK  # 200


def test_auth_with_perm_unauthenticated():
    response = client.get("/auth_with_perm")
    assert response.status_code == HTTPStatus.UNAUTHORIZED  # 401


def test_auth_with_perm_authenticated_unauthorized():
    response = client.get(
        "/auth_with_perm",
        headers=get_jwt_headers(sub="test", claims=[], roles=[]),
    )

    assert response.status_code == HTTPStatus.FORBIDDEN  # 403


def test_auth_with_perm_authenticated_fully_authorized():
    response = client.get(
        "/auth_with_perm",
        headers=get_jwt_headers(
            sub="test", claims=[RANDOM_CLAIM], roles=[RANDOM_ROLE]
        ),
    )

    assert response.status_code == HTTPStatus.OK  # 200


def test_auth_with_perm_authenticated_partially_authorized():
    no_claim_response = client.get(
        "/auth_with_perm",
        headers=get_jwt_headers(sub="test", claims=[], roles=[RANDOM_ROLE]),
    )

    no_role_response = client.get(
        "/auth_with_perm",
        headers=get_jwt_headers(sub="test", claims=[RANDOM_CLAIM], roles=[]),
    )

    assert no_claim_response.status_code == HTTPStatus.FORBIDDEN  # 403
    assert no_role_response.status_code == HTTPStatus.FORBIDDEN  # 403


def test_auth_with_perm_valid_user_type():
    response = client.get("/auth_api_key", headers={"X-API-Key": API_KEY})
    assert response.status_code == 200


def test_auth_with_perm_invalid_user_type():
    jwt_headers = get_jwt_headers(
        sub="test", claims=[RANDOM_CLAIM], roles=[RANDOM_ROLE]
    )

    assert client.get("/auth_no_perm", headers=jwt_headers).status_code == 200
    assert client.get("/auth_api_key", headers=jwt_headers).status_code == 401
