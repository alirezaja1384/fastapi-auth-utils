import uuid
from typing import Annotated

import jwt
from pydantic import BaseModel
from fastapi import Depends, FastAPI
from fastapi.security import HTTPBearer, APIKeyHeader
from starlette.middleware.authentication import AuthenticationMiddleware

from auth_utils.utils import BaseUser, auth_required, get_user
from auth_utils.backends import (
    APIKeyAuthBackend,
    AuthBackendsWrapper,
    JWTAuthBackend,
)

# JWT config
JWT_KEY = str(uuid.uuid4())
JWT_ALGORITHM = "HS256"

# API key, scope pair
API_KEYS = {
    str(uuid.uuid4()): ["home"],
    str(uuid.uuid4()): [],
}


class JWTPermission(BaseModel):
    claims: list[str] | None = None
    roles: list[str] | None = None


class APIKeyPermission(BaseModel):
    scopes: list[str] | None = None


class JWTUser(BaseModel, BaseUser[JWTPermission]):
    """A test user class which has sub and permissions"""

    sub: str
    name: str = ""
    claims: list[str]

    def has_perm(self, perm: JWTPermission) -> bool:
        if not isinstance(perm, JWTPermission):
            raise ValueError(
                f"Unsupported permission type `{perm.__class__.__name__}`!"
            )

        def has_claims(claims: list[str]):
            return all(map(lambda claim: claim in self.claims, claims))

        return has_claims(perm.claims or [])

    @property
    def identity(self) -> str:
        return self.sub

    @property
    def display_name(self) -> str:
        return self.name


class APIKeyUser(BaseUser[APIKeyPermission]):
    """A test user class which has sub and permissions"""

    api_key: str
    scopes: list[str]

    def __init__(self, api_key: str, scopes: list[str]) -> None:
        self.api_key = api_key
        self.scopes = scopes

    def has_perm(self, perm: APIKeyPermission) -> bool:
        if not isinstance(perm, APIKeyPermission):
            raise ValueError(
                f"Unsupported permission type `{perm.__class__.__name__}`!"
            )

        def has_scopes(scopes: list[str]):
            return all(map(lambda scope: scope in self.scopes, scopes))

        return has_scopes(perm.scopes or [])

    @property
    def identity(self) -> str:
        return self.api_key

    @property
    def display_name(self) -> str:
        masked_api_key = self.api_key.replace(self.api_key[4:-4], "*" * 5)
        return f"API user: {masked_api_key}"


async def get_api_key_user(api_key: str) -> APIKeyUser | None:
    if api_key not in API_KEYS:
        return None

    return APIKeyUser(api_key=api_key, scopes=API_KEYS[api_key])


app = FastAPI(
    docs_url="/docs",
    # NOTE: Following dependency enables authorize functionality for swagger
    dependencies=[
        Depends(HTTPBearer(auto_error=False)),
        Depends(APIKeyHeader(name="X-API-Key", auto_error=False)),
    ],
)

app.add_middleware(
    AuthenticationMiddleware,
    backend=AuthBackendsWrapper(
        JWTAuthBackend(
            key=JWT_KEY, decode_algorithms=[JWT_ALGORITHM], user_class=JWTUser
        ),
        APIKeyAuthBackend(get_user=get_api_key_user),
    ),
)


@app.on_event("startup")
def startup():
    claims = ["home"]
    payload = JWTUser(sub="user-0", name="test", claims=claims).model_dump()

    print("> Valid JWT tokens and their claims:")
    print(" - Token:", jwt.encode(payload, JWT_KEY, JWT_ALGORITHM))
    print(" - Claims:", claims)

    print()

    print("> Valid API keys and their scopes:")
    for token, scopes in API_KEYS.items():
        print(f" - {token}: {scopes}")


@app.get(
    "/jwt_me",
    dependencies=[
        Depends(
            auth_required(
                permissions=[JWTPermission(claims=["home"])],
                user_class=JWTUser,
            )
        )
    ],
)
def jwt_auth(user: Annotated[JWTUser, Depends(get_user)]):
    return {"user_class": user.__class__.__name__, "user": user}


@app.get(
    "/api_key_me",
    dependencies=[
        Depends(
            auth_required(
                permissions=[APIKeyPermission(scopes=["home"])],
                user_class=APIKeyUser,
            )
        )
    ],
)
def api_key_auth(user: Annotated[APIKeyUser, Depends(get_user)]):
    return {"user_class": user.__class__.__name__, "user": user}
