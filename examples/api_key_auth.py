import uuid

from pydantic import BaseModel
from fastapi import Depends, FastAPI, Request
from fastapi.security import APIKeyHeader
from starlette.middleware.authentication import AuthenticationMiddleware

from auth_utils.utils import BaseUser, auth_required
from auth_utils.backends import APIKeyAuthBackend


# API key, scope pair
API_KEYS = {
    str(uuid.uuid4()): ["home"],
    str(uuid.uuid4()): [],
}


class Permission(BaseModel):
    scopes: list[str] | None = None


class APIKeyUser(BaseUser[Permission]):
    """A test user class which has sub and permissions"""

    api_key: str
    scopes: list[str]

    def __init__(self, api_key: str, scopes: list[str]) -> None:
        self.api_key = api_key
        self.scopes = scopes

    def has_perm(self, perm: Permission) -> bool:
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


async def get_user(api_key: str) -> APIKeyUser | None:
    if api_key not in API_KEYS:
        return None

    return APIKeyUser(api_key=api_key, scopes=API_KEYS[api_key])


app = FastAPI(
    docs_url="/docs",
    # NOTE: Following dependency enables authorize functionality for swagger
    dependencies=[Depends(APIKeyHeader(name="X-API-Key", auto_error=False))],
)

app.add_middleware(
    AuthenticationMiddleware,
    backend=APIKeyAuthBackend(get_user=get_user),
)


@app.on_event("startup")
def startup():
    print("> Valid API keys and their scopes:")
    for token, scopes in API_KEYS.items():
        print(f" - {token}: {scopes}")


@app.get(
    "/",
    dependencies=[
        Depends(auth_required(permissions=[Permission(scopes=["home"])]))
    ],
)
def me(request: Request):
    return {"user": request.user}
