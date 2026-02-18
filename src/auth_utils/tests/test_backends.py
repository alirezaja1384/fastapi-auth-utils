import base64
import json
import uuid
import logging
from datetime import datetime, timedelta

import jwt
from pydantic import BaseModel
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.authentication import AuthenticationMiddleware

from auth_utils.utils import BaseUser
from auth_utils.backends import (
    APIKeyAuthBackend,
    AuthBackendsWrapper,
    JWTAuthBackend,
)


JWT_KEY = str(uuid.uuid4())
JWT_ALGORITHM = "HS256"
JWT_ISSUER = str(uuid.uuid4())
JWT_AUDIENCE = str(uuid.uuid4())

VALID_API_KEY = str(uuid.uuid4())


class JWTUser(BaseModel, BaseUser[str]):
    """A test user class which has sub and permissions"""

    sub: str
    permissions: list[str]


class APIKeyUser(BaseModel, BaseUser[str]):
    api_key: str


async def get_api_key_user(api_key: str) -> APIKeyUser | None:
    if api_key == VALID_API_KEY:
        return APIKeyUser(api_key=api_key)
    return None


app = FastAPI()
app.add_middleware(
    AuthenticationMiddleware,
    backend=AuthBackendsWrapper(
        JWTAuthBackend(
            key=JWT_KEY,
            decode_algorithms=[JWT_ALGORITHM],
            user_class=JWTUser,
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
        ),
        APIKeyAuthBackend(get_user=get_api_key_user),
    ),
)


@app.get("/me")
def me(request: Request):
    return {
        "user": request.user if request.user.is_authenticated else None,
        "user_class_name": request.user.__class__.__name__,
        "is_authenticated": request.user.is_authenticated,
    }


client = TestClient(app=app)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def tamper_jwt_header(token: str, new_header: dict) -> str:
    header_b64, payload_b64, signature_b64 = token.split(".")
    new_header_bytes = json.dumps(
        new_header, separators=(",", ":"), sort_keys=True
    ).encode()
    return ".".join(
        [_b64url_encode(new_header_bytes), payload_b64, signature_b64]
    )


def generate_jwt_token(
    *, exclude_none_values: bool = True, **kwargs
) -> tuple[dict, str]:
    payload = {
        "sub": str(uuid.uuid4()),
        "aud": JWT_AUDIENCE,
        "iss": JWT_ISSUER,
        **kwargs,
    }

    if exclude_none_values:
        payload = {key: val for key, val in payload.items() if val is not None}

    return payload, jwt.encode(payload, JWT_KEY, JWT_ALGORITHM)


def test_unauthenticated():
    response = client.get("/me")

    assert response.status_code == 200
    assert response.json()["is_authenticated"] is False


def test_jwt_authenticated():
    payload, token = generate_jwt_token(
        sub=str(uuid.uuid4()),
        permissions=[str(uuid.uuid4())],
        an_invalid_field=str(uuid.uuid4()),
    )

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200

    json_response = response.json()

    assert json_response["is_authenticated"] is True
    assert json_response["user_class_name"] == JWTUser.__name__

    assert json_response["user"]["sub"] == payload["sub"]
    assert json_response["user"]["permissions"] == payload["permissions"]

    assert "an_invalid_field" not in json_response


def test_api_key_authenticated():
    response = client.get("/me", headers={"X-API-Key": VALID_API_KEY})

    assert response.status_code == 200

    json_response = response.json()
    assert json_response["is_authenticated"] is True
    assert json_response["user_class_name"] == APIKeyUser.__name__
    assert json_response["user"]["api_key"] == VALID_API_KEY


def test_jwt_api_key_authenticated():
    """
    AuthBackendsWrapper must authenticate the first user returned by
        its backends.
    """
    jwt_payload, jwt_token = generate_jwt_token(
        sub=str(uuid.uuid4()),
        permissions=[str(uuid.uuid4())],
    )

    response = client.get(
        "/me",
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "X-API-Key": VALID_API_KEY,
        },
    )

    assert response.status_code == 200
    json_response = response.json()

    # JWT backend came before APIKey backend, so the request's user
    #   must be a jwt user.
    assert json_response["is_authenticated"] is True
    assert json_response["user_class_name"] == JWTUser.__name__
    assert json_response["user"]["sub"] == jwt_payload["sub"]
    assert json_response["user"]["permissions"] == jwt_payload["permissions"]


def test_jwt_api_key_invalid_jwt():
    """
    AuthBackendsWrapper must authenticate the first user returned by
        its backends.
    """
    response = client.get(
        "/me",
        headers={
            "Authorization": "Bearer invalid_token",
            "X-API-Key": VALID_API_KEY,
        },
    )

    assert response.status_code == 200
    json_response = response.json()

    # It shouldn't authenticate the user because the jwt backend
    #   has priority over api token and given jwt token is invalid.
    assert json_response["is_authenticated"] is False
    assert json_response["user"] is None


def test_jwt_invalid_bearer():
    response = client.get("/me", headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 200

    response_json = response.json()
    assert response_json["is_authenticated"] is False
    assert response_json["user"] is None


def test_jwt_manipulated_header_alg_none():
    _, token = generate_jwt_token(permissions=[str(uuid.uuid4())])
    manipulated = tamper_jwt_header(token, {"alg": "none", "typ": "JWT"})

    response = client.get(
        "/me", headers={"Authorization": f"Bearer {manipulated}"}
    )
    assert response.status_code == 200

    response_json = response.json()
    assert response_json["is_authenticated"] is False
    assert response_json["user"] is None


def test_jwt_api_key_malformed_bearer_blocks_api_key():
    response = client.get(
        "/me",
        headers={
            "Authorization": "Bearer",
            "X-API-Key": VALID_API_KEY,
        },
    )

    assert response.status_code == 200
    response_json = response.json()
    assert response_json["is_authenticated"] is False
    assert response_json["user"] is None


def test_jwt_api_key_malformed_token_shape_blocks_api_key():
    response = client.get(
        "/me",
        headers={
            # Not a JWT (wrong number of segments)
            "Authorization": "Bearer a.b",
            "X-API-Key": VALID_API_KEY,
        },
    )

    assert response.status_code == 200
    response_json = response.json()
    assert response_json["is_authenticated"] is False
    assert response_json["user"] is None


def test_jwt_api_key_bearer_token_with_spaces_blocks_api_key():
    response = client.get(
        "/me",
        headers={
            # Credentials contain spaces -> malformed bearer token
            "Authorization": "Bearer a b",
            "X-API-Key": VALID_API_KEY,
        },
    )

    assert response.status_code == 200
    response_json = response.json()
    assert response_json["is_authenticated"] is False
    assert response_json["user"] is None


def test_api_key_invalid_key():
    response = client.get("/me", headers={"x-api-key": "invalid_value"})
    assert response.status_code == 200

    response_json = response.json()
    assert response_json["is_authenticated"] is False
    assert response_json["user"] is None


def test_jwt_expired_token():
    _, token = generate_jwt_token(
        exp=datetime.timestamp(datetime.now() - timedelta(hours=1))
    )

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.json()["is_authenticated"] is False


def test_jwt_invalid_audience():
    _, token = generate_jwt_token(aud=str(uuid.uuid4()))

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.json()["is_authenticated"] is False


def test_jwt_no_audience():
    payload, token = generate_jwt_token(aud=None, exclude_none_values=True)
    assert "aud" not in payload

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.json()["is_authenticated"] is False


def test_jwt_invalid_issuer():
    _, token = generate_jwt_token(iss=str(uuid.uuid4()))

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.json()["is_authenticated"] is False


def test_jwt_no_issuer():
    payload, token = generate_jwt_token(iss=None, exclude_none_values=True)
    assert "iss" not in payload

    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.json()["is_authenticated"] is False


def test_jwt_logging_expired_token(caplog):
    _, token = generate_jwt_token(
        exp=datetime.timestamp(datetime.now() - timedelta(hours=1))
    )

    with caplog.at_level(logging.DEBUG):
        client.get("/me", headers={"Authorization": f"Bearer {token}"})
        assert "ExpiredSignatureError" in caplog.text


def test_jwt_logging_invalid(caplog):
    with caplog.at_level(logging.WARNING):
        client.get("/me", headers={"Authorization": "Bearer invalid_token"})
        assert "DecodeError" in caplog.text
