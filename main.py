from __future__ import annotations

import logging
import os
from typing import Any, Dict

import requests
import uvicorn
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer
from jwt import PyJWKClient, decode  # from pyjwt
from jwt.exceptions import ExpiredSignatureError
from pydantic import BaseModel

logger = logging.getLogger("uvicorn.error")


class TokenRequest(BaseModel):
    access_token: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


KC_ROOT_URL = str(os.environ.get("KC_HOST", "http://localhost"))
KC_PORT = str(os.environ.get("KC_PORT", "8080"))
KC_REALM = str(os.environ.get("KC_REALM", "UKAEA"))
OIDC_BASE_URL = f"{KC_ROOT_URL}:{KC_PORT}/realms/{KC_REALM}/protocol/openid-connect"
# For the test client
SECRET_KEY = str(os.environ.get("SECRET_KEY"))
JWKS_URL = f"{OIDC_BASE_URL}/certs"

app = FastAPI()

ROUTER = APIRouter(tags=["example AUTH routes"])
USER_ROUTER = APIRouter(tags=["User Auth routes"])
BACKEND_ROUTER = APIRouter(tags=["Service-Service (non human account) Auth routes"])


@ROUTER.get("/")
async def root():
    return {"message": "Hello World"}


oauth_2_scheme = OAuth2AuthorizationCodeBearer(
    # The token endpoint is used to obtain tokens.
    tokenUrl=f"{OIDC_BASE_URL}/token",
    # The authorization endpoint performs authentication of the end-user.
    # This authentication is done by redirecting the user agent to this endpoint.
    authorizationUrl=f"{OIDC_BASE_URL}/auth",
    # The token endpoint is also used to obtain new access tokens when they expire.
    refreshUrl=f"{OIDC_BASE_URL}/token",
)


# initial test route which needs auth to view contents
@ROUTER.get("/private", dependencies=[Depends(oauth_2_scheme)])
def read_item():
    return {"message": "If this is visible, you have successfully authenticated."}


@ROUTER.get("/public")
def get_public():
    return {"message": "This endpoint is public"}


@USER_ROUTER.post("/auth-user-pass")
def user_auth(username="sample-user", password="sample-password"):
    token_response = requests.post(
        url=f"{OIDC_BASE_URL}/token",
        data={
            "grant_type": "password",
            "client_id": "confidential-client",
            "client_secret": SECRET_KEY,
            "username": username,
            "password": password,
        },
    )
    access_token = token_response.json()
    return access_token


@BACKEND_ROUTER.post("/auth")
def auth():
    token_response = requests.post(
        url=f"{OIDC_BASE_URL}/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "confidential-client",
            "client_secret": SECRET_KEY,
        },
    )
    access_token = token_response.json()
    return access_token


# Temporarily not using TokenRequest
@BACKEND_ROUTER.post("/verify")
def verify_token(request: Dict[Any, Any]):
    """
    Verify that the JWT token can be decoded using the client credentials.

    :param access_token:
    :return: True or False (temporarily the payload itself)
    """
    access_token = request["access_token"]
    jwks_client = PyJWKClient(JWKS_URL)
    signing_key = jwks_client.get_signing_key_from_jwt(access_token)
    logger.warning("Decoding token without issuer or verifying audience")
    try:
        payload = decode(
            access_token,
            signing_key.key,
            algorithms=["RS256"],
            # invalid issuer
            # issuer="http://{KC_ROOT_URL}:{KC_PORT}/realms/{KC_REALM}",
            aud="confidential-client",
            options={"verify_aud": False},  # temporary insecure bypass
        )
        logger.debug(f"The decoded token {payload}")
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="The access token has expired.")
    return payload


# TODO add logic for refreshing after expiration
@BACKEND_ROUTER.post("/refresh")
def refresh_token(refresh_request: RefreshTokenRequest):
    response = requests.post(
        url=f"{OIDC_BASE_URL}/token",
        data={
            "grant_type": "refresh_token",
            "client_id": "confidential-client",
            "client_secret": SECRET_KEY,
            "refresh_token": refresh_request.refresh_token,
        },
    )
    return response.json()


app.include_router(ROUTER)
app.include_router(BACKEND_ROUTER)
app.include_router(USER_ROUTER)

# uv run fastapi run --port 8008
if __name__ == "__main__":
    uvicorn.run("main:app", port=8000, reload=True, access_log=False)
    uvicorn.run("main:app", port=8000, reload=True, use_colors=True)
