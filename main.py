from __future__ import annotations

from typing import Annotated

import jwt
import uvicorn
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.security import OAuth2AuthorizationCodeBearer
from jwt import PyJWKClient  # from pyjwt

KC_ROOT_URL = "http://localhost"
KC_PORT = "8080"
KC_REALM = "UKAEA"
OIDC_BASE_URL = f"{KC_ROOT_URL}:{KC_PORT}/realms/{KC_REALM}/protocol/openid-connect"

app = FastAPI()

ROUTER = APIRouter(tags=["example AUTH routes"])


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


async def valid_access_token(access_token: Annotated[str, Depends(oauth_2_scheme)]):
    url = f"{OIDC_BASE_URL}/certs"
    optional_custom_headers = {"User-agent": "custom-user-agent"}
    jwks_client = PyJWKClient(url, headers=optional_custom_headers)
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(access_token)
        data = jwt.decode(
            access_token,
            signing_key.key,
            algorithms=["RS256"],
            audience="confidential-client",
            options={"verify_exp": True},
        )
        return data
    except jwt.exceptions.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Not authenticated")


# initial test route which needs auth to view contents
@ROUTER.get("/private", dependencies=[Depends(oauth_2_scheme)])
def read_item():
    return {"message": "If this is visible, you have successfully authenticated."}


@ROUTER.get("/public")
def get_public():
    return {"message": "This endpoint is public"}


app.include_router(ROUTER)

# uv run fastapi run --port 8008
if __name__ == "__main__":
    uvicorn.run("main:app", port=8000, reload=True, access_log=False)
