import asyncio
import json
import logging
import os
import pprint
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass
import requests

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form, Response, Depends
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from src.oauth_util import create_signed_jwt, generate_pkce_code_verifier, generate_pkce_code_challenge, \
    generate_unique_jwt_id
from src.providers import ProviderCollectionInMemory, Provider
from src.session import SessionCollectionInMemory, SessionDetails, SessionCollection
from src.provision_auth import ProvisionAuth
from src.oauth_client_authentication import ClientAuthentication, ClientAuthenticationNone, \
    ClientAuthenticationClientSecret, ClientAuthenticationKeys

logger = logging.getLogger(__name__)

load_dotenv()

LOG_LEVEL = os.getenv("LOG_LEVEL", "info").lower()
logging.basicConfig(level=LOG_LEVEL.upper())

RUN_HOST = os.getenv("RUN_HOST", "0.0.0.0")
RUN_PORT = os.getenv("RUN_PORT", "8080")

RELOAD = os.getenv("RELOAD", "false").lower() in ["true", "t", "y", "yes"]
ROOT_DIR = os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/..")

OAUTH_SCOPES = ["okta.users.read.self"]
# OAUTH_SCOPES = ["okta.groups.manage"]
OAUTH_SCOPES_STR = " ".join(OAUTH_SCOPES)


@dataclass
class OauthProvider(Provider):
    name: str
    client_id: str
    okta_domain: str  # https://dev-123.okta.com
    authorize_uri: str  # https://dev-123.okta.com/oauth2/v1/authorize
    token_uri: str  # https://dev-123.okta.com/oauth2/v1/token
    redirect_uri: str  # http://localhost:8080/callback
    pkce_enabled: bool = False
    client_auth: ClientAuthentication | None = None


@dataclass
class OauthSessionDetails(SessionDetails):
    oauth_code_verifier: str | None = None
    provider_id: int | None = None
    access_token: str | None = None
    logged_in: bool = False


app = FastAPI()
provision_auth = ProvisionAuth()
providers = ProviderCollectionInMemory(OauthProvider)
sessions = SessionCollection(SessionCollectionInMemory(session_class=OauthSessionDetails))
templates = Jinja2Templates(directory=f"{ROOT_DIR}/templates")
templates.env.filters["pprint"] = lambda value: pprint.pformat(value, width=1)
templates.env.globals["title"] = "Sample Oauth APP"


async def get_user_details(session: OauthSessionDetails) -> dict:
    if not session.logged_in:
        return defaultdict(str)

    try:
        provider: OauthProvider = await providers.get_by_id(session.provider_id)

        response = requests.get(f"{provider.okta_domain}/api/v1/users/me", headers={
            "Authorization": f"Bearer {session.access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        })
        response.raise_for_status()
        result = response.json()
        return result["profile"]
    except Exception as e:
        return {
            "error": str(e)
        }


@app.post("/")
@app.get("/")
async def root(request: Request, response: Response):
    session = await sessions.get_request_session(request, response)
    user_details = await get_user_details(session)
    return templates.TemplateResponse("homepage.html", {
        "request": request,
        "user_details": user_details,
        "session": session,
        "providers": await providers.get_all()
    })


@app.get("/provision")
async def get_provision_form(request: Request, username: str = Depends(provision_auth.authenticate)):
    logger.info(f"Provision accessed by {username=}")
    return templates.TemplateResponse("provision.html", {"request": request})


@app.post("/provision")
async def post_provision_details(
    username: str = Depends(provision_auth.authenticate),
    name: str = Form(...),
    client_id: str = Form(...),
    okta_domain: str = Form(...),
    authorize_uri: str = Form(...),
    token_uri: str = Form(...),
    redirect_uri: str = Form(...),
    pkce: bool = Form(False),
    client_authentication: str = Form("none"),
    client_secret: str = Form(""),
    private_key: str = Form(""),
    public_key: str = Form(""),
):
    logger.info(f"Provider added by {username=}")
    # Create a new instance with the form data
    client_auth = ClientAuthenticationNone()
    if client_authentication == "ClientSecret":
        client_auth = ClientAuthenticationClientSecret(client_secret=client_secret)
    if client_authentication == "Keys":
        client_auth = ClientAuthenticationKeys(public_key=public_key, private_key=private_key)
    provider = OauthProvider(
        name=name,
        client_id=client_id,
        okta_domain=okta_domain,
        authorize_uri=authorize_uri,
        token_uri=token_uri,
        redirect_uri=redirect_uri,
        pkce_enabled=pkce,
        client_auth=client_auth
    )
    await providers.add(provider)
    return RedirectResponse(url="/?success=added_provider")


@app.get("/login/{provider_id}")
async def login(request: Request, response: Response, provider_id: int):
    logging.info(f"Login for {provider_id=}")

    provider: OauthProvider = await providers.get_by_id(provider_id)
    if provider is None:
        return RedirectResponse("/?error=provider_not_found")
    logging.info(f"Login to {provider.name=}")

    session: OauthSessionDetails = await sessions.get_request_session(request, response)

    session.provider_id = provider_id

    redirect_params = {
        "client_id": provider.client_id,
        "response_type": "code",
        "scope": OAUTH_SCOPES_STR,
        "redirect_uri": provider.redirect_uri,
        "state": "state",  # Replace with a proper state value
    }

    if provider.pkce_enabled:
        session.oauth_code_verifier = await generate_pkce_code_verifier()
        redirect_params["code_challenge"] = await generate_pkce_code_challenge(session.oauth_code_verifier)
        redirect_params["code_challenge_method"] = "S256"

    return RedirectResponse(url=f"{provider.authorize_uri}?{urllib.parse.urlencode(redirect_params)}")


@app.post("/callback")
@app.get("/callback")
@app.get("/callback/{provider_index}")
async def callback(request: Request, response: Response, provider_index=None):
    session: OauthSessionDetails = await sessions.get_request_session(request, response)
    if not session:
        return RedirectResponse(url="/?error=no-session")

    if provider_index is None:
        provider_index = session.provider_id

    provider: OauthProvider = await providers.get_by_id(provider_index)
    if provider is None:
        return RedirectResponse("/?error=provider_not_found")

    request_parameters = dict(request.query_params.items())

    token_data = {
        "redirect_uri": provider.redirect_uri,
        "client_id": provider.client_id,
        "code": request_parameters["code"],
        "grant_type": "authorization_code"
    }
    token_headers = {}

    if provider.pkce_enabled:
        token_data["code_verifier"] = session.oauth_code_verifier

    if isinstance(provider.client_auth, ClientAuthenticationClientSecret):
        token_data["client_secret"] = provider.client_auth.client_secret

    if isinstance(provider.client_auth, ClientAuthenticationKeys):
        private_key = json.loads(provider.client_auth.private_key)
        client_assertion = create_signed_jwt(
            client_id=provider.client_id,
            token_endpoint=provider.token_uri,
            private_key=private_key,
            jwt_id=generate_unique_jwt_id()
        )
        token_data["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        token_data["client_assertion"] = client_assertion
        token_headers["alg"] = private_key["alg"]
        token_headers["kid"] = private_key["kid"]
        token_headers["typ"] = "JWT"

    # Exchange the authorization code for an access token
    response = requests.post(provider.token_uri, data=token_data, headers=token_headers)
    response.raise_for_status()
    token_details = response.json()
    session.access_token = token_details["access_token"]
    session.logged_in = True
    return RedirectResponse(url="/?success=login")


@app.get("/logout")
async def logout(request: Request):
    await sessions.delete_request_session(request)
    return RedirectResponse(url="/?success=logged-out")


async def start_app():
    asyncio.create_task(sessions.clear_expired_sessions())
    config = uvicorn.Config("src.main:app", host=RUN_HOST, port=int(RUN_PORT), log_level=LOG_LEVEL, reload=RELOAD)
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(start_app())
