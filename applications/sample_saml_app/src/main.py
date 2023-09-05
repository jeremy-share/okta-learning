import os
from os import getenv
from uuid import UUID

from fastapi import FastAPI, Request, HTTPException, Depends, Form
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from dotenv import load_dotenv
import uvicorn
import logging
from fastapi.responses import Response
from onelogin.saml2.metadata import OneLogin_Saml2_Metadata
import asyncio
import pprint
from dataclasses import dataclass, field

from src.providers import Provider, ProviderCollectionInMemory
from src.provision_auth import ProvisionAuth
from src.session import SessionDetails, SessionCollection, SessionCollectionInMemory

logger = logging.getLogger(__name__)

load_dotenv()

BOOL_TRUE_OPTS = ["true", "t", "y", "yes"]

LOG_LEVEL = getenv("LOG_LEVEL", "info").lower()
logging.basicConfig(level=LOG_LEVEL.upper())

RUN_HOST = getenv("RUN_HOST", "0.0.0.0")
RUN_PORT = getenv("RUN_PORT", "8080")
URL_PREFIX = getenv("URL_PREFIX", f"http://{RUN_HOST}:{RUN_PORT}")

RELOAD = getenv("RELOAD", "false").lower() in BOOL_TRUE_OPTS
ROOT_DIR = os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/..")


@dataclass
class SamlProvider(Provider):
    name: str = ""
    strict: bool = False
    debug: bool = False
    sp_url: str = ""
    sp_x509cert: str = ""
    sp_private_key: str = ""
    idp_entity_id: str = ""  # your_idp_entity_id
    idp_single_sign_on_service_url: str = ""  # your_sso_url
    idp_single_logout_service_url: str = ""  # your_slo_url
    idp_x509cert: str = ""


@dataclass
class SamlSessionDetails(SessionDetails):
    provider_id: UUID | None = None
    logged_in: bool = False
    saml_name_id: str = ""
    saml_name_id_format: str = ""
    saml_name_id_nq: str = ""
    saml_name_id_spnq: str = ""
    saml_session_index: str = ""
    saml_session_expiration: str = ""
    saml_attributes: dict = field(default_factory=dict)
    saml_attributes_friendly_names: dict = field(default_factory=dict)

    def set_from_auth(self, auth: OneLogin_Saml2_Auth):
        self.saml_name_id = auth.get_nameid()
        self.saml_name_id_format = auth.get_nameid_format()
        self.saml_name_id_nq = auth.get_nameid_nq()
        self.saml_name_id_spnq = auth.get_nameid_spnq()
        self.saml_session_index = auth.get_session_index()
        self.saml_session_expiration = auth.get_session_expiration()
        self.saml_attributes = auth.get_attributes()
        self.saml_attributes_friendly_names = auth.get_friendlyname_attributes()


def build_saml_settings(provider: SamlProvider) -> dict:
    return {
        "strict": provider.strict,
        "debug": provider.debug,
        "sp": {
            "entityId": f"{provider.sp_url}/metadata/{provider.id}",
            "assertionConsumerService": {
                "url": f"{provider.sp_url}/acs/{provider.id}",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": f"{provider.sp_url}/sls/{provider.id}",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            "x509cert": provider.sp_x509cert,
            "privateKey": provider.sp_private_key,
        },
        "idp": {
            "entityId": provider.idp_entity_id,
            "singleSignOnService": {
                "url": provider.idp_single_sign_on_service_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": provider.idp_single_logout_service_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": provider.idp_x509cert,
        },
    }


app = FastAPI()
provision_auth = ProvisionAuth()
providers = ProviderCollectionInMemory(SamlProvider)
sessions = SessionCollection(
    SessionCollectionInMemory(session_class=SamlSessionDetails)
)
templates = Jinja2Templates(directory=f"{ROOT_DIR}/templates")
templates.env.filters["pprint"] = lambda value: pprint.pformat(value)
templates.env.globals["title"] = "Sample SAML APP"


async def init_saml_auth(
    request: Request, provider: SamlProvider
) -> OneLogin_Saml2_Auth:
    details = {
        "https": "on" if request.url.scheme == "https" else "off",
        "http_host": request.client.host,
        "server_port": request.url.port,
        "script_name": request.url.path,
        "get_data": dict(request.query_params),
        "post_data": await request.form(),
    }
    return OneLogin_Saml2_Auth(details, build_saml_settings(provider))


@app.post("/")
@app.get("/")
async def root(request: Request, response: Response):
    session = await sessions.get_request_session(request, response)
    return templates.TemplateResponse(
        "homepage.html",
        {
            "request": request,
            "session": session,
            "providers": await providers.get_all(),
        },
    )


@app.get("/metadata/{provider_id}")
async def metadata(request: Request, provider_id: UUID):
    provider = await providers.get_by_id(provider_id)
    saml_auth = await init_saml_auth(request, provider)
    sp_settings = saml_auth.get_settings().get_sp_data()
    metadata_content = OneLogin_Saml2_Metadata.builder(sp_settings)
    response = Response(content=metadata_content, media_type="application/xml")
    response.headers["Content-Disposition"] = "attachment; filename=metadata.xml"
    return response


@app.get("/login/{provider_id}")
@app.get("/sso/{provider_id}")
async def sso(request: Request, provider_id: UUID):
    provider = await providers.get_by_id(provider_id)
    saml_auth = await init_saml_auth(request, provider)
    return RedirectResponse(url=saml_auth.login())
    #     return RedirectResponse(url=get_saml_settings()["idp"]["singleSignOnService"]["url"])


@app.get("/logout/{provider_id}")
@app.get("/slo/{provider_id}")
async def slo(request: Request, provider_id: UUID):
    provider = await providers.get_by_id(provider_id)
    saml_auth = await init_saml_auth(request, provider)
    saml_auth.logout()
    await sessions.delete_request_session(request)
    return RedirectResponse(url=saml_auth.logout(return_to="/"))
    # return RedirectResponse(url=get_saml_settings()["idp"]["singleSignOnService"]["url"])


@app.get("/acs/{provider_id}")
@app.post("/acs/{provider_id}")
async def acs(request: Request, response: Response, provider_id: UUID):
    provider = await providers.get_by_id(provider_id)
    saml_auth = await init_saml_auth(request, provider)
    saml_auth.process_response()
    errors = saml_auth.get_errors()
    if not errors:
        if saml_auth.is_authenticated():
            await sessions.get_request_session(request, response)
            return RedirectResponse("/?loginSuccess=true")
        else:
            raise HTTPException(status_code=401, detail="Not authenticated")
    else:
        logger.error(f"SAML authentication error: {', '.join(errors)}")
        raise HTTPException(
            status_code=400, detail=f"SAML authentication error: {', '.join(errors)}"
        )


@app.get("/provision")
async def get_provision_form(
    request: Request, username: str = Depends(provision_auth.authenticate)
):
    logger.info(f"Provision accessed by {username=}")
    return templates.TemplateResponse(
        "provision.html",
        {"request": request},
    )


@app.post("/provision")
async def post_provision_details(
    username: str = Depends(provision_auth.authenticate),
    provider_id: UUID = Form(...),
    name: str = Form(...),
    strict: bool = Form(False),
    debug: bool = Form(False),
    sp_url: str = Form(False),
    sp_x509cert: str = Form(False),
    sp_private_key: str = Form(False),
    idp_entity_id: str = Form(False),
    idp_single_sign_on_service_url: str = Form(False),
    idp_single_logout_service_url: str = Form(False),
    idp_x509cert: str = Form(False),
):
    logger.info(f"Provider added by {username=}")
    provider = SamlProvider(
        id=provider_id,
        name=name,
        strict=strict,
        debug=debug,
        sp_url=sp_url,
        sp_x509cert=sp_x509cert,
        sp_private_key=sp_private_key,
        idp_entity_id=idp_entity_id,
        idp_single_sign_on_service_url=idp_single_sign_on_service_url,
        idp_single_logout_service_url=idp_single_logout_service_url,
        idp_x509cert=idp_x509cert,
    )
    await providers.set(provider_id, provider)
    return RedirectResponse(url="/?success=added_provider")


@app.get("/logout")
async def logout(request: Request):
    await sessions.delete_request_session(request)
    return RedirectResponse(url="/?success=logged-out")


async def start_app():
    asyncio.create_task(sessions.clear_expired_sessions())
    config = uvicorn.Config(
        "src.main:app",
        host=RUN_HOST,
        port=int(RUN_PORT),
        log_level=LOG_LEVEL,
        reload=RELOAD,
    )
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(start_app())
