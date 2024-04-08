import json
import os
import uuid
from typing import Any

from dotenv import load_dotenv
import jwt
import requests
from jwt.api_jwk import PyJWK
import time
import logging


root_dir = os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/.")
load_dotenv(dotenv_path=f"{root_dir}/.env")

logger = logging.getLogger(__name__)

LOG_LEVEL = os.getenv("LOG_LEVEL", "info").lower()
logging.basicConfig(level=LOG_LEVEL.upper())


def create_signed_jwt(client_id: str, endpoint: str, private_key: dict, jwt_id: str) -> str:
    # This function constructs a JWT and signs it using the private key.
    cert = PyJWK.from_dict(private_key)

    issue_at = int(time.time())

    # Sign the JWT with the RSA private key
    signed_jwt = jwt.encode(
        payload={
            "iss": client_id,
            "sub": client_id,
            "aud": endpoint,
            "iat": issue_at,
            "exp": issue_at + 600,  # Token validity, e.g., 5 minutes
            "jti": jwt_id
        },
        key=cert.key,
        algorithm=private_key.get("alg", "RS256"),
        headers={
            "kid": private_key["kid"]
        }
    )

    return signed_jwt


def generate_unique_jwt_id() -> str:
    return str(uuid.uuid4())


def get_jwk() -> dict[str, Any]:
    with open("private-key.json") as fp:
        return json.load(fp)


def request_asserted(
    okta_client_id: str,
    jwk: dict[str, Any],
    method: str,
    url: str,
    data: dict[str, Any],
    headers: dict[str, Any] = None,
    **kwargs
) -> requests.Response:
    headers = {} if headers is None else headers
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    data["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    data["client_assertion"] = create_signed_jwt(
        client_id=okta_client_id,
        endpoint=url,
        private_key=jwk,
        jwt_id=generate_unique_jwt_id()
    )
    return requests.request(method, url, data=data, headers=headers, **kwargs)


def main() -> None:
    okta_domain = f"https://{os.getenv('OKTA_ORG_NAME')}.{os.getenv('OKTA_BASE_URL')}"
    okta_client_id = os.getenv("AUTH_OKTA_CLIENT_ID")
    okta_scopes = os.getenv("AUTH_OKTA_SCOPES", "").split(",")
    jwk = get_jwk()

    token_response = request_asserted(
        okta_client_id,
        jwk,
        "post",
        f"{okta_domain}/oauth2/v1/token",
        data={
            "grant_type": "client_credentials",
            "scope":  " ".join(okta_scopes),
        }
    )
    token_response.raise_for_status()

    access_token = token_response.json().get("access_token")
    logger.info(f"\nOKTA_ACCESS_TOKEN={access_token}\n")

    input("Press Enter to revoke the access token...")

    revocation_response = request_asserted(
        okta_client_id,
        jwk,
        "post",
        f"{okta_domain}/oauth2/v1/revoke",
        data={
            "token": access_token,
            "token_type_hint": "access_token",
        },
    )
    revocation_response.raise_for_status()
    logger.info("Token revoked")
    logger.info("")
    logger.info("FINISHED!")


if __name__ == "__main__":
    main()
