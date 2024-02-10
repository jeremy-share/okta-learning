import hashlib
import os
import time
import uuid
from jwcrypto import jwk

import jwt
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives import serialization
import base64
from jwt.api_jwk import PyJWK


# def base64url_to_int(value):
#     """Converts a Base64URL encoded string to an integer."""
#     padding = '=' * (4 - (len(value) % 4))
#     return int.from_bytes(base64.urlsafe_b64decode(value + padding), 'big')
#

# def jwk_to_pem_2(jwk_dict: dict) -> str:
#
#     private_numbers = rsa.RSAPrivateNumbers(
#         d=base64url_to_int(jwk_dict["d"]),
#         p=base64url_to_int(jwk_dict["p"]),
#         q=base64url_to_int(jwk_dict["q"]),
#         dmp1=base64url_to_int(jwk_dict["dp"]),
#         dmq1=base64url_to_int(jwk_dict["dq"]),
#         iqmp=base64url_to_int(jwk_dict["qi"]),
#         public_numbers=rsa.RSAPublicNumbers(
#             e=base64url_to_int(jwk_dict["e"]),
#             n=base64url_to_int(jwk_dict["n"])
#         )
#     )
#     private_key = private_numbers.private_key(default_backend())
#
#     pem_key = private_key.private_bytes(
#         encoding=serialization.Encoding.PEM,
#         format=serialization.PrivateFormat.PKCS8,
#         encryption_algorithm=serialization.NoEncryption()
#     ).decode("utf-8")
#
#     return pem_key


# def jwk_to_pem(jwk_dict: dict):
#     key = jwk.JWK(**jwk_dict)
#     return key.export_to_pem(private_key=True, password=None).decode('utf-8')


def generate_unique_jwt_id() -> str:
    return str(uuid.uuid4())


def create_signed_jwt(client_id: str, token_endpoint: str, private_key: dict, jwt_id: str) -> str:
    # Convert JWK to PEM
    cert = PyJWK.from_dict(private_key)

    issue_at = int(time.time())

    # This function constructs a JWT and signs it using the private key.

    # Sign the JWT with the RSA private key
    signed_jwt = jwt.encode(
        payload={
            "iss": client_id,
            "sub": client_id,
            "aud": token_endpoint,
            "iat": issue_at,
            "exp": issue_at + 600,  # Token validity, e.g., 5 minutes
            "jti": jwt_id
        },
        key=cert.key,
        algorithm=private_key["alg"],
        headers={
            "kid": private_key["kid"]
        }
    )

    return signed_jwt


async def generate_pkce_code_verifier() -> str:
    return base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8').rstrip("=")


async def generate_pkce_code_challenge(code_verifier: str) -> str:
    sha256 = hashlib.sha256()
    sha256.update(code_verifier.encode('utf-8'))
    return base64.urlsafe_b64encode(sha256.digest()).decode('utf-8').rstrip("=")
