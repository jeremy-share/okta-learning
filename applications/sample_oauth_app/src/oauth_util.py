import hashlib
import os
import base64


async def generate_pkce_code_verifier() -> str:
    return base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8').rstrip("=")


async def generate_pkce_code_challenge(code_verifier: str) -> str:
    sha256 = hashlib.sha256()
    sha256.update(code_verifier.encode('utf-8'))
    return base64.urlsafe_b64encode(sha256.digest()).decode('utf-8').rstrip("=")
