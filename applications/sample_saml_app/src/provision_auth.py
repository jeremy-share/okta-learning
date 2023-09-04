import os
import bcrypt

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

security = HTTPBasic()


class ProvisionAuth:
    def __init__(self):
        self._access_list: dict[str, str] | None = None

    def authenticate(self, credentials: HTTPBasicCredentials = Depends(security)):
        provision_data = self._load_access_list()
        hashed_password = provision_data.get(credentials.username)
        if hashed_password and self._verify_password(credentials.password, hashed_password):
            return credentials.username
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    @staticmethod
    def _verify_password(plain_password: str, hashed_password: str) -> bool:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

    def _load_access_list(self) -> dict[str, str]:
        if not self._access_list:
            self._access_list = {}
            index = 1
            while True:
                credential = os.getenv(f"PROVISION_{index}")
                if not credential:
                    break

                parts = credential.split(":")
                if len(parts) != 2:
                    index += 1
                    raise Exception("Malformed credential!")

                username, password = parts
                self._access_list[username] = password
                index += 1

        return self._access_list
