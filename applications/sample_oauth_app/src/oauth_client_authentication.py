from abc import ABC, abstractmethod

from dataclasses import dataclass
from typing import TypeVar


@dataclass
class ClientAuthentication(ABC):
    @abstractmethod
    def get_name(self) -> str:
        pass


ClientAuthenticationType = TypeVar('ClientAuthenticationType', bound=ClientAuthentication)


@dataclass
class ClientAuthenticationNone(ClientAuthentication):
    def get_name(self) -> str:
        return "none"


@dataclass
class ClientAuthenticationClientSecret(ClientAuthentication):
    client_secret: str

    def get_name(self) -> str:
        return "client secret"


@dataclass
class ClientAuthenticationKeys(ClientAuthentication):
    private_key: str
    public_key: str

    def get_name(self) -> str:
        return "keys"
