import logging
import os
import secrets

from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from typing import Type, TypeVar, Generic, List
from src.time_unit import unixtime

from fastapi import Request, Response

logger = logging.getLogger(__name__)


@dataclass
class SessionDetails(ABC):
    pass


async def has_session_expired(last_access: int, session_max_age: int) -> bool:
    return (unixtime() - last_access) > session_max_age


SessionDetailsType = TypeVar("SessionDetailsType", bound=SessionDetails)


class SessionPersistence(ABC, Generic[SessionDetailsType]):
    def __init__(self, session_class: Type[SessionDetailsType]):
        self.session_class = session_class
        self.session_max_age = int(os.getenv("SESSION_MAX_AGE", 3600))

    @abstractmethod
    async def get(self, key: str) -> SessionDetailsType | None:
        pass

    @abstractmethod
    async def get_expired(self) -> List[SessionDetailsType]:
        pass

    @abstractmethod
    async def delete(self, key: str) -> None:
        pass

    @abstractmethod
    async def update_last_access(self, key: str) -> None:
        pass


@dataclass
class SessionCollectionInMemoryStructure(Generic[SessionDetailsType]):
    last_access: int
    details: Generic[SessionDetailsType]


class SessionCollectionInMemory(SessionPersistence):

    def __init__(self, session_class: Type[SessionDetailsType]):
        super().__init__(session_class)
        self.sessions: dict[str, SessionCollectionInMemoryStructure] = defaultdict(
            lambda: SessionCollectionInMemoryStructure(last_access=unixtime(), details=self.session_class())
        )

    async def get(self, key: str) -> SessionDetailsType:
        return self.sessions.get(key).details

    async def get_expired(self) -> List[str]:
        expired_session_keys = []
        for cookie_value, last_access, session_details in self.sessions.items():
            if has_session_expired(last_access, self.session_max_age):
                expired_session_keys.append(cookie_value)
        return expired_session_keys

    async def delete(self, key: str) -> None:
        if key in self.sessions:
            del self.sessions[key]

    async def update_last_access(self, key: str) -> None:
        self.sessions[key].last_access = unixtime()


class SessionCollection(Generic[SessionDetailsType]):

    def __init__(self, session_persistence: SessionPersistence):
        self.session_persistence = session_persistence
        self.session_cookie = str(os.getenv("SESSION_COOKIE", "access_token"))
        self.session_expiration_lookup = int(os.getenv("SESSION_EXPIRATION_LOOKUP", 60))

    async def get(self, session_key: str) -> SessionDetailsType:
        await self.session_persistence.update_last_access(session_key)
        return await self.session_persistence.get(session_key)

    async def delete(self, session_key: str) -> None:
        await self.session_persistence.delete(session_key)

    async def clear_expired_sessions(self):
        for key in await self.session_persistence.get_expired():
            logger.info(f"Clearing expired session Key")
            await self.session_persistence.delete(key)

    async def get_request_session_key(self, request: Request) -> str:
        session_key = str(request.cookies.get(self.session_cookie))
        if not session_key:
            session_key = secrets.token_urlsafe()
        return session_key

    async def get_request_session(self, request: Request, response: Response) -> SessionDetailsType:
        session_key = await self.get_request_session_key(request)
        response.set_cookie(key=self.session_cookie, value=session_key, httponly=True)
        return await self.get(session_key)

    async def delete_request_session(self, request: Request) -> None:
        await self.delete(await self.get_request_session_key(request))
