import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Type, TypeVar, Generic
from uuid import UUID, uuid4

logger = logging.getLogger(__name__)


@dataclass
class Provider(ABC):
    id: UUID
    pass


T = TypeVar("T", bound=Provider)


class ProviderCollection(ABC, Generic[T]):
    def __init__(self, details_class: Type[T]):
        self.details_class = details_class

    @staticmethod
    async def generate_id() -> UUID:
        return uuid4()

    @abstractmethod
    async def set(self, identifier: UUID, item: T):
        pass

    @abstractmethod
    async def add(self, item: T) -> UUID:
        pass

    @abstractmethod
    async def get_by_id(self, identifier: UUID) -> T:
        pass

    @abstractmethod
    async def get_all(self) -> Dict[UUID, T]:
        """Return all items stored."""
        pass


class ProviderCollectionInMemory(ProviderCollection[T]):
    def __init__(self, provider_class: Type[T]):
        super().__init__(provider_class)
        self.memory: Dict[UUID, T] = {}
        self.lock = asyncio.Lock()

    async def set(self, identifier: UUID, item: T):
        if not isinstance(item, self.details_class):
            raise ValueError(f"Item is not an instance of {self.details_class}")
        async with self.lock:  # Lock the critical section
            self.memory[identifier] = item

    async def add(self, item: T) -> UUID:
        """Add item to the in-memory collection and return the assigned ID."""
        if not isinstance(item, self.details_class):
            raise ValueError(f"Item is not an instance of {self.details_class}")
        unique_id = await self.generate_id()
        await self.set(unique_id, item)
        return unique_id

    async def get_by_id(self, identifier: UUID) -> T | None:
        async with self.lock:  # Lock the critical section
            if identifier in self.memory:
                return self.memory[identifier]
        return None

    async def get_all(self) -> Dict[UUID, T]:
        """Get a copy of all items stored in the in-memory collection."""
        async with self.lock:  # Lock the critical section
            # Return a shallow copy of the memory for safety
            copy = dict(self.memory)
        return copy

