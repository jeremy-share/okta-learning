import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Type, TypeVar, Generic

logger = logging.getLogger(__name__)


@dataclass
class Provider(ABC):
    pass


T = TypeVar('T', bound=Provider)


class ProviderCollection(ABC, Generic[T]):
    def __init__(self, details_class: Type[T]):
        self.details_class = details_class

    @abstractmethod
    async def add(self, item: T) -> int:
        """Add a new item and return its ID."""
        pass

    @abstractmethod
    async def get_by_id(self, identifier: int) -> T:
        pass

    @abstractmethod
    async def get_all(self) -> Dict[int, T]:
        """Return all items stored."""
        pass


class ProviderCollectionInMemory(ProviderCollection[T]):

    def __init__(self, provider_class: Type[T]):
        super().__init__(provider_class)
        self.memory: Dict[int, T] = {}
        self.lock = asyncio.Lock()
        self._next_id = 0

    async def add(self, item: T) -> int:
        """Add item to the in-memory collection and return the assigned ID."""
        if not isinstance(item, self.details_class):
            raise ValueError(f"Item is not an instance of {self.details_class}")
        async with self.lock:  # Lock the critical section
            index = self._next_id
            self.memory[index] = item
            self._next_id += 1
        return index

    async def get_by_id(self, identifier: int) -> T | None:
        async with self.lock:  # Lock the critical section
            if identifier in self.memory:
                return self.memory[identifier]
        return None

    async def get_all(self) -> Dict[int, T]:
        """Get a copy of all items stored in the in-memory collection."""
        async with self.lock:  # Lock the critical section
            # Return a shallow copy of the memory for safety
            copy = dict(self.memory)
        return copy
