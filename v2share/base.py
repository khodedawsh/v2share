from abc import ABC, abstractmethod
from typing import List

from .data import V2Data


class BaseConfig(ABC):
    @abstractmethod
    def render(self, sort: bool, shuffle: bool) -> str:
        pass

    @abstractmethod
    def add_proxies(self, proxies: List[V2Data]) -> None:
        pass
