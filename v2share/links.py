from typing import List

from v2share.base import BaseConfig
from v2share.data import V2Data


class LinksConfig(BaseConfig):
    def __init__(self):
        self._links = []

    def render(self):
        return "\n".join(self._links)

    def add_proxies(self, proxies: List[V2Data]):
        for proxy in proxies:
            self._links.append(proxy.to_link())
