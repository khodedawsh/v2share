from typing import List

from v2share.base import BaseConfig
from v2share.data import V2Data
from v2share.exceptions import NotSupportedError


class LinksConfig(BaseConfig):
    def __init__(self, swallow_errors=True):
        self._links = []
        self._swallow_errors = swallow_errors

    def render(self):
        return "\n".join(self._links)

    def add_proxies(self, proxies: List[V2Data]):
        for proxy in proxies:
            try:
                self._links.append(proxy.to_link())
            except NotSupportedError:
                if self._swallow_errors:
                    continue
                raise
