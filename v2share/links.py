import random
from typing import List

from v2share.base import BaseConfig
from v2share.data import V2Data
from v2share.exceptions import TransportNotSupportedError, ProtocolNotSupportedError

supported_transports = [
    "tcp",
    "kcp",
    "ws",
    "http",
    "quic",
    "grpc",
    "httpupgrade",
    "splithttp",
    None,
]
supported_protocols = ["vmess", "vless", "trojan", "shadowsocks", "hysteria2", "wireguard"]


class LinksConfig(BaseConfig):
    def __init__(self, swallow_errors=True):
        self._configs: List[V2Data] = []
        self._swallow_errors = swallow_errors

    def render(self, sort: bool = True, shuffle: bool = False):
        if shuffle is True:
            configs = random.sample(self._configs, len(self._configs))
        elif sort is True:
            configs = sorted(self._configs, key=lambda config: config.weight)
        else:
            configs = self._configs

        links = [config.to_link() for config in configs]
        return "\n".join(links)

    def add_proxies(self, proxies: List[V2Data]):
        for proxy in proxies:
            # validation
            if (
                unsupported_transport := proxy.transport_type
                not in supported_transports
            ) or (unsupported_protocol := proxy.protocol not in supported_protocols):
                if self._swallow_errors:
                    continue
                if unsupported_transport:
                    raise TransportNotSupportedError
                if unsupported_protocol:
                    raise ProtocolNotSupportedError

            self._configs.append(proxy)
