import json
from typing import List

from v2share import V2Data
from v2share.base import BaseConfig
from v2share.exceptions import TransportNotSupportedError, ProtocolNotSupportedError

supported_protocols = ["wireguard"]
supported_transports = [None]


class WireGuardConfig(BaseConfig):
    def __init__(self, swallow_errors=True):
        self._swallow_errors = swallow_errors
        self._configs: List[V2Data] = []

    def render(self, sort: bool, shuffle: bool) -> str:
        result = []
        for proxy in self._configs:
            config = "[Interface]\nAddress = " + proxy.client_address + "\n"
            config += "PrivateKey = " + proxy.ed25519 + "\n"
            if proxy.mtu is not None:
                config += "MTU = " + str(proxy.mtu) + "\n"
            if proxy.dns_servers:
                config += "DNS = " + ",".join(proxy.dns_servers) + "\n"
            config += "\n"
            config += "[Peer]\nPublicKey = " + proxy.path + "\n"
            config += "Endpoint = " + proxy.address + ":" + str(proxy.port) + "\n"
            config += "AllowedIPs = "
            if not proxy.allowed_ips:
                config += "0.0.0.0/0, ::/0" + "\n"
            else:
                config += ", ".join(proxy.allowed_ips) + "\n"
            config += "PersistentKeepalive = 25\n"
            result.append({"remark": proxy.remark, "config": config})
        return json.dumps(result)

    def add_proxies(self, proxies: List[V2Data]) -> None:
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
