import random
from importlib import resources
from typing import List, Optional, Dict

import yaml

from v2share.base import BaseConfig
from v2share.data import V2Data
from v2share.exceptions import TransportNotSupportedError, ProtocolNotSupportedError

supported_transports = ["tcp", "http", "ws", "grpc", "h2"]
supported_protocols = ["vmess", "trojan", "shadowsocks"]


class ClashConfig(BaseConfig):
    def __init__(self, template_path: Optional[str] = None, swallow_errors=True):
        if not template_path:
            template_path = resources.files("v2share.templates") / "clash.yml"
        with open(template_path) as f:
            self.template_data = f.read()
        self._swallow_errors = swallow_errors
        self._configs = []

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

    def render(self, sort: bool = True, shuffle: bool = False):
        if shuffle is True:
            configs = random.sample(self._configs, len(self._configs))
        elif sort is True:
            configs = sorted(self._configs, key=lambda config: config.weight)
        else:
            configs = self._configs

        proxies, remarks = [], []
        for proxy in configs:
            proxies.append(self._get_node(proxy))
            remarks.append(proxy.remark)

        result = yaml.safe_load(self.template_data)
        result["proxies"] = proxies
        result["rules"] = []
        result["proxy-groups"][0]["proxies"] = remarks
        return yaml.safe_dump(result, sort_keys=False)

    def _make_node(
        self,
        name: str,
        protocol: str,
        server: str,
        port: int,
        network: str,
        tls: bool,
        sni: str,
        host: str,
        path: str,
        udp: bool = True,
        alpn: str = "",
        ais: bool = "",
    ):
        if protocol == "shadowsocks":
            protocol = "ss"

        node = {
            "name": name,
            "type": protocol,
            "server": server,
            "port": port,
            "network": network,
            f"{network}-opts": {},
            "udp": udp,
        }

        if type == "ss":  # shadowsocks
            return node

        if tls:
            node["tls"] = True
            if type == "trojan":
                node["sni"] = sni
            else:
                node["servername"] = sni
            if alpn:
                node["alpn"] = alpn.split(",")
            if ais:
                node["skip-cert-verify"] = ais

        net_opts = node[f"{network}-opts"]

        if network == "ws":
            if path:
                net_opts["path"] = path
            if host:
                net_opts["headers"] = {"Host": host}

        if network == "grpc":
            if path:
                net_opts["grpc-service-name"] = path

        if network == "h2":
            if path:
                net_opts["path"] = path
            if host:
                net_opts["host"] = [host]

        if network in {"http", "tcp"}:
            if path:
                net_opts["method"] = "GET"
                net_opts["path"] = [path]
            if host:
                net_opts["method"] = "GET"
                net_opts["headers"] = {"Host": host}

        return node

    def _get_node(self, config: V2Data) -> Dict:
        node = self._make_node(
            name=config.remark,
            protocol=config.protocol,
            server=config.address,
            port=config.port,
            network=config.transport_type,
            tls=(config.tls == "tls"),
            sni=config.sni,
            host=config.host,
            path=config.path,
            udp=True,
            alpn=config.alpn,
            ais=config.allow_insecure,
        )

        if config.protocol == "vmess":
            node["uuid"] = str(config.uuid)
            node["alterId"] = 0
            node["cipher"] = "auto"
        elif config.protocol == "trojan":
            node["password"] = config.password
        elif config.protocol == "shadowsocks":
            node["password"] = config.password
            node["cipher"] = config.shadowsocks_method

        return node
