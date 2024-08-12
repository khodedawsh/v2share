import json
import random
from importlib import resources
from typing import List

from v2share.base import BaseConfig
from v2share.data import V2Data
from v2share.exceptions import ProtocolNotSupportedError, TransportNotSupportedError

supported_protocols = ["shadowsocks", "vmess", "trojan", "vless", "hysteria2"]
supported_transports = ["tcp", "ws", "quic", "httpupgrade", "grpc", None]


class SingBoxConfig(BaseConfig):
    def __init__(self, template_path: str = None, swallow_errors=True):
        if not template_path:
            template_path = resources.files("v2share.templates") / "singbox.json"
        with open(template_path) as f:
            self._template_data = f.read()
        self._outbounds = []
        self._swallow_errors = swallow_errors
        self._configs: List[V2Data] = []

    def render(self, sort: bool = True, shuffle: bool = False):
        if shuffle is True:
            configs = random.sample(self._configs, len(self._configs))
        elif sort is True:
            configs = sorted(self._configs, key=lambda config: config.weight)
        else:
            configs = self._configs

        result = json.loads(self._template_data)
        result["outbounds"].extend([self.create_outbound(config) for config in configs])

        urltest_types = ["hysteria2", "vmess", "vless", "trojan", "shadowsocks"]
        urltest_tags = [
            outbound["tag"]
            for outbound in result["outbounds"]
            if outbound["type"] in urltest_types
        ]
        selector_types = [
            "hysteria2",
            "vmess",
            "vless",
            "trojan",
            "shadowsocks",
            "urltest",
        ]
        selector_tags = [
            outbound["tag"]
            for outbound in result["outbounds"]
            if outbound["type"] in selector_types
        ]

        for outbound in result["outbounds"]:
            if outbound.get("type") == "urltest":
                outbound["outbounds"] = urltest_tags

        for outbound in result["outbounds"]:
            if outbound.get("type") == "selector":
                outbound["outbounds"] = selector_tags

        return json.dumps(result, indent=4)

    @staticmethod
    def tls_config(
        sni=None, fp=None, tls=None, pbk=None, sid=None, alpn=None, ais=None
    ):
        config = {}
        if tls in ["tls", "reality"]:
            config["enabled"] = True

        if sni is not None:
            config["server_name"] = sni

        if tls == "tls" and ais:
            config["insecure"] = ais

        if tls == "reality":
            config["reality"] = {"enabled": True}
            if pbk:
                config["reality"]["public_key"] = pbk
            if sid:
                config["reality"]["short_id"] = sid

        if fp:
            config["utls"] = {"enabled": True, "fingerprint": fp}

        if alpn:
            config["alpn"] = [alpn] if not isinstance(alpn, list) else alpn

        return config

    @staticmethod
    def transport_config(
        transport_type="http",
        host=None,
        path=None,
        http_method=None,
        headers=None,
    ):
        if headers is None:
            headers = {}

        transport_config = {"type": transport_type}

        if transport_type == "http":
            transport_config["headers"] = headers
            if host:
                transport_config["host"] = host
            if path:
                transport_config["path"] = path
            if http_method:
                transport_config["method"] = http_method
        elif transport_type == "ws":
            transport_config["headers"] = headers
            if path:
                if "?ed=" in path:
                    path, max_early_data = path.split("?ed=")
                    max_early_data = int(max_early_data)
                    transport_config["early_data_header_name"] = (
                        "Sec-WebSocket-Protocol"
                    )
                    transport_config["max_early_data"] = max_early_data
                transport_config["path"] = path
            if host:
                transport_config["headers"]["Host"] = host
        elif transport_type == "httpupgrade":
            transport_config["headers"] = headers
            if host:
                transport_config["host"] = host
            if path:
                transport_config["path"] = path
        elif transport_type == "grpc":
            if path:
                transport_config["service_name"] = path

        return transport_config

    @staticmethod
    def create_outbound(config: V2Data):
        outbound = {
            "type": config.protocol,
            "tag": config.remark,
            "server": config.address,
            "server_port": config.port,
        }
        if (
            config.protocol == "vless"
            and config.flow
            and config.tls in ["tls", "reality"]
        ):
            outbound["flow"] = config.flow

        if config.transport_type in ["http", "ws", "quic", "grpc", "httpupgrade"]:
            outbound["transport"] = SingBoxConfig.transport_config(
                transport_type=config.transport_type,
                host=config.host,
                path=config.path,
                headers=config.http_headers,
            )

        if config.tls in ("tls", "reality"):
            outbound["tls"] = SingBoxConfig.tls_config(
                sni=config.sni,
                fp=config.fingerprint,
                tls=config.tls,
                pbk=config.reality_pbk,
                sid=config.reality_sid,
                alpn=config.alpn,
                ais=config.allow_insecure,
            )

        if config.protocol in ["vless", "vmess"]:
            outbound["uuid"] = str(config.uuid)

        elif config.protocol == "trojan":
            outbound["password"] = config.password

        elif config.protocol == "shadowsocks":
            outbound["password"] = config.password
            outbound["method"] = config.shadowsocks_method
        elif config.protocol == "hysteria2":
            outbound["password"] = config.password
            if config.header_type:
                outbound["obfs"] = {"type": config.header_type, "password": config.path}
        return outbound

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
