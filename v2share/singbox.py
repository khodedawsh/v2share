import json
from importlib import resources
from typing import List

from v2share.data import V2Data


class SingBoxConfig:
    def __init__(self, template_path: str = None):
        if not template_path:
            template_path = resources.files("v2share.templates") / "singbox.json"
        with open(template_path) as f:
            self._template_data = f.read()
        self._outbounds = []

    def render(self):
        result = json.loads(self._template_data)
        result["outbounds"].extend(self._outbounds)
        urltest_types = ["vmess", "vless", "trojan", "shadowsocks"]
        urltest_tags = [
            outbound["tag"]
            for outbound in result["outbounds"]
            if outbound["type"] in urltest_types
        ]
        selector_types = ["vmess", "vless", "trojan", "shadowsocks", "urltest"]
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

    def add_proxies(self, proxies: List[V2Data]):
        for data in proxies:
            outbound = {
                "type": data.protocol,
                "tag": data.remark,
                "server": data.address,
                "server_port": data.port,
            }
            if (
                data.protocol == "vless"
                and data.flow
                and data.tls in ["tls", "reality"]
            ):
                outbound["flow"] = data.flow

            if data.transport_type in ["http", "ws", "quic", "grpc", "httpupgrade"]:
                outbound["transport"] = SingBoxConfig.transport_config(
                    transport_type=data.transport_type,
                    host=data.host,
                    path=data.path,
                    headers=data.http_headers,
                )

            if data.tls in ("tls", "reality"):
                outbound["tls"] = SingBoxConfig.tls_config(
                    sni=data.sni,
                    fp=data.fingerprint,
                    tls=data.tls,
                    pbk=data.reality_pbk,
                    sid=data.reality_sid,
                    alpn=data.alpn,
                    ais=data.allow_insecure,
                )

            if data.protocol in ["vless", "vmess"]:
                outbound["uuid"] = str(data.uuid)

            elif data.protocol == "trojan":
                outbound["password"] = data.password

            elif data.protocol == "shadowsocks":
                outbound["password"] = data.password
                outbound["method"] = data.shadowsocks_method

            self._outbounds.append(outbound)
