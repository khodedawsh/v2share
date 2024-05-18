import json
from importlib import resources
from typing import List

from v2share.data import V2Data


class SingBoxConfig(str):
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
        transport_type="",
        host="",
        path="",
        method="",
        headers={},
        idle_timeout="15s",
        ping_timeout="15s",
        permit_without_stream=False,
    ):
        transport_config = {}

        if transport_type:
            transport_config["type"] = transport_type

            if transport_type == "http":
                if host:
                    transport_config["host"] = host
                if path:
                    transport_config["path"] = path
                if method:
                    transport_config["method"] = method
                if headers:
                    transport_config["headers"] = headers
                if idle_timeout:
                    transport_config["idle_timeout"] = idle_timeout
                if ping_timeout:
                    transport_config["ping_timeout"] = ping_timeout

            elif transport_type == "ws":
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
                    headers.update({"Host": host})
                if headers:
                    transport_config["headers"] = headers

            elif transport_type == "grpc":
                if path:
                    transport_config["service_name"] = path
                if idle_timeout:
                    transport_config["idle_timeout"] = idle_timeout
                if ping_timeout:
                    transport_config["ping_timeout"] = ping_timeout
                if permit_without_stream:
                    transport_config["permit_without_stream"] = permit_without_stream

            elif transport_type == "httpupgrade":
                if host:
                    transport_config["host"] = host
                if path:
                    transport_config["path"] = path
                if headers:
                    transport_config["headers"] = headers
        return transport_config

    @staticmethod
    def make_outbound(
        type: str,
        remark: str,
        address: str,
        port: int,
        net="ws",
        path="",
        host="",
        flow="",
        tls="",
        sni="",
        fp="",
        alpn="",
        pbk="",
        sid="",
        header_type="",
        headers={},
        ais=False,
    ):
        config = {
            "type": type,
            "tag": remark,
            "server": address,
            "server_port": port,
        }
        if flow and type == "vless":
            config["flow"] = flow

        if net in ["http", "ws", "quic", "grpc", "httpupgrade"]:
            config["transport"] = SingBoxConfig.transport_config(
                transport_type=net, host=host, path=path, headers=headers
            )
        else:
            config["network"] = net

        if tls in ("tls", "reality"):
            config["tls"] = SingBoxConfig.tls_config(
                sni=sni, fp=fp, tls=tls, pbk=pbk, sid=sid, alpn=alpn, ais=ais
            )

        return config

    def add_proxies(self, proxies: List[V2Data]):
        for config in proxies:
            outbound = self.make_outbound(
                remark=config.remark,
                type=config.protocol,
                address=config.address,
                port=config.port,
                net=config.transport_type,
                tls=config.tls,
                flow=config.flow,
                sni=config.sni,
                host=config.host,
                path=config.path,
                alpn=config.alpn,
                fp=config.fingerprint,
                pbk=config.reality_pbk,
                sid=config.reality_sid,
                header_type=config.header_type,
                headers={},
                ais=config.allow_insecure,
            )

            if config.protocol in ["vless", "vmess"]:
                outbound["uuid"] = str(config.uuid)

            elif config.protocol == "trojan":
                outbound["password"] = config.password

            elif config.protocol == "shadowsocks":
                outbound["password"] = config.password
                outbound["method"] = config.shadowsocks_method

            self._outbounds.append(outbound)
