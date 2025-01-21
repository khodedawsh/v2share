import json
import random
from importlib import resources
from typing import List

from v2share._utils import filter_dict
from v2share.base import BaseConfig
from v2share.data import V2Data
from v2share.exceptions import ProtocolNotSupportedError, TransportNotSupportedError


class SingBoxConfig(BaseConfig):
    chaining_support = True
    supported_protocols = [
        "shadowsocks",
        "vmess",
        "trojan",
        "vless",
        "hysteria2",
        "wireguard",
        "shadowtls",
        "tuic",
    ]
    supported_transports = [
        "tcp",
        "ws",
        "quic",
        "httpupgrade",
        "grpc",
        "http",
        "splithttp",
        None,
    ]

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
            configs = sorted(self._configs, key=lambda c: c.weight)
        else:
            configs = self._configs

        result = json.loads(self._template_data)

        blackset = set()
        for config in configs:
            c = config
            while True:
                outbound = self.create_outbound(c)
                if c.next:
                    outbound["detour"] = config.next.remark
                    blackset.add(c.next.remark)
                    c = config.next
                    result["outbounds"].append(outbound)
                else:
                    result["outbounds"].append(outbound)
                    break

        urltest_types = [
            "hysteria2",
            "vmess",
            "vless",
            "trojan",
            "shadowsocks",
            "wireguard",
            "tuic",
            "shadowtls",
        ]
        urltest_tags = [
            outbound["tag"]
            for outbound in result["outbounds"]
            if outbound["type"] in urltest_types and outbound["tag"] not in blackset
        ]
        selector_types = [
            "hysteria2",
            "vmess",
            "vless",
            "trojan",
            "shadowsocks",
            "wireguard",
            "tuic",
            "shadowtls",
            "urltest",
        ]
        selector_tags = [
            outbound["tag"]
            for outbound in result["outbounds"]
            if outbound["type"] in selector_types and outbound["tag"] not in blackset
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
        transport_type="tcp",
        host=None,
        path=None,
        http_method=None,
        headers=None,
        early_data=None,
    ):
        if headers is None:
            headers = {}

        transport_config = {"type": transport_type}

        if transport_type in {"http", "tcp", "splithttp"}:
            transport_config["type"] = "http"
            transport_config["headers"] = headers
            if host:
                transport_config["host"] = [host]
            if path:
                transport_config["path"] = path
            if http_method:
                transport_config["method"] = http_method
        elif transport_type == "ws":
            transport_config["headers"] = headers
            if path:
                if early_data:
                    transport_config["early_data_header_name"] = (
                        "Sec-WebSocket-Protocol"
                    )
                    transport_config["max_early_data"] = early_data
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

        if config.transport_type in [
            "ws",
            "quic",
            "grpc",
            "httpupgrade",
            "http",
            "splithttp",
        ] or (config.transport_type == "tcp" and config.header_type == "http"):
            outbound["transport"] = SingBoxConfig.transport_config(
                transport_type=config.transport_type,
                host=config.host,
                path=config.path,
                headers=config.http_headers,
                early_data=config.early_data,
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
        elif config.protocol == "wireguard":
            outbound.update(
                {
                    "private_key": config.ed25519,
                    "local_address": [config.client_address],
                    "mtu": config.mtu,
                    "peers": [
                        {
                            "server": config.address,
                            "port": config.port,
                            "public_key": config.path,
                            "allowed_ips": config.allowed_ips or ["0.0.0.0/0", "::/0"],
                        }
                    ],
                }
            )
        elif config.protocol == "shadowtls":
            if config.shadowtls_version:
                outbound["version"] = config.shadowtls_version
                if config.shadowtls_version in {2, 3}:
                    outbound["password"] = config.password
        elif config.protocol == "tuic":
            outbound["password"] = config.password
            outbound["uuid"] = str(config.uuid)

        if config.mux_settings is not None and config.mux_settings.protocol in {
            "h2mux",
            "yamux",
            "smux",
        }:
            outbound["multiplex"] = {"enabled": True, "protocol": config.mux_settings.protocol}
            if config.mux_settings.sing_box_mux_settings is not None:
                additional_mux_settings = filter_dict(
                    {
                        "max_connections": config.mux_settings.sing_box_mux_settings.max_connections,
                        "min_streams": config.mux_settings.sing_box_mux_settings.min_streams,
                        "max_streams": config.mux_settings.sing_box_mux_settings.max_streams,
                        "padding": config.mux_settings.sing_box_mux_settings.padding,
                    },
                    (None,),
                )
                outbound["multiplex"].update(additional_mux_settings)
        return outbound

    def add_proxies(self, proxies: List[V2Data]):
        for proxy in proxies:
            # validation
            if (
                unsupported_transport := proxy.transport_type
                not in self.supported_transports
            ) or (
                unsupported_protocol := proxy.protocol not in self.supported_protocols
            ):
                if self._swallow_errors:
                    continue
                if unsupported_transport:
                    raise TransportNotSupportedError
                if unsupported_protocol:
                    raise ProtocolNotSupportedError

            self._configs.append(proxy)
