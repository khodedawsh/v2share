from typing import List

from v2share.clash import ClashConfig
from v2share.data import V2Data
from v2share.exceptions import TransportNotSupportedError, ProtocolNotSupportedError

supported_transports = ["tcp", "http", "ws", "grpc", "h2"]
supported_protocols = ["vmess", "trojan", "shadowsocks", "vless"]


class ClashMetaConfig(ClashConfig):
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
        header_type: str = "",
        udp: bool = True,
        alpn: str = "",
        fp: str = "",
        pbk: str = "",
        sid: str = "",
        ais: bool = "",
    ):
        node = super()._make_node(
            name=name,
            protocol=protocol,
            server=server,
            port=port,
            network=network,
            tls=tls,
            sni=sni,
            host=host,
            path=path,
            udp=udp,
            alpn=alpn,
            ais=ais,
        )
        if fp:
            node["client-fingerprint"] = fp
        if pbk:
            node["reality-opts"] = {"public-key": pbk, "short-id": sid}

        return node

    def _get_node(self, config: V2Data):
        node = self._make_node(
            name=config.remark,
            protocol=config.protocol,
            server=config.address,
            port=config.port,
            network=config.transport_type,
            tls=(config.tls in ["tls", "reality"]),
            sni=config.sni,
            host=config.host,
            path=config.path,
            header_type=config.header_type,
            udp=True,
            alpn=config.alpn,
            fp=config.fingerprint,
            pbk=config.reality_pbk,
            sid=config.reality_sid,
            ais=config.allow_insecure,
        )

        if config.protocol == "vmess":
            node["uuid"] = str(config.uuid)
            node["alterId"] = 0
            node["cipher"] = "auto"

        elif config.protocol == "vless":
            node["uuid"] = str(config.uuid)

            if config.transport_type in ("tcp", "kcp") and config.header_type != "http":
                node["flow"] = config.flow

        elif config.protocol == "trojan":
            node["password"] = config.password

        elif config.protocol == "shadowsocks":
            node["password"] = config.password
            node["cipher"] = config.shadowsocks_method
        return node

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
