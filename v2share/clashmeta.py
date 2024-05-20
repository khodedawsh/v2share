from v2share.clash import ClashConfig
from v2share.data import V2Data


class ClashMetaConfig(ClashConfig):
    def _make_node(
        self,
        name: str,
        type: str,
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
            type=type,
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

    def _add_node(self, config: V2Data):
        node = self._make_node(
            name=config.remark,
            type=config.protocol,
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
            self.data["proxies"].append(node)
            self.proxy_remarks.append(config.remark)

        if config.protocol == "vless":
            node["uuid"] = str(config.uuid)

            if config.transport_type in ("tcp", "kcp") and config.header_type != "http":
                node["flow"] = config.flow

            self.data["proxies"].append(node)
            self.proxy_remarks.append(config.remark)

        if config.protocol == "trojan":
            node["password"] = config.password

            if (
                config.transport_type in ("tcp", "kcp")
                and config.header_type != "http"
                and config.tls
            ):
                node["flow"] = config.flow

            self.data["proxies"].append(node)
            self.proxy_remarks.append(config.remark)

        if config.protocol == "shadowsocks":
            node["password"] = config.password
            node["cipher"] = config.shadowsocks_method
            self.data["proxies"].append(node)
            self.proxy_remarks.append(config.remark)
