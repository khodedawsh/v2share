from typing import List

from v2share.config import V2Config
from v2share.templates import render_template


class ClashConfiguration:
    def __init__(self):
        self.data = {
            "proxies": [],
            "proxy-groups": [],
            "rules": [],
        }
        self.proxy_remarks = []

    def add_proxies(self, proxies: List[V2Config]):
        for proxy in proxies:
            self._add_node(proxy)

    def render(self):
        return render_template(
            "clash.yml", {"conf": self.data, "proxy_remarks": self.proxy_remarks}
        )

    def _remark_validation(self, remark, depth: int = 0):
        if remark not in self.proxy_remarks:
            return remark
        return self._remark_validation(f"{remark} {depth}", depth + 1)

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
        udp: bool = True,
        alpn: str = "",
        ais: bool = "",
    ):
        if type == "shadowsocks":
            type = "ss"

        remark = self._remark_validation(name)
        node = {
            "name": remark,
            "type": type,
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

        if network == "http" or network == "tcp":
            if path:
                net_opts["method"] = "GET"
                net_opts["path"] = [path]
            if host:
                net_opts["method"] = "GET"
                net_opts["headers"] = {"Host": host}

        return node

    def _add_node(self, config: V2Config):
        node = self._make_node(
            name=config.remark,
            type=config.protocol,
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
            node["uuid"] = config.uuid
            node["alterId"] = 0
            node["cipher"] = "auto"
            self.data["proxies"].append(node)
            self.proxy_remarks.append(config.remark)
        elif config.protocol == "trojan":
            node["password"] = config.password
            self.data["proxies"].append(node)
            self.proxy_remarks.append(config.remark)
        elif config.protocol == "shadowsocks":
            node["password"] = config.password
            node["cipher"] = config.shadowsocks_method
            self.data["proxies"].append(node)
            self.proxy_remarks.append(config.remark)

