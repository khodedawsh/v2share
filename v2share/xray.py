import json
from importlib import resources
from typing import List

from v2share.data import V2Data


class XrayConfig:
    def __init__(self, template_path: str = None, mux_template_path: str = None):
        self.config = []
        if not template_path:
            template_path = resources.files("v2share.templates") / "xray.json"
        if not mux_template_path:
            mux_template_path = resources.files("v2share.templates") / "xray_mux.json"
        with open(template_path) as f:
            self._template = f.read()
        with open(mux_template_path) as f:
            self._mux_template = f.read()

    def add_proxies(self, proxies: List[V2Data]):
        for data in proxies:
            outbound = {"tag": data.remark, "protocol": data.protocol}

            if data.protocol == "vmess":
                outbound["settings"] = XrayConfig.vmess_config(
                    address=data.address, port=data.port, uuid=str(data.uuid)
                )
            elif data.protocol == "vless":
                if data.tls in ["reality", "tls"]:
                    flow = data.flow or "none"
                else:
                    flow = "none"
                outbound["settings"] = XrayConfig.vless_config(
                    address=data.address, port=data.port, uuid=str(data.uuid), flow=flow
                )

            elif data.protocol == "trojan":
                outbound["settings"] = XrayConfig.trojan_config(
                    address=data.address, port=data.port, password=data.password
                )

            elif data.protocol == "shadowsocks":
                outbound["settings"] = XrayConfig.shadowsocks_config(
                    address=data.address,
                    port=data.port,
                    password=data.password,
                    method=data.shadowsocks_method,
                )

            outbounds = [outbound]
            dialer_proxy = None

            if data.fragment:
                fragment_outbound = XrayConfig.make_fragment_outbound(
                    data.fragment_packets, data.fragment_length, data.fragment_interval
                )
                outbounds.append(fragment_outbound)
                dialer_proxy = fragment_outbound["tag"]

            outbound["streamSettings"] = XrayConfig.make_stream_settings(
                net=data.transport_type,
                tls=data.tls,
                sni=data.sni,
                host=data.host,
                path=data.path,
                alpn=data.alpn,
                fp=data.fingerprint,
                pbk=data.reality_pbk,
                sid=data.reality_sid,
                ais=data.allow_insecure,
                header_type=data.header_type,
                grpc_multi_mode=data.grpc_multi_mode,
                dialer_proxy=dialer_proxy,
                headers=data.http_headers,
            )

            mux_config = json.loads(self._mux_template)
            mux_config["enabled"] = data.enable_mux
            outbound["mux"] = mux_config

            json_template = json.loads(self._template)
            json_template["remarks"] = data.remark
            json_template["outbounds"] = outbounds + json_template["outbounds"]
            self.config.append(json_template)

    def render(self):
        return json.dumps(self.config, indent=4)

    @staticmethod
    def tls_config(sni, fingerprint, alpn=None, ais=False):
        tlsSettings = {"serverName": sni, "allowInsecure": ais or False}
        if alpn is None:
            alpn = ["h2", "http/1.1"]

        tlsSettings["alpn"] = alpn

        if fingerprint:
            tlsSettings["fingerprint"] = fingerprint

        return tlsSettings

    @staticmethod
    def reality_config(public_key, short_id, sni, fingerprint="", spiderx=""):

        realitySettings = {
            "serverName": sni,
            "fingerprint": fingerprint,
            "show": False,
            "publicKey": public_key,
            "shortId": short_id,
            "spiderX": spiderx,
        }

        return realitySettings

    @staticmethod
    def ws_config(path=None, host=None, headers=None):
        if headers is None:
            headers = {}

        ws_settings = {"headers": headers}
        if path:
            ws_settings["path"] = path
        if host:
            ws_settings["host"] = host

        return ws_settings

    @staticmethod
    def httpupgrade_config(path=None, host=None, headers=None):
        if headers is None:
            headers = {}

        httpupgrade_settings = {"headers": headers}
        if path:
            httpupgrade_settings["path"] = path
        if host:
            httpupgrade_settings["host"] = host

        return httpupgrade_settings

    @staticmethod
    def grpc_config(service_name=None, multi_mode=False):

        grpc_settings = {
            "multi_mode": multi_mode,
            "idle_timeout": 60,
            "health_check_timeout": 20,
            "permit_without_stream": False,
            "initial_windows_size": 0,
        }
        if service_name:
            grpc_settings["serviceName"] = service_name
        return grpc_settings

    @staticmethod
    def tcp_http_config(header_type=None):
        if header_type is None:
            header_type = "none"

        tcp_settings = {
            "header": {
                "type": header_type,
            }
        }

        return tcp_settings

    @staticmethod
    def h2_config(path=None, host=None, headers=None):
        if host is None:
            host = []
        if path is None:
            path = "/"
        if headers is None:
            headers = {}

        http_settings = {"path": path, "host": host}
        if headers:
            http_settings["headers"] = headers

        return http_settings

    @staticmethod
    def splithttp_config(path=None, host=None, headers=None):
        if host is None:
            host = []
        if path is None:
            path = "/"
        if headers is None:
            headers = {}

        splithttp_settings = {"path": path, "headers": headers}

        if host:
            splithttp_settings["host"] = host

        return splithttp_settings

    @staticmethod
    def quic_config(security="none", key=None, header_type="none"):

        quic_settings = {
            "security": security,
            "header": {"type": header_type},
        }

        if key:
            quic_settings["key"] = key

        return quic_settings

    @staticmethod
    def kcp_config(seed=None, header_type=None):

        kcp_settings = {
            "header": {},
            "mtu": 1350,
            "tti": 50,
            "uplinkCapacity": 12,
            "downlinkCapacity": 100,
            "congestion": False,
            "readBufferSize": 2,
            "writeBufferSize": 2,
        }

        if seed:
            kcp_settings["seed"] = seed
        if header_type:
            kcp_settings["header"]["type"] = header_type

        return kcp_settings

    @staticmethod
    def make_stream_settings(
        net="tcp",
        path=None,
        host=None,
        tls="none",
        sni="",
        fp=None,
        alpn="h2,http/1.1",
        pbk=None,
        sid=None,
        ais=False,
        header_type=None,
        grpc_multi_mode=False,
        dialer_proxy=None,
        headers=None,
    ):
        if headers is None:
            headers = {}

        stream_settings = {"network": net}

        if net == "ws":
            stream_settings["wsSettings"] = XrayConfig.ws_config(
                path=path, host=host, headers=headers
            )
        elif net == "grpc":
            stream_settings["grpcSettings"] = XrayConfig.grpc_config(
                service_name=path, multi_mode=grpc_multi_mode
            )
        elif net == "h2":
            stream_settings["httpSettings"] = XrayConfig.h2_config(
                path=path, host=[host], headers=headers
            )
        elif net == "kcp":
            stream_settings["kcpSettings"] = XrayConfig.kcp_config(
                seed=path, header_type=header_type
            )
        elif net == "tcp":
            stream_settings["tcpSettings"] = XrayConfig.tcp_http_config(
                header_type=header_type
            )
        elif net == "quic":
            stream_settings["quicSettings"] = XrayConfig.quic_config(
                security=host, key=path, header_type=header_type
            )
        elif net == "httpupgrade":
            stream_settings["httpupgradeSettings"] = XrayConfig.httpupgrade_config(
                path=path, host=host, headers=headers
            )
        elif net == "splithttp":
            stream_settings["splithttpSettings"] = XrayConfig.splithttp_config(
                path=path, host=host, headers=headers
            )

        if tls == "tls":
            stream_settings["security"] = "tls"
            stream_settings["tlsSettings"] = XrayConfig.tls_config(
                sni=sni, fingerprint=fp, alpn=alpn.split(",") if alpn else None, ais=ais
            )
        elif tls == "reality":
            stream_settings["security"] = "reality"
            stream_settings["realitySettings"] = XrayConfig.reality_config(
                pbk, sid, sni, fingerprint=fp
            )
        else:
            stream_settings["security"] = "none"

        if dialer_proxy:
            stream_settings["sockopt"] = {"dialerProxy": dialer_proxy}

        return stream_settings

    @staticmethod
    def vmess_config(address, port, uuid):

        return {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [
                        {
                            "id": uuid,
                            "security": "auto",
                        }
                    ],
                }
            ]
        }

    @staticmethod
    def vless_config(address, port, uuid, flow="none"):

        return {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [
                        {
                            "id": uuid,
                            "encryption": "none",
                            "flow": flow,
                        }
                    ],
                }
            ]
        }

    @staticmethod
    def trojan_config(address, port, password):
        return {
            "servers": [
                {
                    "address": address,
                    "port": port,
                    "password": password,
                    "email": "kiomars",
                }
            ]
        }

    @staticmethod
    def shadowsocks_config(address, port, password, method):
        return {
            "servers": [
                {
                    "address": address,
                    "port": port,
                    "password": password,
                    "email": "kiomars",
                    "method": method,
                    "uot": False,
                }
            ]
        }

    @staticmethod
    def make_fragment_outbound(packets, length, interval):
        return {
            "tag": "fragment_out",
            "protocol": "freedom",
            "settings": {
                "fragment": {"packets": packets, "length": length, "interval": interval}
            },
        }
