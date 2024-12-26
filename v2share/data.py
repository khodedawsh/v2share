import base64
import json
import urllib.parse as urlparse
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from uuid import UUID

from v2share._utils import filter_dict, set_path_early_data
from v2share.exceptions import ProtocolNotSupportedError


@dataclass
class XrayNoise:
    type: str
    packet: str
    delay: str


@dataclass
class XMuxSettings:
    max_concurrency: Optional[str] = None
    max_connections: Optional[str] = None
    max_reuse_times: Optional[str] = None
    max_lifetime: Optional[str] = None
    max_request_times: Optional[str] = None
    keep_alive_period: Optional[int] = None


@dataclass
class SplitHttpSettings:
    mode: Optional[str] = None
    no_grpc_header: Optional[bool] = None
    padding_bytes: Optional[str] = None
    xmux: Optional[XMuxSettings] = None


@dataclass
class SingBoxMuxSettings:
    max_connections: Optional[int] = None
    min_streams: Optional[int] = None
    max_streams: Optional[int] = None
    padding: Optional[bool] = None


@dataclass
class MuxCoolSettings:
    concurrency: Optional[int] = None
    xudp_concurrency: Optional[int] = None
    xudp_proxy_443: Optional[str] = None


@dataclass
class MuxSettings:
    protocol: str = "mux_cool"
    sing_box_mux_settings: Optional[SingBoxMuxSettings] = None
    mux_cool_settings: Optional[MuxCoolSettings] = None


@dataclass
class V2Data:
    protocol: str
    remark: str
    address: str
    port: int
    shadowsocks_method: Optional[str] = None
    uuid: Optional[UUID] = None
    vmess_security: str = "auto"
    password: Optional[str] = None
    ed25519: Optional[str] = None
    host: Optional[str] = None
    http_headers: Dict[str, str] = field(default_factory=dict)
    transport_type: str = "tcp"
    grpc_multi_mode: Optional[bool] = None
    grpc_user_agent: Optional[str] = None
    path: Optional[str] = None
    header_type: Optional[str] = None
    tls: str = "none"
    flow: Optional[str] = None
    sni: Optional[str] = None
    fingerprint: Optional[str] = None
    alpn: Optional[str] = None
    reality_pbk: Optional[str] = None
    reality_sid: Optional[str] = None
    reality_spx: Optional[str] = None
    client_address: Optional[str] = None
    fragment: bool = False
    fragment_packets: str = "tlshello"
    fragment_length: str = "100-200"
    fragment_interval: str = "10-20"
    xray_noises: Optional[List[XrayNoise]] = None
    early_data: Optional[int] = None
    mtu: Optional[int] = None
    dns_servers: Optional[List[str]] = None
    allowed_ips: Optional[List[str]] = None
    congestion_control: Optional[str] = None
    tuic_udp_relay_mode: Optional[str] = None
    shadowtls_version: Optional[int] = None
    disable_sni: bool = False
    allow_insecure: bool = False
    weight: int = 1
    next: Optional["V2Data"] = None
    splithttp_settings: Optional[SplitHttpSettings] = None
    mux_settings: Optional[MuxSettings] = None

    def _apply_tls_settings(self, payload):
        if self.tls in ["tls", "reality"]:
            payload.update(
                {
                    "sni": self.sni,
                    "fp": self.fingerprint,
                }
            )
            if self.protocol in ["vless", "trojan"]:
                payload.update({"allowInsecure": int(self.allow_insecure) or None})
        if self.tls == "tls":
            payload.update(
                {
                    "alpn": self.alpn,
                }
            )
        elif self.tls == "reality":
            payload.update(
                {
                    "pbk": self.reality_pbk,
                    "sid": self.reality_sid,
                    "spx": self.reality_spx,
                }
            )

    def _apply_trojan_vless_transport(self, payload):
        if self.transport_type == "grpc":
            transport_data = {
                "serviceName": self.path,
                "authority": self.host,
                "mode": "multi" if self.grpc_multi_mode else "gun",
            }
        elif self.transport_type == "kcp":
            transport_data = {"seed": self.path}
        elif self.transport_type == "quic":
            transport_data = {"key": self.path, "quicSecurity": self.host}
        else:
            transport_data = {"path": self.path, "host": self.host}
            if self.transport_type in {"ws", "httpupgrade"} and self.early_data:
                transport_data["path"] = set_path_early_data(
                    transport_data.get("path", "/"), self.early_data
                )
            if (
                self.transport_type == "splithttp"
                and self.splithttp_settings is not None
            ):
                transport_data["mode"] = self.splithttp_settings.mode
                transport_data["extra"] = filter_dict(
                    {
                        "headers": self.http_headers,
                        "xPaddingBytes": self.splithttp_settings.padding_bytes,
                        "noGRPCHeader": self.splithttp_settings.no_grpc_header,
                        "xmux": (
                            filter_dict(
                                {
                                    "maxConcurrency": self.splithttp_settings.xmux.max_concurrency,
                                    "maxConnections": self.splithttp_settings.xmux.max_connections,
                                    "cMaxReuseTimes": self.splithttp_settings.xmux.max_reuse_times,
                                    "cMaxLifetimeMs": self.splithttp_settings.xmux.max_lifetime,
                                    "hMaxRequestTimes": self.splithttp_settings.xmux.max_request_times,
                                    "hKeepAlivePeriod": self.splithttp_settings.xmux.keep_alive_period,
                                },
                                (None,),
                            )
                            if self.splithttp_settings.xmux is not None
                            else None
                        ),
                    },
                    (None,),
                )

        payload.update(transport_data)

    def to_link(self):
        if self.protocol == "shadowsocks":
            return (
                "ss://"
                + base64.b64encode(
                    (
                        f"{self.shadowsocks_method}:{self.password}"
                        + f"@{self.address}:{self.port}"
                    ).encode()
                ).decode()
                + f"#{urlparse.quote(self.remark)}"
            )

        if self.protocol == "vmess":
            payload = {
                "add": self.address,
                "aid": "0",
                "host": self.host,
                "id": str(self.uuid),
                "net": (
                    self.transport_type
                    if self.transport_type != "splithttp"
                    else "xhttp"
                ),
                "path": self.path,
                "port": self.port,
                "ps": self.remark,
                "scy": self.vmess_security,
                "tls": self.tls,
                "type": (
                    self.header_type
                    if self.transport_type != "splithttp"
                    or not self.splithttp_settings
                    or not self.splithttp_settings.mode
                    else self.splithttp_settings.mode
                ),
                "v": "2",
            }

            self._apply_tls_settings(payload)
            payload = filter_dict(payload, ("", None))
            return (
                "vmess://"
                + base64.b64encode(
                    json.dumps(payload, sort_keys=True).encode()
                ).decode()
            )

        if self.protocol in ["trojan", "vless"]:
            payload = {
                "security": self.tls,
                "type": (
                    self.transport_type
                    if self.transport_type != "splithttp"
                    else "xhttp"
                ),
                "headerType": self.header_type,
            }
            if self.protocol == "vless" and self.flow:
                payload.update({"flow": self.flow or ""})

            self._apply_trojan_vless_transport(payload)

            self._apply_tls_settings(payload)

            payload = filter_dict(payload, ("", None))

            passphrase = (
                self.uuid
                if self.protocol == "vless"
                else urlparse.quote(self.password, safe=":")
            )
            return (
                f"{self.protocol}://"
                + f"{passphrase}@{self.address}:{self.port}?"
                + urlparse.urlencode(payload)
                + f"#{(urlparse.quote(self.remark))}"
            )

        if self.protocol == "hysteria2":
            payload = {"sni": self.sni}
            if self.header_type:
                payload.update({"obfs": self.header_type})
                payload.update({"obfs-password": self.path})
            if self.disable_sni:
                payload.update({"disable_sni": "1"})
            if self.allow_insecure:
                payload.update({"insecure": "1"})

            return (
                "hysteria2://"
                + f"{self.password}@{self.address}:{self.port}?"
                + urlparse.urlencode(payload)
                + f"#{(urlparse.quote(self.remark))}"
            )

        if self.protocol == "wireguard":
            payload = {"publickey": self.path, "address": self.client_address}
            if isinstance(self.mtu, int):
                payload.update({"mtu": self.mtu})
            return (
                "wireguard://"
                + f"{self.ed25519}@{self.address}:{self.port}?"
                + urlparse.urlencode(payload)
                + f"#{(urlparse.quote(self.remark))}"
            )

        if self.protocol == "tuic":
            payload = {
                "sni": self.sni,
                "udp_relay_mode": self.tuic_udp_relay_mode,
                "congestion_control": self.congestion_control,
                "alpn": self.alpn,
            }
            if self.allow_insecure:
                payload.update({"insecure": "1"})
            if self.disable_sni:
                payload.update({"disable_sni": "1"})

            payload = filter_dict(payload, ("", None))
            return (
                "tuic://"
                + f"{self.uuid}:{self.password}@{self.address}:{self.port}?"
                + urlparse.urlencode(payload)
                + f"#{(urlparse.quote(self.remark))}"
            )
        raise ProtocolNotSupportedError
