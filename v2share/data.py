import base64
import json
from dataclasses import dataclass
from typing import Optional
from uuid import UUID
import urllib.parse as urlparse


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
    host: Optional[str] = None
    transport_type: Optional[str] = "tcp"
    path: Optional[str] = None
    header_type: Optional[str] = None
    tls: Optional[str] = "none"
    flow: Optional[str] = None
    sni: Optional[str] = None
    fingerprint: Optional[str] = None
    alpn: Optional[str] = None
    reality_pbk: Optional[str] = None
    reality_sid: Optional[str] = None
    reality_spx: Optional[str] = None
    allow_insecure: bool = False

    def _apply_tls_settings(self, payload):
        if self.tls == "tls" or self.tls == "reality":
            payload.update(
                {
                    "sni": self.sni,
                    "fp": self.fingerprint,
                }
            )
        if self.tls == "tls":
            payload.update(
                {
                    "alpn": self.alpn,
                }
            )
        if self.tls == "reality":
            payload.update(
                {
                    "pbk": self.reality_pbk,
                    "sid": self.reality_sid,
                    "spx": self.reality_spx,
                }
            )

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
        elif self.protocol == "vmess":
            payload = {
                "add": self.address,
                "aid": "0",
                "host": self.host,
                "id": str(self.uuid),
                "transport_type": self.transport_type,
                "path": self.path,
                "port": self.port,
                "ps": self.remark,
                "scy": "auto",
                "tls": self.tls,
                "type": self.header_type,
                "v": "2",
            }

            self._apply_tls_settings(payload)
            payload = dict(filter(lambda p: p[1], payload.items()))
            return (
                "vmess://"
                + base64.b64encode(
                    json.dumps(payload, sort_keys=True).encode("utf-8")
                ).decode()
            )
        elif self.protocol == "vless":
            payload = {
                "security": self.tls,
                "type": self.transport_type,
                "host": self.host,
                "headerType": self.header_type,
            }
            if self.flow:
                payload.update({"flow": self.flow})

            path_name = "serviceName" if self.transport_type == "grpc" else "path"
            payload.update({path_name: self.path})

            self._apply_tls_settings(payload)
            payload = dict(filter(lambda p: p[1], payload.items()))
            return (
                "vless://"
                + f"{self.uuid}@{self.address}:{self.port}?"
                + urlparse.urlencode(payload)
                + f"#{(urlparse.quote(self.remark))}"
            )
        elif self.protocol == "trojan":
            payload = {
                "security": self.tls,
                "type": self.transport_type,
                "host": self.host,
                "headerType": self.header_type,
            }
            path_name = "serviceName" if self.transport_type == "grpc" else "path"
            payload.update({path_name: self.path})
            self._apply_tls_settings(payload)
            payload = dict(filter(lambda p: p[1], payload.items()))
            return (
                "trojan://"
                + f"{urlparse.quote(self.password, safe=':')}@{self.address}:{self.port}?"
                + urlparse.urlencode(payload)
                + f"#{urlparse.quote(self.remark)}"
            )
