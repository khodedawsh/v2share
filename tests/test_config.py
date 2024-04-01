import uuid

from v2share import V2Data


def test_shadowsocks_link():
    ss = V2Data(
        "shadowsocks",
        "remark",
        "127.0.0.1",
        1234,
        uuid=uuid.UUID("bb34fc3a-529d-473a-a3d9-1749b2116f2a"),
    )
    assert ss.to_link() == "ss://Tm9uZTpOb25lQDEyNy4wLjAuMToxMjM0#remark"


def test_trojan_link():
    tj = V2Data("trojan", "remark", "127.0.0.1", 1234, password="1234")
    assert tj.to_link() == "trojan://1234@127.0.0.1:1234?security=none&type=tcp#remark"


def test_vless_link():
    vl = V2Data(
        "vless",
        "remark",
        "127.0.0.1",
        1234,
        uuid=uuid.UUID("bb34fc3a-529d-473a-a3d9-1749b2116f2a"),
    )
    assert (
        vl.to_link()
        == "vless://bb34fc3a-529d-473a-a3d9-1749b2116f2a@127.0.0.1:1234?security=none&type=tcp#remark"
    )
