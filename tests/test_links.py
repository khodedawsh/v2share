import uuid

from v2share import V2Data


def test_shadowsocks_link():
    ss = V2Data(
        "shadowsocks",
        "remark",
        "127.0.0.1",
        1234,
        password="1234",
    )
    assert ss.to_link() == "ss://Tm9uZToxMjM0QDEyNy4wLjAuMToxMjM0#remark"


def test_trojan_link():
    tj = V2Data("trojan", "remark", "127.0.0.1", 1234, password="1234")
    assert tj.to_link() == "trojan://1234@127.0.0.1:1234?security=none&type=tcp#remark"
    tj.tls = "tls"
    tj.alpn = "h2"
    tj.allow_insecure = True
    assert (
        tj.to_link()
        == "trojan://1234@127.0.0.1:1234?security=tls&type=tcp&allowInsecure=1&alpn=h2#remark"
    )


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


def test_vmess_link():
    vm = V2Data(
        "vmess",
        "remark",
        "127.0.0.1",
        1234,
        uuid=uuid.UUID("bb34fc3a-529d-473a-a3d9-1749b2116f2a"),
    )
    assert (
        vm.to_link()
        == "vmess://eyJhZGQiOiAiMTI3LjAuMC4xIiwgImFpZCI6ICIwIiwgImlkIjogImJiMzRmYzNhLTUyOWQtNDczYS1hM2Q5LTE3NDliMjExNmYyYSIsICJuZXQiOiAidGNwIiwgInBvcnQiOiAxMjM0LCAicHMiOiAicmVtYXJrIiwgInNjeSI6ICJhdXRvIiwgInRscyI6ICJub25lIiwgInYiOiAiMiJ9"
    )
    tls_vm = V2Data(
        "vmess",
        "remark",
        "127.0.0.1",
        1234,
        uuid=uuid.UUID("bb34fc3a-529d-473a-a3d9-1749b2116f2a"),
        tls="tls",
        sni="something.com",
        alpn="h2",
    )
    assert (
        tls_vm.to_link()
        == "vmess://eyJhZGQiOiAiMTI3LjAuMC4xIiwgImFpZCI6ICIwIiwgImFscG4iOiAiaDIiLCAiaWQiOiAiYmIzNGZjM2EtNTI5ZC00NzNhLWEzZDktMTc0OWIyMTE2ZjJhIiwgIm5ldCI6ICJ0Y3AiLCAicG9ydCI6IDEyMzQsICJwcyI6ICJyZW1hcmsiLCAic2N5IjogImF1dG8iLCAic25pIjogInNvbWV0aGluZy5jb20iLCAidGxzIjogInRscyIsICJ2IjogIjIifQ=="
    )
