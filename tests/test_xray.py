import json
import uuid

from v2share import XrayConfig, V2Data


def test_xray_chaining():
    detour_config = V2Data(
        "vmess",
        "detour_outbound",
        "127.0.0.1",
        1234,
        uuid=uuid.UUID("bb34fc3a-529d-473a-a3d9-1749b2116f2a"),
    )
    main_config = V2Data(
        "vmess",
        "main_outbound",
        "127.0.0.1",
        1234,
        uuid=uuid.UUID("bb34fc3a-529d-473a-a3d9-1749b2116f2a"),
        next=detour_config,
    )
    x = XrayConfig()
    x.add_proxies([main_config])
    result = json.loads(x.render())

    main_outbound = None
    for outbound in result[0]["outbounds"]:
        if outbound["tag"] == "main_outbound":
            main_outbound = outbound
            break
    assert (
        main_outbound["streamSettings"]["sockopt"]["dialerProxy"] == "detour_outbound"
    )
