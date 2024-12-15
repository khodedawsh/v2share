import json
import uuid

from v2share import SingBoxConfig, V2Data


def test_sing_box_chaining():
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
    sb = SingBoxConfig()
    sb.add_proxies([main_config])

    result = json.loads(sb.render())

    main_outbound, selector_outbounds = None, []
    for outbound in result["outbounds"]:
        if outbound["tag"] == "main_outbound":
            main_outbound = outbound

        if outbound["type"] == "selector" or outbound["type"] == "urltest":
            selector_outbounds.append(outbound)

    assert main_outbound["detour"] == "detour_outbound"
    for outbound in selector_outbounds:
        assert (
            "detour_outbound" not in outbound["outbounds"]
        )  # detour outbound should not be in the selectors
