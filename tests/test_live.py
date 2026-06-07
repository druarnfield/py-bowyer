"""@pytest.mark.live — runs only against a Docker SQL Server.

Phase 1 "Done when": send an arbitrary payload in a valid packet and read back a
fully reassembled server message. We replay the captured PRELOGIN payload over a
real socket and require the server's (Type-4) reply to come back intact.

Requires the dev server up: `docker compose up -d` (bowyer-sql2022 on :1433).
"""

import pytest

from bowyer import build_prelogin
from bowyer.constants import PacketType
from bowyer.transport import Transport


@pytest.mark.live
def test_prelogin_roundtrip_real_server():
    transport = Transport.connect("127.0.0.1", 1433, timeout=10.0)
    try:
        transport.send_message(PacketType.PRELOGIN, build_prelogin())
        pkt_type, response = transport.receive_message()
    finally:
        transport.close()

    assert pkt_type is PacketType.TABULAR_RESULT  # server reply is type 0x04
    assert len(response) > 0
    assert response.hex(sep="-") == (
        "00-00-0b-00-06-01-00-11-00-01-ff-10-00-10-a4-00-00-02"
    )
