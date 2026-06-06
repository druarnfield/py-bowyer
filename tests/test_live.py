"""@pytest.mark.live — runs only against a Docker SQL Server.

Phase 1 "Done when": send an arbitrary payload in a valid packet and read back a
fully reassembled server message. We replay the captured PRELOGIN payload over a
real socket and require the server's (Type-4) reply to come back intact.

Requires the dev server up: `docker compose up -d` (bowyer-sql2022 on :1433).
"""

import pytest

from bowyer.constants import PacketType
from bowyer.transport import Transport


@pytest.mark.live
def test_prelogin_roundtrip_real_server(raw):
    payload = raw(4)[8:]  # captured PRELOGIN message payload, minus its header
    transport = Transport.connect("127.0.0.1", 1433, timeout=10.0)
    try:
        transport.send_message(PacketType.PRELOGIN, payload)
        pkt_type, response = transport.receive_message()
    finally:
        transport.close()

    assert pkt_type is PacketType.TABULAR_RESULT  # server reply is type 0x04
    assert len(response) > 0
