"""Offline tests for the transport layer (packet framing + reassembly).

Driven entirely by FakeSocket (see conftest) — no real network.
"""

import pytest

from bowyer._buffer import PacketHeader
from bowyer.constants import HEADER_SIZE, PacketType, Status
from bowyer.transport import Transport, TransportError


def _packet(
    ptype: PacketType, payload: bytes, *, eom: bool, packet_id: int = 0
) -> bytes:
    """Build one on-wire packet (header + payload) for feeding to FakeSocket."""
    status = Status.EOM if eom else Status.NORMAL
    header = PacketHeader(ptype, status, len(payload) + HEADER_SIZE, 0, packet_id, 0)
    return header.pack() + payload


def _split_packets(data: bytes) -> list[tuple[PacketHeader, bytes]]:
    """Walk a byte stream of one-or-more packets into (header, body) pairs."""
    out = []
    pos = 0
    while pos < len(data):
        header = PacketHeader.unpack(data[pos:])
        body = data[pos + HEADER_SIZE : pos + header.length]
        out.append((header, body))
        pos += header.length
    return out


# --- receive_message ----------------------------------------------------------


def test_receive_single_packet(raw, fake_socket):
    sock = fake_socket([raw(6)])  # a complete single-packet server reply (EOM set)
    pkt_type, payload = Transport(sock).receive_message()
    assert pkt_type is PacketType.TABULAR_RESULT
    assert payload == raw(6)[HEADER_SIZE:]


def test_receive_reassembles_two_packets(fake_socket):
    stream = _packet(PacketType.TABULAR_RESULT, b"AAAA", eom=False) + _packet(
        PacketType.TABULAR_RESULT, b"BBBB", eom=True
    )
    sock = fake_socket([stream])
    pkt_type, payload = Transport(sock).receive_message()
    assert pkt_type is PacketType.TABULAR_RESULT
    assert payload == b"AAAABBBB"


def test_receive_handles_chunked_recv(fake_socket):
    # Same two-packet message, but recv() hands back only 1-3 bytes at a time.
    stream = _packet(PacketType.TABULAR_RESULT, b"hello", eom=False) + _packet(
        PacketType.TABULAR_RESULT, b" world", eom=True
    )
    chunks = [stream[i : i + 3] for i in range(0, len(stream), 3)]
    sock = fake_socket(chunks)
    pkt_type, payload = Transport(sock).receive_message()
    assert pkt_type is PacketType.TABULAR_RESULT
    assert payload == b"hello world"


def test_receive_closed_socket_raises(fake_socket):
    # Only a partial header arrives, then the peer closes (recv -> b"").
    sock = fake_socket([b"\x04\x01\x00"])
    with pytest.raises(TransportError):
        Transport(sock).receive_message()


# --- send_message -------------------------------------------------------------


def test_send_single_packet(fake_socket):
    sock = fake_socket()
    Transport(sock).send_message(PacketType.SQL_BATCH, b"payload-bytes")

    packets = _split_packets(bytes(sock.sent))
    assert len(packets) == 1
    header, body = packets[0]
    assert header.type is PacketType.SQL_BATCH
    assert header.is_eom
    assert header.spid == 0
    assert header.length == len(b"payload-bytes") + HEADER_SIZE
    assert body == b"payload-bytes"


def test_send_chunks_large_payload(fake_socket):
    sock = fake_socket()
    payload = bytes(range(20))  # 20 bytes, max payload per packet = 16 - 8 = 8
    Transport(sock).send_message(PacketType.SQL_BATCH, payload, packet_size=16)

    packets = _split_packets(bytes(sock.sent))
    assert [len(body) for _, body in packets] == [8, 8, 4]
    # EOM only on the final packet.
    assert [h.is_eom for h, _ in packets] == [False, False, True]
    # PacketID increments from 1.
    assert [h.packet_id for h, _ in packets] == [1, 2, 3]
    # Bodies reassemble to the original payload.
    assert b"".join(body for _, body in packets) == payload


def test_send_empty_payload_is_one_eom_packet(fake_socket):
    sock = fake_socket()
    Transport(sock).send_message(PacketType.SQL_BATCH, b"")

    packets = _split_packets(bytes(sock.sent))
    assert len(packets) == 1
    header, body = packets[0]
    assert header.is_eom
    assert body == b""


def test_send_then_receive_roundtrip(fake_socket):
    # Pipe what we sent back through a reader to prove framing is self-consistent.
    sender = fake_socket()
    Transport(sender).send_message(PacketType.PRELOGIN, b"the-payload")

    reader = fake_socket([bytes(sender.sent)])
    pkt_type, payload = Transport(reader).receive_message()
    assert pkt_type is PacketType.PRELOGIN
    assert payload == b"the-payload"


def test_packet_size_setter_rejects_out_of_spec(fake_socket):
    transport = Transport(fake_socket)
    with pytest.raises(ValueError):
        transport.packet_size = 256
    with pytest.raises(ValueError):
        transport.packet_size = 40000
