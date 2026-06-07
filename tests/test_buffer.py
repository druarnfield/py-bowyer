"""Unit tests for ByteReader / ByteWriter and PacketHeader (offline, no socket).

Header facts are asserted against the golden capture frames (see conftest `raw`).
"""

import pytest

from bowyer._buffer import ByteReader, ByteWriter, PacketHeader
from bowyer.constants import HEADER_SIZE, PacketType, Status

ALL_FRAMES = [4, 6, 8, 9, 11, 12]


# --- PacketHeader: unpack against the capture ---------------------------------


def test_header_unpack_login7_frame8(raw):
    pkt = raw(8)
    hdr = PacketHeader.unpack(pkt)
    assert hdr.type is PacketType.LOGIN7
    assert hdr.is_eom
    assert hdr.length == len(pkt)
    assert hdr.spid == 0
    assert hdr.packet_id == 1
    assert hdr.payload_length == len(pkt) - HEADER_SIZE


def test_header_unpack_tolerates_nonzero_server_spid(raw):
    # Server replies carry a non-zero SPID (frame 9 == 65); the reader must keep it.
    assert PacketHeader.unpack(raw(9)).spid == 65


def test_header_status_is_a_flag_field(raw):
    # Frame 11's status is 0x09 == EOM | RESET_CONNECTION.
    status = PacketHeader.unpack(raw(11)).status
    assert Status.EOM in status
    assert Status.RESET_CONNECTION in status


@pytest.mark.parametrize("frame", ALL_FRAMES)
def test_header_pack_roundtrips_capture(raw, frame):
    pkt = raw(frame)
    assert PacketHeader.unpack(pkt).pack() == pkt[:HEADER_SIZE]


def test_header_unpack_rejects_short_input():
    with pytest.raises(ValueError):
        PacketHeader.unpack(b"\x10\x01\x00")


def test_header_unpack_rejects_length_below_header_size():
    # length field == 3 (< HEADER_SIZE) would make payload_length negative.
    with pytest.raises(ValueError):
        PacketHeader.unpack(b"\x04\x01\x00\x03\x00\x00\x01\x00")


# --- ByteWriter / ByteReader: little-endian payload primitives -----------------


def test_uint16_is_little_endian():
    w = ByteWriter()
    w.write_uint16(0x0102)
    assert w.getvalue() == b"\x02\x01"


def test_uint16_be_is_big_endian():
    # PRELOGIN option offsets/lengths are big-endian (the payload exception).
    w = ByteWriter()
    w.write_uint16_be(0x0102)
    assert w.getvalue() == b"\x01\x02"


def test_uint16_be_roundtrips_through_reader():
    w = ByteWriter()
    w.write_uint16_be(0xBEEF)
    assert ByteReader(w.getvalue()).read_uint16_be() == 0xBEEF


def test_read_uint16_be_decodes_big_endian():
    assert ByteReader(b"\x01\x02").read_uint16_be() == 0x0102


def test_le_primitive_roundtrip():
    w = ByteWriter()
    w.write_uint8(0xAB)
    w.write_uint16(0xBEEF)
    w.write_uint32(0xDEADBEEF)
    w.write_int32(-12345)
    w.write_bytes(b"\x00\xff")

    r = ByteReader(w.getvalue())
    assert r.read_uint8() == 0xAB
    assert r.read_uint16() == 0xBEEF
    assert r.read_uint32() == 0xDEADBEEF
    assert r.read_int32() == -12345
    assert r.read_bytes(2) == b"\x00\xff"
    assert r.eof()


def test_utf16le_roundtrip():
    w = ByteWriter()
    w.write_utf16le("SELECT 1;")
    blob = w.getvalue()
    assert blob == "SELECT 1;".encode("utf-16-le")
    assert ByteReader(blob).read_utf16le(len(blob)) == "SELECT 1;"


def test_reader_decodes_login7_le_length_prefix(raw):
    # The LOGIN7 payload begins with a little-endian uint32 total length, while
    # the packet header Length is big-endian -- this cross-checks the split.
    pkt = raw(8)
    assert ByteReader(pkt[HEADER_SIZE:]).read_uint32() == len(pkt) - HEADER_SIZE


def test_reader_tracks_position_and_remaining():
    r = ByteReader(b"\x01\x02\x03\x04")
    assert r.position == 0
    assert r.remaining == 4
    r.read_uint16()
    assert r.position == 2
    assert r.remaining == 2


def test_reader_overrun_raises():
    r = ByteReader(b"\x01")
    with pytest.raises(ValueError):
        r.read_uint32()


@pytest.mark.parametrize(
    "method, value",
    [
        ("write_uint8", 256),
        ("write_uint16", 0x10000),
        ("write_uint32", 0x1_0000_0000),
        ("write_int32", 0x8000_0000),
    ],
)
def test_writer_out_of_range_raises_named_value_error(method, value):
    # Out-of-range writes surface a domain ValueError naming the field, not a
    # bare struct.error from deep in the buffer.
    w = ByteWriter()
    with pytest.raises(ValueError):
        getattr(w, method)(value)
