"""Unit tests for PRELOGIN build/parse."""

import pytest

from bowyer.constants import HEADER_SIZE, EncryptionLevel, PreLoginOption
from bowyer.prelogin import build_prelogin, parse_prelogin, parse_prelogin_encryption


def test_build_prelogin_is_byte_exact():
    # VERSION + ENCRYPTION + terminator. Directory is two 5-byte entries + 0xFF =
    # 11 bytes, so VERSION data lands at offset 11 and ENCRYPTION at 17. Offsets
    # and lengths are big-endian (the PRELOGIN payload exception).
    expected = bytes.fromhex(
        "00000b0006"  # VERSION:    token, offset=11, len=6
        "0100110001"  # ENCRYPTION: token, offset=17, len=1
        "ff"  # terminator
        "000000010000"  # VERSION data: version (0,0,0,1) + subbuild 0
        "02"  # ENCRYPTION data: NOT_SUP
    )
    assert build_prelogin(EncryptionLevel.NOT_SUP) == expected


@pytest.mark.parametrize("level", list(EncryptionLevel))
def test_build_prelogin_carries_requested_encryption(level):
    # The ENCRYPTION blob is the last byte (its data sits at the end of the
    # payload); whatever level we request must land there unchanged.
    assert build_prelogin(level)[-1] == level


def test_build_prelogin_defaults_to_not_supported():
    # v1 advertises "encryption not supported" so the server replies in plaintext.
    assert build_prelogin()[-1] == EncryptionLevel.NOT_SUP


def test_build_prelogin_version_is_first_option():
    # VERSION must be the first directory entry per the spec.
    assert build_prelogin()[0] == PreLoginOption.VERSION


# --- parse_prelogin / parse_prelogin_encryption -------------------------------
# The parsers consume the message *payload* (what Transport.receive_message hands
# back). The fixture stores full on-wire packets, so strip the 8-byte header here.


@pytest.mark.parametrize("frame", [4, 6])
def test_parse_prelogin_encryption_from_capture(raw, frame):
    # Both captured PRELOGINs (client request 4, server reply 6) advertise
    # ENCRYPT_NOT_SUP, which is what lets this session run in plaintext.
    payload = raw(frame)[HEADER_SIZE:]
    assert parse_prelogin_encryption(payload) == EncryptionLevel.NOT_SUP


def test_parse_prelogin_returns_every_option(raw):
    options = parse_prelogin(raw(4)[HEADER_SIZE:])
    # Frame 4 advertises VERSION..TRACEID (tokens 0x00-0x05).
    assert set(options) == {
        PreLoginOption.VERSION,
        PreLoginOption.ENCRYPTION,
        PreLoginOption.INSTOPT,
        PreLoginOption.THREADID,
        PreLoginOption.MARS,
        PreLoginOption.TRACEID,
    }
    assert options[PreLoginOption.VERSION] == bytes.fromhex("080009010000")
    assert options[PreLoginOption.ENCRYPTION] == bytes([EncryptionLevel.NOT_SUP])


def test_parse_prelogin_handles_zero_length_options(raw):
    # Frame 6 (server reply) has empty THREADID and TRACEID options.
    options = parse_prelogin(raw(6)[HEADER_SIZE:])
    assert options[PreLoginOption.THREADID] == b""
    assert options[PreLoginOption.TRACEID] == b""


@pytest.mark.parametrize("level", list(EncryptionLevel))
def test_prelogin_build_parse_roundtrip(level):
    # build_prelogin produces exactly what parse_prelogin consumes — a payload,
    # no packet header on either side.
    payload = build_prelogin(level)
    assert parse_prelogin_encryption(payload) == level
    assert parse_prelogin(payload)[PreLoginOption.VERSION] == bytes.fromhex(
        "000000010000"
    )


def test_parse_prelogin_encryption_raises_when_absent():
    # A directory with only VERSION (no ENCRYPTION option) must raise, not return junk.
    payload = (
        bytes([PreLoginOption.VERSION])
        + (6).to_bytes(2, "big")  # offset
        + (6).to_bytes(2, "big")  # length
        + bytes([PreLoginOption.TERMINATOR])
        + b"\x00\x00\x00\x01\x00\x00"  # version data
    )
    with pytest.raises(ValueError):
        parse_prelogin_encryption(payload)
