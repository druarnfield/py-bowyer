"""
Golden round-trip test for the bowyer TDS driver.

Fixture: a real *plaintext* TDS 7.4 session captured against SQL Server 2022,
client = go-mssqldb via `go-sqlcmd -N disable` (ENCRYPT_NOT_SUP, so no TLS).
Exchange:  PRELOGIN -> LOGIN7 -> SQLBatch "SELECT 1" -> result.

The functions in the REFERENCE section below are a small, verified implementation
included only so this test runs and passes today. As you build bowyer, delete them
one at a time and replace with imports from your package, e.g.:

    from bowyer.login import build_login7, obfuscate_password, deobfuscate_password
    from bowyer.prelogin import parse_prelogin_encryption
    from bowyer.batch import parse_sqlbatch_query

The assertions are the contract your code must satisfy. The headline test is
`test_login7_builder_is_byte_exact`: your LOGIN7 encoder, given the captured
inputs, must reproduce packet #8 on the wire byte-for-byte.

Run:  pytest test_login_select1.py -v
"""

import json
import struct
from pathlib import Path

import pytest

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "login_select1_plaintext.json").read_text()
)
PKT = {p["frame"]: p for p in FIXTURE["packets"]}


def raw(frame: int) -> bytes:
    """Full on-the-wire bytes of a captured packet (incl. 8-byte TDS header)."""
    return bytes.fromhex(PKT[frame]["hex"])


# ============================ REFERENCE ====================================
# Minimal, verified TDS pieces. Replace with `from bowyer... import ...`.


def obfuscate_password(pw: str) -> bytes:
    """ENCODE (client -> wire): UTF-16LE, then per byte: swap nibbles, XOR 0xA5."""
    return bytes((((b << 4) & 0xF0) | (b >> 4)) ^ 0xA5 for b in pw.encode("utf-16-le"))


def deobfuscate_password(b: bytes) -> str:
    """DECODE (wire -> text): per byte XOR 0xA5 then swap nibbles, then UTF-16LE."""
    plain = bytes((((c ^ 0xA5) >> 4) | (((c ^ 0xA5) << 4) & 0xF0)) for c in b)
    return plain.decode("utf-16-le")


def build_login7(
    *,
    tds_version,
    packet_size,
    client_prog_ver,
    client_pid,
    connection_id,
    option_flags1,
    option_flags2,
    type_flags,
    option_flags3,
    client_timezone,
    client_lcid,
    client_id_mac,
    host,
    user,
    password,
    app,
    server,
    library,
) -> bytes:
    """Build a complete LOGIN7 TDS packet (header + message).

    Layout: 36-byte fixed header, then a 58-byte variable table of
    (offset,length) pairs + the inline 6-byte ClientID (MAC), then the data
    block of UTF-16LE strings. Offsets are bytes from the start of the LOGIN7
    message; lengths are character counts. The password bytes are obfuscated.
    """
    enc = lambda s: s.encode("utf-16-le")
    data = bytearray()
    pos = 94  # data block begins right after the 36-byte header + 58-byte table
    pairs = {}

    def put(name, blob, char_len):
        nonlocal pos
        pairs[name] = (pos, char_len)
        data.extend(blob)
        pos += len(blob)

    put("host", enc(host), len(host))
    put("user", enc(user), len(user))
    put("pass", obfuscate_password(password), len(password))
    put("app", enc(app), len(app))
    put("server", enc(server), len(server))
    pairs["unused"] = (0, 0)  # Extension: pinned to 0 (go-mssqldb convention)
    put("lib", enc(library), len(library))
    pairs["lang"] = (pos, 0)  # empty trailing fields point at the data end
    pairs["db"] = (pos, 0)
    end = pos

    body = bytearray()
    body += struct.pack(
        "<IIIII", tds_version, packet_size, client_prog_ver, client_pid, connection_id
    )
    body += bytes([option_flags1, option_flags2, type_flags, option_flags3])
    body += struct.pack("<iI", client_timezone, client_lcid)
    for nm in ("host", "user", "pass", "app", "server", "unused", "lib", "lang", "db"):
        body += struct.pack("<HH", *pairs[nm])
    body += bytes.fromhex(client_id_mac)  # 6-byte ClientID, inline in the table
    body += struct.pack("<HH", end, 0)  # ibSSPI / cbSSPI
    body += struct.pack("<HH", end, 0)  # ibAtchDBFile / cchAtchDBFile
    body += struct.pack("<HH", end, 0)  # ibChangePassword / cchChangePassword
    body += struct.pack("<I", 0)  # cbSSPILong
    body += data

    msg = struct.pack("<I", len(body) + 4) + bytes(body)  # prepend total Length
    # TDS packet header: NOTE the length is BIG-endian, everything else LE.
    header = struct.pack(">BBHHBB", 0x10, 0x01, len(msg) + 8, 0, 1, 0)
    return header + msg


def parse_prelogin_encryption(packet: bytes) -> int:
    """Return the ENCRYPTION option byte (0=OFF,1=ON,2=NOT_SUP,3=REQ)."""
    body = packet[8:]  # strip 8-byte TDS header; option offsets are relative to here
    i = 0
    while body[i] != 0xFF:  # 0xFF = option terminator
        token = body[i]
        offset, length = struct.unpack_from(
            ">HH", body, i + 1
        )  # PRELOGIN offsets are BE
        if token == 0x01:  # ENCRYPTION
            return body[offset]
        i += 5
    raise AssertionError("no ENCRYPTION option found")


def parse_sqlbatch_query(packet: bytes) -> tuple[int, str]:
    """Return (all_headers_total_length, query_text) from a SQLBatch packet."""
    body = packet[8:]
    all_headers_total = struct.unpack_from("<I", body, 0)[0]
    text = body[all_headers_total:].decode("utf-16-le")
    return all_headers_total, text


def decode_select1_result(packet: bytes) -> dict:
    """Walk the token stream of the SELECT 1 result; return key fields."""
    body = packet[8:]
    i = 0
    out = {}
    while i < len(body):
        token = body[i]
        if token == 0xE3:  # ENVCHANGE: token + USHORT length + data
            length = struct.unpack_from("<H", body, i + 1)[0]
            i += 3 + length
        elif token == 0x81:  # COLMETADATA
            count = struct.unpack_from("<H", body, i + 1)[0]
            assert count == 1
            col = i + 3  # skip token(1) + count(2)
            out["column_type"] = body[col + 6]  # after usertype(4) + flags(2)
            namelen = body[col + 7]
            i = col + 8 + namelen * 2  # column = 8 bytes + name (chars*2)
        elif token == 0xD1:  # ROW (one fixed-len INT4 column)
            out["row_value"] = struct.unpack_from("<i", body, i + 1)[0]
            i += 1 + 4
        elif token == 0xFD:  # DONE: status(2) curcmd(2) rowcount(8)
            out["done_rowcount"] = struct.unpack_from("<Q", body, i + 5)[0]
            i += 1 + 12
        else:
            break
    return out


# ============================== TESTS ======================================


def test_prelogin_negotiates_not_supported():
    # Both client and server advertise ENCRYPT_NOT_SUP (0x02) -> fully plaintext.
    assert parse_prelogin_encryption(raw(4)) == 2
    assert parse_prelogin_encryption(raw(6)) == 2


def test_password_obfuscation_roundtrips():
    pw = FIXTURE["login7_rebuild"]["inputs"]["password"]
    assert deobfuscate_password(obfuscate_password(pw)) == pw


def test_login7_password_decodes_from_wire():
    # Pull the obfuscated password straight out of the captured LOGIN7 and decode.
    msg = raw(8)[8:]
    off, length = struct.unpack_from("<HH", msg, 36 + 2 * 4)  # 3rd offset/len pair
    on_wire = msg[off : off + length * 2]
    assert deobfuscate_password(on_wire) == "Bowyer_Dev2026!"


def test_login7_builder_is_byte_exact():
    # The headline contract: rebuild LOGIN7 from the captured inputs and require
    # it to match packet #8 on the wire, byte for byte.
    built = build_login7(**FIXTURE["login7_rebuild"]["inputs"])
    assert built == raw(FIXTURE["login7_rebuild"]["expected_frame"])


def test_login_response_has_loginack_from_sql2022():
    payload = raw(9)
    assert 0xAD in payload  # LOGINACK token present
    assert "sql2022".encode("utf-16-le") in payload  # server names itself


def test_sqlbatch_carries_all_headers_then_query():
    total, text = parse_sqlbatch_query(raw(11))
    assert total == 22  # the ALL_HEADERS prefix the server requires
    assert text == "SELECT 1;"


def test_result_is_one_int_column_value_1():
    r = decode_select1_result(raw(12))
    assert r["column_type"] == 0x38  # INT4 (fixed 4-byte int)
    assert r["row_value"] == 1
    assert r["done_rowcount"] == 1
