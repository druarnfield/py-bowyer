"""Build and parse PRELOGIN (Type 18) — the encryption/option negotiation.

PRELOGIN is the first message of the handshake (MS-TDS §2.2.6.5). The payload is
a tiny *option directory* — a list of (token, offset, length) entries terminated
by ``0xFF`` — followed by the option-data blobs the offsets point into:

    repeated:  TOKEN (1)  Offset (2, BE)  Length (2, BE)
    then:      0xFF  (TERMINATOR)
    then:      <data blobs>

Note the offsets/lengths here are **big-endian** (like the packet header, unlike
the rest of the payload), so all packing/unpacking is done via `_buffer` where
endianness lives — this module never imports `struct`.

v1 scope: advertise VERSION + ENCRYPTION=NOT_SUP so the server replies in
plaintext. If the server demands ENCRYPT_REQ we abort — TLS-in-TDS is out of v1.
"""

from bowyer._buffer import ByteReader, ByteWriter
from bowyer.constants import EncryptionLevel, PreLoginOption

_OPTION_ENTRY_SIZE = 5  # token (1) + offset (2, BE) + length (2, BE)

# Client version advertised in the VERSION option (UL_VERSION: 4-byte version +
# 2-byte subbuild). Driver-identity policy, not protocol vocabulary — cosmetic for
# SQL auth, so it lives here next to the only code that uses it (not in constants).
CLIENT_VERSION: tuple[int, int, int, int] = (0, 0, 0, 1)
CLIENT_SUBBUILD: int = 0


def build_prelogin(encryption: EncryptionLevel = EncryptionLevel.NOT_SUP) -> bytes:
    """Build a PRELOGIN *payload* (no 8-byte packet header) advertising our options.

    Lays out the option directory in order — VERSION (from `CLIENT_VERSION` /
    `CLIENT_SUBBUILD`), then ENCRYPTION (the `encryption` arg), then the 0xFF
    terminator — back-fills each entry's big-endian offset/length to point at its
    blob in the trailing data section, and appends the blobs.

    Returns bytes ready for ``Transport.send_message(PacketType.PRELOGIN, ...)``.
    v1 sends only VERSION + ENCRYPTION; INSTOPT/THREADID/MARS/etc. are omitted.
    """
    version = ByteWriter()
    version.write_bytes(bytes(CLIENT_VERSION))  # 4-byte version
    version.write_uint16_be(CLIENT_SUBBUILD)  # 2-byte subbuild
    options = [
        (PreLoginOption.VERSION, version.getvalue()),
        (PreLoginOption.ENCRYPTION, bytes([encryption])),
    ]

    # The data section starts right after the directory (one entry per option plus
    # the 1-byte terminator). Walk the options once, writing each directory entry
    # with the running offset while accumulating the blobs that follow it.
    directory = ByteWriter()
    data = ByteWriter()
    offset = len(options) * _OPTION_ENTRY_SIZE + 1
    for token, blob in options:
        directory.write_uint8(token)
        directory.write_uint16_be(offset)
        directory.write_uint16_be(len(blob))
        data.write_bytes(blob)
        offset += len(blob)
    directory.write_uint8(PreLoginOption.TERMINATOR)

    return directory.getvalue() + data.getvalue()


def parse_prelogin(payload: bytes) -> dict[PreLoginOption, bytes]:
    """Parse a PRELOGIN response *payload* into ``{option: raw_data_bytes}``.

    Takes the reassembled message payload as handed back by
    ``Transport.receive_message()`` — packet headers are already stripped, so this
    sees only the option directory + data. Walks the directory until TERMINATOR,
    slicing each option's blob out of the data section using its big-endian
    offset/length. All standard PRELOGIN tokens are modeled by `PreLoginOption`;
    an unrecognized token raises (it signals an unexpected server, not a stream we
    should silently skip).
    """
    reader = ByteReader(payload)
    options: dict[PreLoginOption, bytes] = {}
    while True:
        token = reader.read_uint8()
        if token == PreLoginOption.TERMINATOR:
            break
        offset = reader.read_uint16_be()
        length = reader.read_uint16_be()
        # Offsets are relative to the start of the payload — the directory we're
        # reading and the data we're slicing share the same `payload` buffer.
        options[PreLoginOption(token)] = payload[offset : offset + length]
    return options


def parse_prelogin_encryption(payload: bytes) -> EncryptionLevel:
    """Return the server's ENCRYPTION level from a PRELOGIN response payload.

    Convenience over `parse_prelogin`: pulls the ENCRYPTION (0x01) option's single
    byte. Raises if the server sent no ENCRYPTION option. Drives the v1 decision —
    anything other than `EncryptionLevel.REQ` means we may proceed in plaintext.

    Contract: matches `tests/test_login_select1.py` (captured frames 4 & 6 → NOT_SUP).
    """
    options = parse_prelogin(payload)
    if PreLoginOption.ENCRYPTION not in options:
        raise ValueError("PRELOGIN response has no ENCRYPTION option")
    return EncryptionLevel(options[PreLoginOption.ENCRYPTION][0])
