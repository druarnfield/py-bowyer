"""IntEnums and protocol constants for the byte/framing layer.

PacketType and Status cover Phase 1 (framing). TokenType / DataType enums are
added in later phases (token parsing / the type system) as they become testable.
"""

from enum import IntEnum, IntFlag

HEADER_SIZE = 8
# Max packet size until LOGIN7 negotiates a different one. Max payload per
# packet = DEFAULT_PACKET_SIZE - HEADER_SIZE.
DEFAULT_PACKET_SIZE = 4096


class PacketType(IntEnum):
    """The Type byte (offset 0) of the 8-byte packet header (MS-TDS §2.2.3.1.1)."""

    SQL_BATCH = 0x01
    RPC = 0x03
    TABULAR_RESULT = 0x04  # every server reply comes back as this type
    ATTENTION = 0x06
    BULK_LOAD = 0x07
    LOGIN7 = 0x10
    PRELOGIN = 0x12


class Status(IntFlag):
    """The Status byte (offset 1) of the packet header (MS-TDS §2.2.3.1.2)."""

    NORMAL = 0x00
    EOM = 0x01  # last packet of a message; drives reassembly
    IGNORE = 0x02
    RESET_CONNECTION = 0x08
    RESET_CONNECTION_SKIP_TRAN = 0x10
