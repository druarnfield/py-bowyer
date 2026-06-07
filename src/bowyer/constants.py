"""IntEnums and protocol constants — the protocol's wire vocabulary.

PacketType and Status cover Phase 1 (framing); PreLoginOption and EncryptionLevel
cover Phase 2 (the handshake). TokenType / DataType enums are added in later phases
(token parsing / the type system) as they become testable.

This file is for the *protocol's* fixed vocabulary; driver-identity/policy defaults
(e.g. the version bowyer advertises) live next to the code that uses them.
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

    NORMAL = 0x00  # zero-valued label for "no flags"; not membership-testable
    EOM = 0x01  # last packet of a message; drives reassembly
    IGNORE = 0x02
    RESET_CONNECTION = 0x08
    RESET_CONNECTION_SKIP_TRAN = 0x10


class PreLoginOption(IntEnum):
    """
    PRELOGIN option tokens (MS-TDS §2.2.6.5).
    VERSION must be first; 0xFF terminates.
    """

    VERSION = 0x00
    ENCRYPTION = 0x01
    INSTOPT = 0x02
    THREADID = 0x03
    MARS = 0x04
    TRACEID = 0x05
    FEDAUTHREQUIRED = 0x06
    TERMINATOR = 0xFF


class EncryptionLevel(IntEnum):
    """The 1-byte ENCRYPTION option value (MS-TDS §2.2.6.5)."""

    OFF = 0x00  # encryption available, currently off
    ON = 0x01  # encryption available, currently on
    NOT_SUP = 0x02  # encryption not supported by this side
    REQ = 0x03  # encryption required (forces TLS — out of v1 scope)
