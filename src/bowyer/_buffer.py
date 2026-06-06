"""ByteReader / ByteWriter / PacketHeader — the ONE place struct + endianness live.

The TDS endianness split is baked in here so nothing else needs to think about it:

- The 8-byte packet header has two multi-byte fields (Length, SPID) that are
  *big-endian*. They are sealed inside `PacketHeader`, the only big-endian thing.
- Everything in the payload (values, lengths, offsets) is *little-endian*, so the
  reader/writer primitives are little-endian only and cannot be misused.

This is the only module in the package that imports `struct`.
"""

import struct
from dataclasses import dataclass

from bowyer.constants import HEADER_SIZE, PacketType, Status


@dataclass(frozen=True, slots=True)
class PacketHeader:
    """The 8-byte TDS packet header (MS-TDS §2.2.3.1).

    Layout: Type(1) Status(1) Length(2, BE) SPID(2, BE) PacketID(1) Window(1).
    `length` is the whole packet including this 8-byte header.
    """

    _FORMAT = ">BBHHBB"

    type: PacketType
    status: Status
    length: int
    spid: int = 0
    packet_id: int = 0
    window: int = 0

    def pack(self) -> bytes:
        return struct.pack(
            self._FORMAT,
            int(self.type),
            int(self.status),
            self.length,
            self.spid,
            self.packet_id,
            self.window,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "PacketHeader":
        if len(data) < HEADER_SIZE:
            raise ValueError(f"need {HEADER_SIZE} header bytes, got {len(data)}")
        type_, status, length, spid, packet_id, window = struct.unpack(
            cls._FORMAT, data[:HEADER_SIZE]
        )
        return cls(PacketType(type_), Status(status), length, spid, packet_id, window)

    @property
    def payload_length(self) -> int:
        """Number of payload bytes after the header (Length - 8)."""
        return self.length - HEADER_SIZE

    @property
    def is_eom(self) -> bool:
        """True if this is the last packet of its message."""
        return Status.EOM in self.status


class ByteWriter:
    """Builds a little-endian payload buffer."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def write_uint8(self, value: int) -> None:
        self._buf += struct.pack("<B", value)

    def write_uint16(self, value: int) -> None:
        self._buf += struct.pack("<H", value)

    def write_uint32(self, value: int) -> None:
        self._buf += struct.pack("<I", value)

    def write_int32(self, value: int) -> None:
        self._buf += struct.pack("<i", value)

    def write_bytes(self, data: bytes) -> None:
        self._buf += data

    def write_utf16le(self, text: str) -> None:
        self._buf += text.encode("utf-16-le")

    def getvalue(self) -> bytes:
        return bytes(self._buf)

    def __len__(self) -> int:
        return len(self._buf)


class ByteReader:
    """Reads little-endian primitives from a buffer, tracking a cursor."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def _take(self, n: int) -> int:
        end = self._pos + n
        if end > len(self._data):
            raise ValueError(
                f"read of {n} byte(s) at offset {self._pos} exceeds "
                f"buffer length {len(self._data)}"
            )
        start = self._pos
        self._pos = end
        return start

    def read_uint8(self) -> int:
        return struct.unpack_from("<B", self._data, self._take(1))[0]

    def read_uint16(self) -> int:
        return struct.unpack_from("<H", self._data, self._take(2))[0]

    def read_uint32(self) -> int:
        return struct.unpack_from("<I", self._data, self._take(4))[0]

    def read_int32(self) -> int:
        return struct.unpack_from("<i", self._data, self._take(4))[0]

    def read_bytes(self, n: int) -> bytes:
        start = self._take(n)
        return self._data[start : start + n]

    def read_utf16le(self, byte_len: int) -> str:
        return self.read_bytes(byte_len).decode("utf-16-le")

    @property
    def position(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def eof(self) -> bool:
        return self._pos >= len(self._data)
