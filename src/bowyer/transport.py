"""Socket + 8-byte packet header + packet<->message reassembly.

A TDS *message* is one or more *packets*. Each packet has an 8-byte header and a
payload; the final packet of a message has the EOM status bit set. This module
splits outgoing payloads across packets and reassembles incoming ones, delegating
all byte/struct handling to `_buffer` (this file never imports `struct`).
"""

import socket

from bowyer._buffer import PacketHeader
from bowyer.constants import DEFAULT_PACKET_SIZE, HEADER_SIZE, PacketType, Status


class TransportError(Exception):
    """A framing/socket-level failure. Placeholder until exceptions.py lands."""


class Transport:
    """Sends and receives whole TDS messages over a socket."""

    def __init__(self, sock) -> None:
        self._sock = sock
        self._packet_size = DEFAULT_PACKET_SIZE

    @classmethod
    def connect(cls, host: str, port: int = 1433, timeout: float = 10.0) -> "Transport":
        return cls(socket.create_connection((host, port), timeout=timeout))

    def close(self) -> None:
        self._sock.close()

    def send_message(
        self,
        packet_type: PacketType,
        payload: bytes,
        *,
        packet_size: int = DEFAULT_PACKET_SIZE,
    ) -> None:
        """Split `payload` across packets, setting EOM only on the last one."""
        max_payload = packet_size - HEADER_SIZE
        # Chunk into max_payload-sized pieces; an empty payload still sends one
        # (EOM) packet so the peer sees a complete message.
        chunks = [
            payload[i : i + max_payload] for i in range(0, len(payload), max_payload)
        ] or [b""]

        for packet_id, chunk in enumerate(chunks):
            is_last = packet_id == len(chunks) - 1
            header = PacketHeader(
                type=packet_type,
                status=Status.EOM if is_last else Status.NORMAL,
                length=len(chunk) + HEADER_SIZE,
                spid=0,
                packet_id=packet_id % 256,
                window=0,
            )
            self._sock.sendall(header.pack() + chunk)

    def receive_message(self) -> tuple[PacketType, bytes]:
        """Read packets until EOM, returning (message type, reassembled payload)."""
        buf = bytearray()
        message_type: PacketType | None = None
        while True:
            header = PacketHeader.unpack(self._recv_exact(HEADER_SIZE))
            if message_type is None:
                message_type = header.type
            buf += self._recv_exact(header.payload_length)
            if header.is_eom:
                break
        return message_type, bytes(buf)

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly `n` bytes, looping over partial recv() results."""
        chunks = []
        remaining = n
        while remaining > 0:
            chunk = self._sock.recv(remaining)
            if not chunk:
                raise TransportError(
                    f"connection closed with {remaining} of {n} byte(s) unread"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
