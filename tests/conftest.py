"""Pytest fixtures shared across the suite.

- `raw`: returns the full on-the-wire bytes of a captured packet (incl. the
  8-byte TDS header) from the golden plaintext fixture, keyed by frame number.
- `fake_socket`: a factory for an offline stand-in socket used to drive the
  transport layer without a real connection. Its `recv()` hands back scripted
  chunks (each call returns at most `n` bytes, and never more than the next
  scripted chunk), which lets tests exercise partial-read reassembly.

The `live` marker is registered in pyproject.toml ([tool.pytest.ini_options]).
"""

import json
from pathlib import Path

import pytest

_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "login_select1_plaintext.json"


@pytest.fixture(scope="session")
def raw():
    """Return `raw(frame) -> bytes`: full on-wire bytes of a captured packet."""
    fixture = json.loads(_FIXTURE_PATH.read_text())
    packets = {p["frame"]: bytes.fromhex(p["hex"]) for p in fixture["packets"]}

    def _raw(frame: int) -> bytes:
        return packets[frame]

    return _raw


class FakeSocket:
    """Offline socket stand-in.

    `recv_chunks` is the scripted sequence handed out by successive `recv()`
    calls; each `recv(n)` returns at most `n` bytes and at most one chunk, so
    small chunks simulate the kernel returning fewer bytes than requested.
    Once the script is exhausted `recv()` returns b"" (peer closed). Bytes
    passed to `sendall()` accumulate in `self.sent`.
    """

    def __init__(self, recv_chunks=()):
        self._recv_chunks = [bytes(c) for c in recv_chunks]
        self.sent = bytearray()
        self.closed = False

    def recv(self, n: int) -> bytes:
        if n <= 0 or not self._recv_chunks:
            return b""
        chunk = self._recv_chunks[0]
        if len(chunk) <= n:
            return self._recv_chunks.pop(0)
        self._recv_chunks[0] = chunk[n:]
        return chunk[:n]

    def sendall(self, data) -> None:
        self.sent.extend(data)

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_socket():
    """Return the FakeSocket factory; call it with scripted recv chunks."""
    return FakeSocket
