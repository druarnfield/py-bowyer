"""Build LOGIN7 (Type 16) with SQL auth, password obfuscation, and the
PRELOGIN→LOGIN7 handshake orchestration.

LOGIN7 (MS-TDS §2.2.6.4) is the offset-addressed record that carries SQL-auth
credentials and connection options. A fixed prefix of (offset, length) pairs
points into a trailing UTF-16LE data block; you build the data block first, then
back-fill the offsets. The password is lightly *obfuscated* (nibble-swap + XOR
0xA5) — not encrypted.

⚠️ One wrong byte = silent rejection by the server, so `build_login7` is verified
byte-for-byte against the Wireshark capture (`test_login7_builder_is_byte_exact`).

All struct/endianness goes through `_buffer` (ByteReader/ByteWriter); this module
never imports `struct`.
"""

from dataclasses import dataclass

from bowyer.constants import DEFAULT_PACKET_SIZE
from bowyer.transport import Transport

# --- password obfuscation -----------------------------------------------------


def obfuscate_password(password: str) -> bytes:
    """Encode a password into its LOGIN7 wire form (§2.2.6.4).

    UTF-16LE encode, then per byte: swap the two nibbles and XOR with 0xA5. This
    is obfuscation, not encryption — trivially reversible (see
    `deobfuscate_password`); it offers no real protection on an unencrypted link.
    """
    raise NotImplementedError


def deobfuscate_password(data: bytes) -> str:
    """Reverse `obfuscate_password`: per byte XOR 0xA5 then swap nibbles, then
    UTF-16LE decode. Used by tests to read a password back out of a captured
    LOGIN7 and to prove the transform round-trips."""
    raise NotImplementedError


# --- caller-facing config -----------------------------------------------------


@dataclass(frozen=True, slots=True)
class LoginConfig:
    """The caller-facing inputs for a login: who connects, where, and as whom.

    The high-level layer (`build_login7_for` / `do_handshake`) expands these few
    values into the dozens of low-level LOGIN7 protocol fields using driver
    defaults, so callers never touch flag bytes or version words directly.
    """

    host: str  # SQL Server hostname; also sent as the LOGIN7 "server name"
    user: str
    password: str
    database: str = ""  # "" → server's default database
    app_name: str = "bowyer"
    client_host: str = ""  # this client's hostname; "" is acceptable
    library: str = "bowyer"


# --- LOGIN7 encoders ----------------------------------------------------------


def build_login7(
    *,
    tds_version: int,
    packet_size: int,
    client_prog_ver: int,
    client_pid: int,
    connection_id: int,
    option_flags1: int,
    option_flags2: int,
    type_flags: int,
    option_flags3: int,
    client_timezone: int,
    client_lcid: int,
    client_id_mac: str,
    host: str,
    user: str,
    password: str,
    app: str,
    server: str,
    library: str,
) -> bytes:
    """Build a complete LOGIN7 packet (8-byte header + message), byte-exact.

    The low-level encoder: every protocol field is an explicit keyword argument so
    the output can be diffed against the capture. Layout (§2.2.6.4):

      * 36-byte fixed prefix: total length, TDS version, requested packet size,
        client program version / PID / connection id, the four option-flag bytes,
        timezone and LCID;
      * a variable table of (offset, length) pairs for host/user/password/app/
        server/library/… with the 6-byte ClientID (`client_id_mac`, a hex string)
        inline;
      * the UTF-16LE data block the offsets point into (password via
        `obfuscate_password`).

    Offsets are bytes from the start of the LOGIN7 message; string lengths are
    *character* counts. Contract: given the captured inputs this reproduces packet
    #8 on the wire exactly (`test_login7_builder_is_byte_exact`). Keep all packing
    in `_buffer`.
    """
    raise NotImplementedError


def build_login7_for(
    config: LoginConfig, *, packet_size: int = DEFAULT_PACKET_SIZE
) -> bytes:
    """Ergonomic wrapper: build a LOGIN7 packet from a `LoginConfig` + defaults.

    Fills the low-level fields `build_login7` requires — TDS 7.4 version, a client
    program version / PID, the default option-flag bytes, LCID / timezone, a zeroed
    ClientID — with driver constants, maps `config` onto host/user/password/app/
    server/library, then delegates to `build_login7`. This is what the connection
    layer (Phase 6) will call.
    """
    raise NotImplementedError


# --- handshake orchestration --------------------------------------------------


def do_handshake(transport: Transport, config: LoginConfig) -> bytes:
    """Run PRELOGIN → LOGIN7 over `transport`; return the raw Type-4 login reply.

    Steps:
      1. send PRELOGIN advertising ENCRYPTION=NOT_SUP, read the response;
      2. parse the server's ENCRYPTION level — abort if it is `EncryptionLevel.REQ`
         (TLS-in-TDS is out of v1 scope);
      3. send the LOGIN7 built from `config`;
      4. read and return the server's Type-4 response payload (unparsed — token
         parsing arrives in Phase 3).

    Phase 2 "done when": this returns a Type-4 blob, even if not yet decoded.
    (Likely migrates into `connection.py` in Phase 6.)
    """
    raise NotImplementedError
