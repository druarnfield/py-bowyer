# Design: Zig port of the bowyer TDS driver (Phase 0–2 parity)

## Context

`bowyer` is a from-scratch pure-Python Microsoft TDS driver, currently built
through the start of Phase 2 of `docs/roadmap/phases.md`. We want a parallel
implementation in **Zig**, living under `./zig`, that mirrors the *current*
Python feature state and uses idiomatic Zig rather than transliterated Python.

**Why:** a second implementation in a systems language (a) validates the
protocol understanding by re-deriving it against the same byte-for-byte capture
oracle, (b) gives a path to a fast, dependency-free native driver, and (c) keeps
one shared conformance corpus (the Wireshark capture) honest across two
languages.

**Scope decision (confirmed):** *mirror the current Python state*, not the full
roadmap Phase 2. So we port the layers that are actually implemented in Python —
byte buffer, framing/transport, constants, PRELOGIN build+parse — and leave the
LOGIN7 / password-obfuscation / handshake layer as **stubs** (`error.NotImplemented`),
exactly as `src/bowyer/login.py` is scaffolded today.

Target toolchain: **Zig 0.16.0** (current stable; post-"Writergate" `std.Io`,
unmanaged `std.ArrayList` by default, networking under `std.Io.net`). Verify std
APIs by compiling, not from memory.

## Parity surface (what exists in Python today)

| Python file | Public surface | Port? |
|---|---|---|
| `src/bowyer/_buffer.py` | `ByteReader`, `ByteWriter` (LE primitives + `*_be` u16), `PacketHeader` (pack/unpack, `payload_length`, `is_eom`, length≥8 guard), `_pack` named-error wrapping | **Yes** |
| `src/bowyer/constants.py` | `HEADER_SIZE`, `DEFAULT_PACKET_SIZE`, `PacketType`, `Status` (flags), `PreLoginOption`, `EncryptionLevel` | **Yes** |
| `src/bowyer/transport.py` | `Transport` (send_message chunking + 1-based packet_id mod 256 + EOM; receive_message reassembly; `_recv_exact` short-read loop; packet_size 512–32767 validation; close), `TransportError` | **Yes** |
| `src/bowyer/prelogin.py` | `build_prelogin`, `parse_prelogin`, `parse_prelogin_encryption`, `CLIENT_VERSION`/`CLIENT_SUBBUILD` | **Yes** |
| `src/bowyer/login.py` | `obfuscate_password`, `deobfuscate_password`, `LoginConfig`, `build_login7`, `build_login7_for`, `do_handshake` | **Stub only** |

## Idiomatic-Zig mapping (not a transliteration)

- **Endianness** → `std.mem.writeInt`/`readInt(T, …, .little|.big)`. No separate
  `_be` method names: endianness is a parameter. The "all endianness in one
  place" invariant becomes "only `buffer.zig` imports the int-serialization
  helpers."
- **`ByteReader`/`ByteWriter`** → a small `Reader` over `[]const u8` with a
  cursor (bounds-checked, returns `error.EndOfBuffer`) and a `Writer` wrapping
  `std.ArrayList(u8)` (allocator-based). Methods: `readInt(comptime T, endian)`,
  `readBytes(n)`, `writeInt(comptime T, value, endian)`, `writeBytes`,
  `writeUtf16Le`. Errors replace Python's `ValueError`/`struct.error`.
- **`PacketHeader`** → a plain struct with `pack(*Writer)`/`unpack([]const u8)
  !PacketHeader`. Not a `packed struct` (host-endian packed layout can't express
  the big-endian header). `unpack` enforces `length >= HEADER_SIZE`
  (`error.PacketTooShort`).
- **`Status`** → `packed struct(u8)` of `bool` fields (`eom`, `ignore`,
  `reset_connection`, …) with reserved padding bits, `@bitCast` to/from `u8`.
  `header.status.eom` replaces `Status.EOM in status`.
- **`PacketType`/`PreLoginOption`/`EncryptionLevel`** → `enum(u8)`.
- **`Transport`** → comptime-generic: `pub fn Transport(comptime Stream: type)
  type`. `Stream` is duck-typed to need `read([]u8) !usize` +
  `writeAll([]const u8) !void`. Offline tests instantiate with an in-memory
  `FakeStream` (slice of scripted read-chunks + an `ArrayList` capturing writes —
  the `FakeSocket` equivalent). Live uses `std.net.Stream`.
  - `sendMessage(packet_type, payload)` writes header+chunk per packet straight
    to the stream — no big allocation.
  - `receiveMessage(allocator) -> struct{ type: PacketType, payload: []u8 }`
    accumulates into an `ArrayList`; caller owns/frees.
  - `recvExact(buf)` loops over short reads; closed mid-message →
    `error.ConnectionClosed`.
  - packet size validated at `init`/`setPacketSize` (`error.InvalidPacketSize`).
  - No context manager — `defer transport.deinit()` is the Zig idiom; port
    `close` behavior, drop the `__enter__/__exit__`-specific test.
- **`prelogin`** → `buildPrelogin(allocator, encryption) ![]u8` (owned slice).
  `parsePreloginEncryption(payload) !EncryptionLevel` walks the directory with
  **zero allocation** (the one that matters). `parsePrelogin(allocator, payload)`
  returns a slice of `{ option, data: []const u8 }` entries whose `data` slices
  **borrow** the input payload (no per-option copy) — replaces Python's dict.
  Missing ENCRYPTION → `error.MissingEncryptionOption`.
- **`login`** → real `LoginConfig` struct + signatures; every function body is
  `return error.NotImplemented;` (the Zig analog of `raise NotImplementedError`).

## Project layout

```
zig/
  build.zig            # module "bowyer"; test step; @embedFile of shared fixture; -Dlive flag
  build.zig.zon        # manifest (name, version, .paths)
  src/
    root.zig           # re-exports public API; test aggregator (_ = @import each file)
    buffer.zig         # Reader, Writer, PacketHeader  (+ colocated tests)
    constants.zig      # enums + consts                (+ tests)
    transport.zig      # Transport(Stream) + FakeStream test helper (+ tests)
    prelogin.zig       # build/parse                   (+ tests)
    login.zig          # stubs                         (+ stub-asserting tests)
    fixture.zig        # test-only: parse embedded JSON, expose raw(frame) -> []const u8
```

Tests are **colocated** in each source file via `test "…"` blocks (idiomatic
Zig). `root.zig` references every file so `zig build test` discovers all blocks.

## Shared test oracle

The Python fixture `tests/fixtures/login_select1_plaintext.json` stays the single
source of truth. In `build.zig`, add it as an anonymous import to the test
module (`module.addAnonymousImport("fixture_json", .{ .root_source_file =
b.path("../tests/fixtures/login_select1_plaintext.json") })`), then in
`fixture.zig` do `const json = @embedFile("fixture_json");` and parse with
`std.json`. `raw(frame)` returns the captured packet bytes (hex-decoded),
mirroring the `raw` pytest fixture. No second copy, no cwd dependence; recapturing
updates both languages at once.

## Tests to port (offline, byte-for-byte against the capture)

- **buffer**: header unpack/pack round-trip over all capture frames; non-zero
  server SPID (frame 9 = 65); status flag field (frame 11 = EOM|RESET_CONNECTION);
  length<8 rejected; LE primitive round-trip; BE u16 read/write; reader overrun
  → error; position/remaining; the LOGIN7 LE length-prefix vs BE header-length
  cross-check (frame 8).
- **transport**: receive single / two-packet / chunked (1–3 byte reads) / closed
  mid-header; all captured replies single-packet; real frame-9 payload re-framed
  into multiple packets and reassembled; undersized length rejected; send single
  / chunked / empty / send→receive round-trip; packet_size validation; close.
- **prelogin**: `build_prelogin` byte-exact; encryption carried for all 4 levels;
  default NOT_SUP; VERSION first; parse encryption from frames 4 & 6; parse all 6
  options from frame 4; zero-length options (frame 6); build→parse round-trip;
  missing-encryption raises.
- **login**: each stub returns `error.NotImplemented`.
- **live (gated)**: `-Dlive` (or env var) → connect to the Docker SQL Server
  (`compose.yml`), send a PRELOGIN, assert a Type-4 reply parses to a non-`REQ`
  encryption level. Absent the flag → `return error.SkipZigTest;`.

## Verification

- `cd zig && zig build test` → all offline tests pass, login stubs assert
  `error.NotImplemented`, output clean.
- `cd zig && zig build` → library compiles.
- Live: `docker compose up -d` then `cd zig && zig build test -Dlive` → the gated
  test connects and gets a Type-4 PRELOGIN response.
- Cross-check: the Zig `build_prelogin` byte-exact test and the Python
  `test_build_prelogin_is_byte_exact` assert the *same* 18-byte payload.

## Out of scope (matches Python today)

LOGIN7 encoding, password obfuscation, the handshake driver, token parsing
(Phase 3+), TLS, and wiring Zig into `.github/workflows/ci.yml` (follow-up).

## Risks / notes

- **Toolchain pin** — the machine has both 0.17-dev and 0.16.0 on PATH; the
  project targets **0.16.0** (`build.zig.zon` `minimum_zig_version`). Networking
  uses `std.Io.net` (the `Stream` exposes only buffered `reader()`/`writer()`, so
  `NetStream` holds persistent reader/writer pointing at its own buffers and must
  not be copied after `connect`).
- **`@embedFile` across the package root** — the fixture lives outside `./zig`;
  the anonymous-import approach in `build.zig` is the supported way to embed it.
  Fallback: copy the fixture into `zig/testdata/` (a second oracle — avoid unless
  the import approach fails on this toolchain).
