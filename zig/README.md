# bowyer (Zig)

A pure-Zig port of the `bowyer` Microsoft TDS driver, at Phase 0–2 parity with
the Python implementation: byte buffer, packet framing + reassembly, protocol
constants, and PRELOGIN build/parse. LOGIN7, password obfuscation, and the
handshake are stubbed (`error.NotImplemented`), mirroring the Python driver.

## Toolchain

Targets **Zig 0.16.0** (current stable). This machine also has a 0.17-dev build
on `PATH`; if `zig version` doesn't report 0.16.0, invoke it explicitly, e.g.
`/opt/homebrew/bin/zig`.

## Build & test

```sh
zig build test          # offline suite (live test auto-skips)
zig build               # compile the library module
```

The tests reuse the SAME capture oracle as the Python tests
(`../tests/fixtures/login_select1_plaintext.json`), embedded at compile time and
parsed with `std.json`. The Zig and Python byte-exact PRELOGIN tests assert the
same bytes.

### Live integration test

Gated behind `-Dlive`; needs a SQL Server reachable on `127.0.0.1:1433`
(see `../compose.yml`):

```sh
docker compose -f ../compose.yml up -d
zig build test -Dlive   # connects, sends PRELOGIN, asserts a Type-4 reply
```

## Layout

| File | Role |
|---|---|
| `src/constants.zig` | `PacketType`, `Status` (packed flags), `PreLoginOption`, `EncryptionLevel` |
| `src/buffer.zig` | `Reader`, `Writer`, `PacketHeader` (endianness via `std.mem`) |
| `src/transport.zig` | `Transport(Stream)` framing/reassembly; `NetStream` socket binding; `FakeStream` (tests) |
| `src/prelogin.zig` | `buildPrelogin`, `parsePrelogin`, `parsePreloginEncryption` |
| `src/login.zig` | LOGIN7 / obfuscation / handshake — stubs |
| `src/fixture.zig` | test-only shared-capture loader |
| `src/live.zig` | gated live integration test |

Tests are colocated in each source file (`test "…"` blocks) and aggregated by
`src/root.zig`.
