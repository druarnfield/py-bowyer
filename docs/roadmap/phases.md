# TDS Python Driver — v1 Build Checklist

Build order for a minimum-viable pure-Python TDS client: SQL auth, run a
`SELECT`, decode the result. Phases 0–4 are a **chain** (each blocks the next);
phases 5–7 **fan out** and can be reordered. Goal: reach a working end-to-end
thread (Phase 4) as fast as possible, then add breadth.

Companion docs: `tds-cheatsheet.md` (protocol reference), [MS-TDS] spec.

---

## Phase 0 — Ground truth & scaffolding
*Do this before any protocol code.*

- [x] Run SQL Server in Docker (`mcr.microsoft.com/mssql/server:2022-latest`, `MSSQL_SA_PASSWORD`, port 1433, Developer edition)
- [x] Confirm **encryption is optional, not forced** (so PRELOGIN can negotiate it off / plaintext is visible)
- [x] Connect with `sqlcmd` (go-sqlcmd) and run `SELECT 1` successfully
- [x] Install Wireshark; enable loopback capture (`lo` / `lo0` / Npcap loopback on Windows)
- [x] Capture a real `sqlcmd` login + `SELECT 1`; enable "Reassemble fragmented TDS messages"; filter `tds`
- [x] Save that capture — it's the byte-for-byte oracle for the whole project
- [x] Lay down repo skeleton: src layout, `pyproject.toml` (PEP 621), pytest, ruff
- [x] `pip install -e .` / `uv sync` works; empty package imports

**Done when:** a labelled capture of a real login + `SELECT 1` exists, and the empty package imports.

---

## Phase 1 — Byte layer & framing
*Files: `_buffer.py`, `transport.py`, `constants.py`*

- [ ] `ByteReader` / `ByteWriter` with endianness-correct primitives (header = big-endian, payload = little-endian — bake the split in here)
- [ ] Unit-test the buffer against header bytes from the capture (offline, no socket)
- [ ] `transport.py`: socket connect, write a packet (8-byte header + payload)
- [ ] Read a packet; reassemble multi-packet messages by the EOM status bit
- [ ] `constants.py`: enums added as needed (PacketType, Status flags so far)

**Done when:** you can send an arbitrary payload in a valid packet and read back a fully reassembled server message (even if unparsed). Header pack/unpack matches the capture.

---

## Phase 2 — The handshake (the scary part)
*Files: `prelogin.py`, `login.py`*

- [ ] Build + send PRELOGIN (Type 18); parse the option directory in the response
- [ ] Confirm the server accepts encryption **off** (not ENCRYPT_REQ)
- [ ] Build LOGIN7 (Type 16) with SQL auth (offset-addressed fields)
- [ ] Implement password obfuscation (XOR `0xA5` + nibble-swap; verify order vs §2.2.6.4)
- [ ] **Diff your LOGIN7 against the Wireshark capture byte-for-byte** ⚠️ #1 stall point
- [ ] Send LOGIN7; receive a Type-4 response back

**Done when:** PRELOGIN + LOGIN7 produce a Type-4 response (even as an unparsed blob).

---

## Phase 3 — Minimal token parsing (know if login worked)
*File: `tokens.py`*

- [ ] Token loop + the four length shapes (zero / fixed / variable / variable-count)
- [ ] Handle LOGINACK (`0xAD`), skip ENVCHANGE (`0xE3`)
- [ ] Parse ERROR (`0xAA`) and INFO (`0xAB`) — makes all later failures legible
- [ ] Recognize-and-skip unknown tokens (don't crash)

**Done when:** you can distinguish "login succeeded" from "login failed: &lt;readable message&gt;".

---

## Phase 4 — The thin end-to-end thread 🎯
*Files: `batch.py`, + `tokens.py`, + minimal `types.py`*

- [ ] Build SQLBatch (Type 1): ALL_HEADERS stub + SQL text as UTF-16LE
- [ ] **Diff ALL_HEADERS against the capture** ⚠️ #2 stall point (wrong stub = silent rejection)
- [ ] Send `SELECT 1`
- [ ] Parse COLMETADATA (`0x81`, first variable-count token) + ROW (`0xD1`) + DONE (`0xFD`)
- [ ] Decode a 4-byte int (INT4 / INTN) — ignore all other types for now
- [ ] Print `1`

**Done when:** `SELECT 1` prints `1`. **The milestone — spine complete. Commit it.**

---

## Phase 5 — The type system
*File: `types.py` (now testable against a working thread)*

- [ ] TYPE_INFO parsing per column in COLMETADATA (resolve once per result set)
- [ ] Value length classes: fixed / BYTELEN / USHORTLEN (`0xFFFF` NULL) / LONGLEN (`0xFFFFFFFF` NULL)
- [ ] Easy types: NVARCHAR (UTF-16LE), INTN widths (tiny/small/bigint), BIT, FLOAT
- [ ] Fiddly types: DECIMAL/NUMERIC (sign + LE magnitude), DATETIME2 / DATETIMN, GUID
- [ ] NULL handling (length sentinels) + NBCROW (`0xD2`)
- [ ] Build a one-column-of-each-type table; capture bytes → hex fixtures; assert every decode

**Done when:** a `SELECT` over a one-of-each-type table round-trips correctly vs fixtures + live server.

---

## Phase 6 — The usable surface
*Files: `connection.py`, `cursor.py`, `exceptions.py`, `__init__.py`*

- [ ] `Connection` (owns transport + login + cursor factory)
- [ ] `Cursor` with `execute()` / `fetchone()` / `fetchall()`
- [ ] PEP 249 exception hierarchy; map ERROR token → raised exception
- [ ] `connect()` as the only public name in `__init__.py`

**Done when:** `connect(...).cursor().execute("SELECT …")` then `fetchall()` works like any DB-API driver.

---

## Phase 7 — Hardening (optional for v1)

- [ ] Large result set spanning many packets (exercises Phase-1 reassembly for real)
- [ ] Multiple result sets (DONE_MORE) and multi-statement batches
- [ ] README note on SQL-injection risk of string-built queries (params = RPC → v2)
- [ ] MAX/PLP & LOB types → v2
- [ ] Parameterized queries via `sp_executesql` (RPC) → v2

---

## Cross-cutting habits (every phase)

- [ ] Write a hex fixture + parser unit test the moment each piece works (grows into the conformance corpus for the eventual port)
- [ ] Keep the Wireshark capture open the whole time
- [ ] Commit each green milestone before adding breadth
- [ ] Keep all `struct`/endianness in `_buffer.py` only

---

## Key resources

| Need | Resource |
|---|---|
| Run the server | MS Learn: "Run SQL Server Linux container images with Docker" |
| Ground-truth client | go-sqlcmd (`github.com/microsoft/go-sqlcmd`) |
| Wire inspection | Wireshark built-in TDS dissector (`tds` filter); read the netlib comment in `packet-tds.c` |
| Reference impl (read, don't copy) | pytds (`github.com/denisenkom/pytds`) — pure Python, src layout, links spec sections |
| Modern readable framing | tedious (`github.com/tediousjs/tedious`); FreeTDS `tds/packet.c`, `net.c` |
| Protocol prose | FreeTDS user guide (`freetds.org/userguide/`) |
| Spec (hyperlinked) | MS-TDS at `learn.microsoft.com/.../openspecs/windows_protocols/ms-tds/` |
| Byte handling | Python `struct` + `memoryview` docs |
| Packaging | packaging.python.org (tutorial + src-layout discussion); uv & ruff docs |

⚠️ The two stall points are both "one wrong byte = silent rejection": **LOGIN7**
(Phase 2) and **ALL_HEADERS** (Phase 4). Diff both against the capture.
