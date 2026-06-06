# TDS MVP Cheat-Sheet

A working reference for a minimum-viable TDS client, distilled from **[MS-TDS]
v20251031**. Section numbers (§) point into that spec. Scope: enough to log in
with SQL auth, run a `SELECT`, and decode the result. TLS, RPC, bulk load,
federated/SSPI auth, MARS, and the type long tail are **out of scope for v1**.

---

## 0. The mental model (read this first)

Three nested layers — keep them distinct (§2.2.3–2.2.4):

```
message   = one logical unit (PRELOGIN, LOGIN7, a query, a result set)
  └─ packet(s)  = message chopped into fixed-size frames, each with an 8-byte header
       └─ payload = tokenless (PRELOGIN/LOGIN7/SQLBatch) OR a token stream (server results)
```

- A message may span several packets. Reassemble packets → message **before**
  parsing the payload. The last packet has the **EOM** status bit set.
- Only **server responses** are token streams. Client requests are tokenless
  structures.
- Read loop is two levels: reassemble packets → message bytes, then parse.

---

## 1. Endianness — the #1 trap

| Where | Byte order |
|---|---|
| Packet **header** `Length` and `SPID` | **big-endian** (network order) |
| Everything in the **payload** (data values, lengths, offsets) | **little-endian** |

In Python: header length `struct.unpack(">H", ...)`; payload values `"<..."`.
Get this backwards and nothing parses.

---

## 2. Packet header — 8 bytes (§2.2.3.1)

| Offset | Field | Size | Notes |
|---|---|---|---|
| 0 | Type | 1 | message type (§3) |
| 1 | Status | 1 | bit flags (§4) |
| 2 | Length | 2 | whole packet incl. header, **big-endian** |
| 4 | SPID | 2 | **big-endian**; client sends `0x0000` |
| 6 | PacketID | 1 | increment mod 256 (receiver ignores it) |
| 7 | Window | 1 | always `0x00` |

- `Length` = bytes from start of this header to start of next. ≥ 512, ≤ 32767.
- Max packet is **4096** until a size is negotiated in LOGIN7.
- Max payload per packet = negotiated size − 8.

### Packet Type values (§2.2.3.1.1)

| Type | Meaning | Direction |
|---|---|---|
| `18` | Pre-Login | client |
| `16` | TDS7 Login (LOGIN7) | client |
| `1` | SQL Batch | client |
| `3` | RPC | client (later) |
| `7` | Bulk load | client (later) |
| `6` | Attention | client (later) |
| `4` | **Tabular result** | **server (all responses)** |

> Every server reply — PRELOGIN response, login response, rows, errors — comes
> back as **Type 4**.

---

## 3. Status flags (§2.2.3.1.2)

| Flag | Value | Meaning |
|---|---|---|
| EOM | `0x01` | last packet of the message |
| IGNORE | `0x02` | ignore event (EOM must also be set) |
| RESETCONNECTION | `0x08` | reset session state first |
| RESETCONNECTIONSKIPTRAN | `0x10` | reset but keep transaction state |

For the MVP: set `0x01` on your single-packet requests; treat `0x01` as
"message complete" when reading.

---

## 4. Handshake: PRELOGIN → (TLS) → LOGIN7

### 4.1 PRELOGIN (Type 18, §2.2.6.5)

An option directory followed by the option data:

```
repeated:  PL_OPTION_TOKEN (1)  Offset (2, big-endian)  Length (2, big-endian)
then:      0xFF  (TERMINATOR)
then:      <option data blobs the offsets point into>
```

Option tokens:

| Token | Value | Data |
|---|---|---|
| VERSION | `0x00` | `UL_VERSION` (required, **must be first**) |
| ENCRYPTION | `0x01` | 1-byte encryption intent |
| INSTOPT | `0x02` | instance name |
| THREADID | `0x03` | client thread id |
| MARS | `0x04` | 1 byte (0=off) |
| TRACEID | `0x05` | trace GUID |
| FEDAUTHREQUIRED | `0x06` | 1 byte |

Encryption byte values:

| Value | Meaning |
|---|---|
| `0x00` | ENCRYPT_OFF (available, off) |
| `0x01` | ENCRYPT_ON (available, on) |
| `0x02` | ENCRYPT_NOT_SUP (not supported) |
| `0x03` | ENCRYPT_REQ (required) |

**MVP path:** send VERSION + ENCRYPTION=`0x02` + TERMINATOR. If the server's
response is **not** ENCRYPT_REQ, skip TLS and go straight to LOGIN7 in
plaintext. If it returns ENCRYPT_REQ, you must do the TLS-in-TDS handshake →
**defer to phase 2** and use a Docker server configured to allow unencrypted
connections for v1.

### 4.2 LOGIN7 (Type 16, §2.2.6.4)

- A fixed header of `(offset, length)` pairs pointing into a variable-length
  data section: hostname, **username**, **password**, app name, server name,
  database, etc., followed by login options (requested packet size, client TDS
  version).
- Everything is offset-addressed — the tedious part. Build the variable section,
  then back-fill offsets/lengths.
- **Password obfuscation:** for each byte, XOR with `0xA5` **and** swap its
  nibbles. (Confirm the exact order against §2.2.6.4 as you implement.)
- SQL auth lives entirely in this record. SSPI/integrated auth (Type 17) and
  federated auth → **out of scope**.

### 4.3 Server reply to login

A Type-4 token stream containing (at least) **LOGINACK** (`0xAD`, confirms
negotiated TDS version) and one or more **ENVCHANGE** (`0xE3`, e.g. database /
packet size / collation), ending in a **DONE**. Parse **ERROR** (`0xAA`) here so
a failed login is legible.

---

## 5. Sending a query: SQLBatch (Type 1, §2.2.6.7)

Payload =

```
ALL_HEADERS (§2.2.5.2)   then   SQL text as UTF-16LE
```

- `ALL_HEADERS` includes a **transaction descriptor** header. For a
  non-transactional MVP it's a small fixed stub (descriptor = 0, outstanding
  request count = 1). Copy a known-good capture — a wrong `ALL_HEADERS` makes
  the server reject the batch.
- The SQL text itself is UTF-16LE (`"SELECT 1".encode("utf-16-le")`).

---

## 6. Reading the response: the token-stream loop (§2.2.4–2.2.5)

```
reassemble Type-4 packets -> message bytes
cursor = 0
while cursor < len(message):
    token = message[cursor]; cursor += 1
    handler = dispatch[token]        # consume this token's data per its shape
    handler(cursor)                  # advance cursor
stop when a DONE arrives WITHOUT the DONE_MORE bit
```

### Token length taxonomy (§2.2.4.2.1) — lets you skip unknown tokens

| Class | How to read its length |
|---|---|
| Zero-length | no data |
| Fixed-length | known from the token |
| Variable-length | a length prefix precedes the data |
| Variable-count | a **count** precedes N sub-structures (only COLMETADATA, ALTMETADATA) |

Implement these four shapes and you can recognise-and-skip tokens you don't
support instead of crashing.

### Token codes (§2.2.5.1)

| Token | Byte | MVP role |
|---|---|---|
| LOGINACK | `0xAD` | login OK + TDS version |
| ENVCHANGE | `0xE3` | env changes during/after login |
| ERROR | `0xAA` | server error |
| INFO | `0xAB` | informational (same shape as ERROR) |
| COLMETADATA | `0x81` | result-set column types |
| ROW | `0xD1` | one row |
| NBCROW | `0xD2` | row with leading null-bitmap (7.3+) |
| DONE | `0xFD` | result/statement completion |
| DONEPROC | `0xFE` | proc completion (skip-ok) |
| DONEINPROC | `0xFF` | per-statement completion (skip-ok) |
| RETURNSTATUS | `0x79` | proc return value (skip-ok) |
| ORDER | `0xA9` | ORDER BY columns (skip-ok) |
| COLINFO | `0xA5` | (skip-ok) |

### DONE token (§2.2.7.5)

```
TokenType (1)  Status (2)  CurCmd (2)  DoneRowCount (8, TDS 7.2+)
```

Status flags:

| Flag | Value | Meaning |
|---|---|---|
| DONE_FINAL | `0x00` | final DONE |
| DONE_MORE | `0x01` | more result sets follow |
| DONE_ERROR | `0x02` | statement errored |
| DONE_INXACT | `0x04` | transaction in progress |
| DONE_COUNT | `0x10` | DoneRowCount is valid |

Loop ends on a DONE **without** DONE_MORE.

---

## 7. COLMETADATA + the type system (§2.2.7.4, §2.2.5.4–5.5)

COLMETADATA = column **count**, then per column: `UserType`, `Flags`, and a
**TYPE_INFO** blob (type token + parameters), then the column name. Resolve
TYPE_INFO **once** per result set; it tells you how to read each cell in the
following ROW tokens.

### Value length classes (§2.2.5.4.2)

| Class | Length prefix | NULL sentinel |
|---|---|---|
| Fixed-length | none (implicit) | n/a (use NBCROW / nullable variant) |
| BYTELEN | 1 byte | length `0x00` |
| USHORTLEN (var char/binary) | 2 bytes | `0xFFFF` |
| LONGLEN / PARTLEN (MAX, text/image) | 4 bytes | `0xFFFFFFFF` (−1); or PLP-chunked |

PLP (MAX) types: 8-byte total length, then chunks, then `0x00000000`
terminator. **Skip MAX for v1.**

### Starter type tokens (§2.2.5.5)

| SQL type | Token | Encoding notes |
|---|---|---|
| int (4-byte) | `0x38` INT4 / `0x26` INTN | INTN length byte 1/2/4/8 → tinyint/smallint/int/bigint |
| bit | `0x68` BITN | 1 byte |
| float | `0x6D` FLTN | length 4 or 8 |
| decimal / numeric | `0x6A` / `0x6C` | precision+scale in metadata; value = sign byte + LE magnitude (lengths 5/9/13/17) |
| datetime2 | `0x2A` DATETIME2N | scale-dependent length |
| smalldatetime/datetime | `0x6F` DATETIMN | length 4 or 8 |
| uniqueidentifier | `0x24` GUID | 16 bytes, driver-specific order; 0x00 = NULL |
| nvarchar | `0xE7` | **UTF-16LE on the wire**; 5-byte collation in metadata |

**Value-level gotchas everyone hits:**
- NVARCHAR/NCHAR are UTF-16LE — `b.decode("utf-16-le")`, not UTF-8.
- char/binary NULL is the **length sentinel** (`0xFFFF`), not a zero-length value.
- decimal is sign-plus-magnitude — implement it **after** int/nvarchar round-trip.

---

## 8. Explicitly NOT in v1

TLS / encryption, SSPI / integrated / federated auth, RPC & prepared statements
(§2.2.6.6), bulk load (§2.2.5.3, §3), MAX/PLP & LOB types, MARS,
ALTMETADATA/ALTROW, and every type beyond §7. All are additions to a working
skeleton, not changes to its shape.

---

## 9. First milestone checklist

- [ ] TCP connect to SQL Server
- [ ] Build + send PRELOGIN (Type 18), parse the option directory back
- [ ] Negotiate encryption **off** (server not ENCRYPT_REQ)
- [ ] Build + send LOGIN7 (Type 16) with SQL auth (password obfuscation)
- [ ] Parse LOGINACK + ENVCHANGE + DONE; surface ERROR cleanly
- [ ] Send `SELECT 1` as SQLBatch (Type 1) with ALL_HEADERS + UTF-16LE text
- [ ] Token loop: parse COLMETADATA → ROW → DONE
- [ ] Print `1`

When `1` prints, you understand the spine. Everything after is breadth.

---

## 10. Spec section index (for jumping into [MS-TDS])

| Topic | § |
|---|---|
| Packet header | 2.2.3.1 |
| Packet data / multi-packet | 2.2.3.2 |
| Token vs tokenless streams | 2.2.4 |
| Token length taxonomy | 2.2.4.2.1 |
| Data type definitions / TYPE_INFO | 2.2.5.4–2.2.5.5 |
| ALL_HEADERS | 2.2.5.2 |
| LOGIN7 | 2.2.6.4 |
| PRELOGIN | 2.2.6.5 |
| SQLBatch | 2.2.6.7 |
| Token byte codes | 2.2.5.1 |
| COLMETADATA | 2.2.7.4 |
| DONE / DONEPROC / DONEINPROC | 2.2.7.5–2.2.7.8 |
| ROW | 2.2.7.x (ROW_TOKEN 0xD1) |
| NBCROW | 2.2.7.15 |
| LOGINACK / ENVCHANGE / ERROR / INFO | 2.2.7.x |

---

## Tooling tip

Keep a **Wireshark** capture of a real client (`sqlcmd` / `pymssql`) doing the
same login + `SELECT 1` open beside you — its TDS dissector labels every field
you're reproducing, so you're never guessing what "correct" looks like. Save
captured packet bytes as hex fixtures for your parser unit tests.
