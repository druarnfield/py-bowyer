# py-bowyer

An **Arrow-native** client for Microsoft SQL Server's TDS (Tabular Data Stream)
wire protocol — no FreeTDS, no ODBC, no C driver dependency. Rows are decoded
straight off the wire into Apache Arrow columnar buffers.

> **Status: early / in development.** A pure-Python prototype is being built
> first as a readable reference implementation; the production target is a
> from-scratch Arrow-native implementation in [Zig](https://ziglang.org). Not
> yet production-ready — see [Relationship to existing tools](#relationship-to-existing-tools).

## The name

A *bowyer* is the craftsperson who makes the bow — the instrument that sends an
arrow flying straight and true. That's the goal here: deliver **Arrow** data
from SQL Server faithfully and fast, exactly as it left the server.

## What it aims to accomplish

bowyer optimizes for, in order:

1. **Arrow-native by design.** Decode the TDS wire *directly* into Arrow column
   buffers (validity bitmap + offsets + data), with no intermediate row
   materialization and no per-value boxing. Results leave the driver already
   columnar, so they compose zero-copy with the analytical ecosystem — Polars,
   DuckDB, pandas, Parquet — instead of being transposed at the boundary.
2. **Correctness & type fidelity.** Values arrive exactly as they left the
   server: no silent decimal precision loss, no mangled binary, no
   NULL-vs-empty ambiguity, correct Unicode. Where a value genuinely can't be
   represented, the driver fails loudly rather than corrupting it quietly.
3. **Lightweight & dependency-free.** A pure protocol implementation — no ODBC,
   no FreeTDS, no Oracle/Instant-Client baggage. The Zig core is a static
   binary that cross-compiles trivially to Linux, macOS, and Windows.
4. **Clarity.** The code is organized to mirror the protocol's own layers —
   bytes → packet framing → message codec → token stream → Arrow column
   decoding — so the codebase reads as a guided tour of how TDS works.

## How it's being built

Two stages, deliberately separated so each is one problem at a time:

- **Stage 1 — Python reference prototype.** A small, row-oriented, pure-Python
  implementation of the protocol spine. Its job is to nail the wire format and
  serve as a readable, replayable reference (captured bytes drive the tests, no
  live server required). It is *not* optimized — clarity over speed.
- **Stage 2 — Zig Arrow-native core.** A from-scratch reimplementation that
  decodes straight into Arrow buffers, using Zig's `comptime` to generate
  type-specialized, branch-free per-column decoders. This is where the
  Arrow-native and memory-efficiency goals are actually realized.

The intended public interface for the Zig core is the **ADBC C API**, so the
driver plugs into the Arrow Database Connectivity ecosystem and is consumable
zero-copy from Python (pyarrow), R, Go, and others via the ADBC driver manager —
without hand-written per-language bindings.

## Scope (current focus)

The first milestone is the smallest genuinely useful client:

- TCP connection and the PRELOGIN handshake
- LOGIN7 with SQL Server authentication
- Running a SQL batch (`SELECT …`) and decoding the result set
- Common scalar types — integers, `bit`, `float`, `decimal`/`numeric`,
  `nvarchar`/`varchar`, `datetime2`, `uniqueidentifier` — with correct NULL handling

**Out of scope for now** (planned, not yet built): TLS / encrypted connections,
RPC and parameterized queries, bulk copy, MARS, `MAX`/LOB types, and
integrated/federated authentication.

## Roadmap

Roughly in order:

- Python reference prototype: the protocol spine, fully tested against captured bytes
- Zig Arrow-native core: direct-to-Arrow decoding, `comptime` column decoders
- Encrypted connections (TLS negotiated within the protocol)
- Bulk copy (the fast minimal-logging load path)
- ADBC C API surface + prebuilt wheels/artifacts via Zig cross-compilation
- Eventually, bowyer may serve as the SQL Server connector for a separate
  data-movement tool — but that tool is its own project; bowyer stands alone.

## Why Arrow-native at the protocol level?

TDS is row-major on the wire, so a transpose into columns is unavoidable either
way. Doing it *inside* the driver — straight into Arrow buffers — doesn't make
the decode dramatically faster (throughput is bounded by the network and, on
the bulk path, compression). What it does buy is **memory efficiency**
(eliminating per-value boxing and intermediate row objects) and **zero-copy
composition** (the data is already Arrow the moment it leaves the socket). TDS
also reports static per-column types in its COLMETADATA, which maps cleanly onto
Arrow's schema model. Those are the real wins, and they're architectural rather
than micro-optimizations.

## Relationship to existing tools

Mature TDS drivers already exist — [pytds](https://github.com/denisenkom/pytds)
(pure Python), [tiberius](https://github.com/prisma/tiberius) (Rust),
[go-mssqldb](https://github.com/microsoft/go-mssqldb) (Go), and FreeTDS/ODBC (C).
For production workloads today you should use one of those. bowyer's distinct
aim is to be a **pure-Zig, Arrow-native** TDS driver with no ODBC/FreeTDS
dependency — a combination that doesn't currently exist — with type fidelity and
zero-copy Arrow output as first-class concerns. It is not a drop-in replacement
for any of the above.

## References

- [MS-TDS] — the official Microsoft protocol specification
- [Apache Arrow C Data Interface] / [ADBC] — the zero-copy interchange and driver API
- [pytds](https://github.com/denisenkom/pytds) — pure-Python reference implementation
- [tedious](https://github.com/tediousjs/tedious) — readable modern (Node.js) TDS driver
- [FreeTDS user guide](https://www.freetds.org/userguide/) — approachable protocol prose

## License

TBD.
