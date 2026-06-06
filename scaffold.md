py-bowyer/                        # repo root
├── pyproject.toml                # PEP 621 metadata + tool config (the only config file you need)
├── README.md
├── LICENSE
├── docs/
│   └── tds_cheatsheet.md     # the reference you're working from
├── src/
│   └── tinytds/
│       ├── __init__.py           # PUBLIC API only: connect(), Connection, version, exceptions
│       ├── constants.py          # IntEnums: PacketType, TokenType, DataType, Status flags
│       ├── exceptions.py         # error hierarchy (PEP 249 style: DatabaseError, OperationalError, …)
│       ├── _buffer.py            # ByteReader / ByteWriter — the ONE place struct + endianness live
│       ├── transport.py          # socket + 8-byte packet header + packet<->message reassembly
│       ├── prelogin.py           # build/parse PRELOGIN (the option directory)
│       ├── login.py              # build LOGIN7, password obfuscation
│       ├── batch.py              # build SQLBatch (ALL_HEADERS + UTF-16LE text)
│       ├── tokens.py             # token-stream parser + dispatch (COLMETADATA, ROW, DONE, …)
│       ├── types.py              # TYPE_INFO parsing + per-type value decode (the type system)
│       ├── connection.py         # Connection: owns the transport, login, cursor factory
│       └── cursor.py             # Cursor: execute() / fetchone() / fetchall()
└── tests/
    ├── conftest.py               # pytest fixtures; a `live` marker for integration tests
    ├── fixtures/
    │   └── select_1.hex          # captured wire bytes → parser unit tests, no server needed
    ├── test_buffer.py
    ├── test_prelogin.py
    ├── test_tokens.py            # feed it fixture bytes, assert the parse
    ├── test_types.py
    └── test_live.py              # @pytest.mark.live — runs only against a Docker SQL Server
