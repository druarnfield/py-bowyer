//! IntEnums and protocol constants — the protocol's wire vocabulary.
//!
//! PacketType and Status cover framing; PreLoginOption and EncryptionLevel cover
//! the handshake. This file is for the *protocol's* fixed vocabulary; driver
//! identity/policy defaults live next to the code that uses them.

const std = @import("std");

pub const HEADER_SIZE = 8;

/// Max packet size until LOGIN7 negotiates a different one. Max payload per
/// packet = DEFAULT_PACKET_SIZE - HEADER_SIZE.
pub const DEFAULT_PACKET_SIZE = 4096;

/// The Type byte (offset 0) of the 8-byte packet header (MS-TDS §2.2.3.1.1).
pub const PacketType = enum(u8) {
    sql_batch = 0x01,
    rpc = 0x03,
    tabular_result = 0x04, // every server reply comes back as this type
    attention = 0x06,
    bulk_load = 0x07,
    login7 = 0x10,
    prelogin = 0x12,
};

/// The Status byte (offset 1) of the packet header (MS-TDS §2.2.3.1.2).
///
/// A packed struct of bit flags: `status.eom` replaces Python's `EOM in status`.
/// Fields are laid out least-significant-bit first, matching the spec values
/// (EOM=0x01, IGNORE=0x02, RESET_CONNECTION=0x08, RESET_CONNECTION_SKIP_TRAN=0x10).
pub const Status = packed struct(u8) {
    eom: bool = false, // 0x01 last packet of a message; drives reassembly
    ignore: bool = false, // 0x02
    _reserved2: u1 = 0, // 0x04
    reset_connection: bool = false, // 0x08
    reset_connection_skip_tran: bool = false, // 0x10
    _reserved5: u3 = 0,

    /// "No flags" — the zero value.
    pub const normal: Status = .{};

    pub fn toByte(self: Status) u8 {
        return @bitCast(self);
    }

    pub fn fromByte(b: u8) Status {
        return @bitCast(b);
    }
};

/// PRELOGIN option tokens (MS-TDS §2.2.6.5). VERSION must be first; 0xFF terminates.
pub const PreLoginOption = enum(u8) {
    version = 0x00,
    encryption = 0x01,
    instopt = 0x02,
    threadid = 0x03,
    mars = 0x04,
    traceid = 0x05,
    fedauthrequired = 0x06,
    terminator = 0xff,
};

/// The 1-byte ENCRYPTION option value (MS-TDS §2.2.6.5).
pub const EncryptionLevel = enum(u8) {
    off = 0x00, // encryption available, currently off
    on = 0x01, // encryption available, currently on
    not_sup = 0x02, // encryption not supported by this side
    req = 0x03, // encryption required (forces TLS — out of v1 scope)
};

test "status flags round-trip through a byte" {
    const s = Status{ .eom = true, .reset_connection = true };
    try std.testing.expectEqual(@as(u8, 0x09), s.toByte());

    const back = Status.fromByte(0x09);
    try std.testing.expect(back.eom and back.reset_connection);
    try std.testing.expect(!back.ignore and !back.reset_connection_skip_tran);
}

test "status normal is zero" {
    try std.testing.expectEqual(@as(u8, 0x00), Status.normal.toByte());
}
