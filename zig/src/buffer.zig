//! Reader / Writer / PacketHeader — the ONE place integer (de)serialization lives.
//!
//! The TDS endianness split is concentrated here: the 8-byte packet header has
//! big-endian multi-byte fields (Length, SPID), while everything in the payload
//! is little-endian. Endianness is a *parameter* to `readInt`/`writeInt` (the
//! idiomatic Zig way via std.mem), so there are no separate `_be` methods — only
//! this module reaches for integer serialization.

const std = @import("std");
const c = @import("constants.zig");

const HEADER_SIZE = c.HEADER_SIZE;
const PacketType = c.PacketType;
const Status = c.Status;

/// The 8-byte TDS packet header (MS-TDS §2.2.3.1).
/// Layout: Type(1) Status(1) Length(2,BE) SPID(2,BE) PacketID(1) Window(1).
/// `length` is the whole packet including this 8-byte header.
pub const PacketHeader = struct {
    type: PacketType,
    status: Status,
    length: u16,
    spid: u16 = 0,
    packet_id: u8 = 0,
    window: u8 = 0,

    pub fn pack(self: PacketHeader) [HEADER_SIZE]u8 {
        var out: [HEADER_SIZE]u8 = undefined;
        out[0] = @intFromEnum(self.type);
        out[1] = self.status.toByte();
        std.mem.writeInt(u16, out[2..4], self.length, .big);
        std.mem.writeInt(u16, out[4..6], self.spid, .big);
        out[6] = self.packet_id;
        out[7] = self.window;
        return out;
    }

    pub fn unpack(data: []const u8) !PacketHeader {
        if (data.len < HEADER_SIZE) return error.ShortHeader;
        const length = std.mem.readInt(u16, data[2..4], .big);
        // A server-supplied length below HEADER_SIZE would make payloadLength
        // underflow and silently desync the stream; reject it at this layer.
        if (length < HEADER_SIZE) return error.PacketTooShort;
        return .{
            .type = std.enums.fromInt(PacketType, data[0]) orelse return error.InvalidPacketType,
            .status = Status.fromByte(data[1]),
            .length = length,
            .spid = std.mem.readInt(u16, data[4..6], .big),
            .packet_id = data[6],
            .window = data[7],
        };
    }

    /// Number of payload bytes after the header (Length - 8).
    pub fn payloadLength(self: PacketHeader) usize {
        return self.length - HEADER_SIZE;
    }

    /// True if this is the last packet of its message.
    pub fn isEom(self: PacketHeader) bool {
        return self.status.eom;
    }
};

/// Builds a payload buffer. Caller supplies the allocator and owns the result.
pub const Writer = struct {
    buf: std.ArrayList(u8) = .empty,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Writer {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Writer) void {
        self.buf.deinit(self.allocator);
    }

    pub fn writeByte(self: *Writer, value: u8) !void {
        try self.buf.append(self.allocator, value);
    }

    pub fn writeInt(self: *Writer, comptime T: type, value: T, endian: std.builtin.Endian) !void {
        var tmp: [@divExact(@bitSizeOf(T), 8)]u8 = undefined;
        std.mem.writeInt(T, &tmp, value, endian);
        try self.buf.appendSlice(self.allocator, &tmp);
    }

    pub fn writeBytes(self: *Writer, data: []const u8) !void {
        try self.buf.appendSlice(self.allocator, data);
    }

    pub fn items(self: *const Writer) []const u8 {
        return self.buf.items;
    }

    pub fn len(self: *const Writer) usize {
        return self.buf.items.len;
    }

    /// Hand ownership of the built bytes to the caller; resets this writer.
    pub fn toOwnedSlice(self: *Writer) ![]u8 {
        return self.buf.toOwnedSlice(self.allocator);
    }
};

/// Reads primitives from a fixed buffer, tracking a cursor. Borrows its input.
pub const Reader = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data };
    }

    fn take(self: *Reader, n: usize) ![]const u8 {
        const end = self.pos + n;
        if (end > self.data.len) return error.EndOfBuffer;
        const start = self.pos;
        self.pos = end;
        return self.data[start..end];
    }

    pub fn readByte(self: *Reader) !u8 {
        const slice = try self.take(1);
        return slice[0];
    }

    pub fn readInt(self: *Reader, comptime T: type, endian: std.builtin.Endian) !T {
        const n = @divExact(@bitSizeOf(T), 8);
        const slice = try self.take(n);
        return std.mem.readInt(T, slice[0..n], endian);
    }

    pub fn readBytes(self: *Reader, n: usize) ![]const u8 {
        return self.take(n);
    }

    pub fn remaining(self: *const Reader) usize {
        return self.data.len - self.pos;
    }

    pub fn eof(self: *const Reader) bool {
        return self.pos >= self.data.len;
    }
};

// --- tests --------------------------------------------------------------------

const testing = std.testing;

test "little-endian primitives round-trip through reader and writer" {
    var w = Writer.init(testing.allocator);
    defer w.deinit();
    try w.writeByte(0xAB);
    try w.writeInt(u16, 0xBEEF, .little);
    try w.writeInt(u32, 0xDEADBEEF, .little);
    try w.writeBytes(&.{ 0x00, 0xFF });

    var r = Reader.init(w.items());
    try testing.expectEqual(@as(u8, 0xAB), try r.readByte());
    try testing.expectEqual(@as(u16, 0xBEEF), try r.readInt(u16, .little));
    try testing.expectEqual(@as(u32, 0xDEADBEEF), try r.readInt(u32, .little));
    try testing.expectEqualSlices(u8, &.{ 0x00, 0xFF }, try r.readBytes(2));
    try testing.expect(r.eof());
}

test "uint16 little-endian byte order" {
    var w = Writer.init(testing.allocator);
    defer w.deinit();
    try w.writeInt(u16, 0x0102, .little);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x01 }, w.items());
}

test "uint16 big-endian byte order (PRELOGIN offsets/lengths)" {
    var w = Writer.init(testing.allocator);
    defer w.deinit();
    try w.writeInt(u16, 0x0102, .big);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02 }, w.items());
}

test "reader overrun returns EndOfBuffer" {
    var r = Reader.init(&.{0x01});
    try testing.expectError(error.EndOfBuffer, r.readInt(u32, .little));
}

test "reader tracks position and remaining" {
    var r = Reader.init(&.{ 1, 2, 3, 4 });
    try testing.expectEqual(@as(usize, 4), r.remaining());
    _ = try r.readInt(u16, .little);
    try testing.expectEqual(@as(usize, 2), r.remaining());
}

test "packet header packs to fixed bytes and round-trips" {
    const h = PacketHeader{
        .type = .sql_batch,
        .status = .{ .eom = true },
        .length = 0x0030,
        .spid = 0,
        .packet_id = 1,
        .window = 0,
    };
    const packed_bytes = h.pack();
    try testing.expectEqualSlices(
        u8,
        &.{ 0x01, 0x01, 0x00, 0x30, 0x00, 0x00, 0x01, 0x00 },
        &packed_bytes,
    );

    const back = try PacketHeader.unpack(&packed_bytes);
    try testing.expectEqual(PacketType.sql_batch, back.type);
    try testing.expect(back.isEom());
    try testing.expectEqual(@as(usize, 0x30 - 8), back.payloadLength());
}

test "packet header rejects short input" {
    try testing.expectError(error.ShortHeader, PacketHeader.unpack(&.{ 0x10, 0x01, 0x00 }));
}

test "packet header rejects length below header size" {
    // length field = 3 (< HEADER_SIZE) would make payloadLength underflow.
    const bad = [_]u8{ 0x04, 0x01, 0x00, 0x03, 0x00, 0x00, 0x01, 0x00 };
    try testing.expectError(error.PacketTooShort, PacketHeader.unpack(&bad));
}

// --- tests against the captured oracle ----------------------------------------

const fixture = @import("fixture.zig");

test "header unpack matches captured LOGIN7 (frame 8)" {
    const pkt = try fixture.raw(testing.allocator, 8);
    defer testing.allocator.free(pkt);
    const h = try PacketHeader.unpack(pkt);
    try testing.expectEqual(PacketType.login7, h.type);
    try testing.expect(h.isEom());
    try testing.expectEqual(@as(u16, @intCast(pkt.len)), h.length);
    try testing.expectEqual(@as(u16, 0), h.spid);
    try testing.expectEqual(@as(u8, 1), h.packet_id);
    try testing.expectEqual(pkt.len - HEADER_SIZE, h.payloadLength());
}

test "header keeps a non-zero server SPID (frame 9 = 65)" {
    const pkt = try fixture.raw(testing.allocator, 9);
    defer testing.allocator.free(pkt);
    try testing.expectEqual(@as(u16, 65), (try PacketHeader.unpack(pkt)).spid);
}

test "header status is a flag field (frame 11 = EOM|RESET_CONNECTION)" {
    const pkt = try fixture.raw(testing.allocator, 11);
    defer testing.allocator.free(pkt);
    const status = (try PacketHeader.unpack(pkt)).status;
    try testing.expect(status.eom);
    try testing.expect(status.reset_connection);
}

test "header pack round-trips every captured frame" {
    for ([_]u64{ 4, 6, 8, 9, 11, 12 }) |frame| {
        const pkt = try fixture.raw(testing.allocator, frame);
        defer testing.allocator.free(pkt);
        const packed_bytes = (try PacketHeader.unpack(pkt)).pack();
        try testing.expectEqualSlices(u8, pkt[0..HEADER_SIZE], &packed_bytes);
    }
}

test "LOGIN7 LE payload length-prefix cross-checks the BE header length (frame 8)" {
    // The LOGIN7 payload begins with a little-endian u32 total length while the
    // packet header Length is big-endian — proves the endianness split.
    const pkt = try fixture.raw(testing.allocator, 8);
    defer testing.allocator.free(pkt);
    var r = Reader.init(pkt[HEADER_SIZE..]);
    try testing.expectEqual(@as(u32, @intCast(pkt.len - HEADER_SIZE)), try r.readInt(u32, .little));
}
