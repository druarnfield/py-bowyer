//! Socket + 8-byte packet header + packet<->message reassembly.
//!
//! A TDS *message* is one or more *packets*; the final packet has the EOM status
//! bit set. `Transport` is generic over a `Stream` type (comptime duck typing):
//! it needs `read([]u8) !usize` and `writeAll([]const u8) !void`. Offline tests
//! drive it with `FakeStream`; the live path uses `std.net.Stream`.

const std = @import("std");
const c = @import("constants.zig");
const buffer = @import("buffer.zig");

const HEADER_SIZE = c.HEADER_SIZE;
const DEFAULT_PACKET_SIZE = c.DEFAULT_PACKET_SIZE;
const PacketType = c.PacketType;
const Status = c.Status;
const PacketHeader = buffer.PacketHeader;

/// A fully reassembled server message. `payload` is owned by the caller.
pub const Message = struct {
    type: PacketType,
    payload: []u8,
};

pub fn Transport(comptime Stream: type) type {
    return struct {
        const Self = @This();

        stream: Stream,
        packet_size: u16 = DEFAULT_PACKET_SIZE,

        pub fn init(stream: Stream) Self {
            return .{ .stream = stream };
        }

        /// §2.2.3.1.3: a negotiated packet size must be 512..32767.
        pub fn setPacketSize(self: *Self, value: u16) !void {
            if (value < 512 or value > 32767) return error.InvalidPacketSize;
            self.packet_size = value;
        }

        /// Split `payload` across packets, setting EOM only on the last. An empty
        /// payload still sends one (EOM) packet so the peer sees a complete message.
        pub fn sendMessage(self: *Self, packet_type: PacketType, payload: []const u8) !void {
            const max_payload: usize = self.packet_size - HEADER_SIZE;
            var offset: usize = 0;
            var packet_id: u8 = 1; // 1-based to match reference captures
            while (true) {
                const chunk_len = @min(payload.len - offset, max_payload);
                const is_last = offset + chunk_len >= payload.len;
                const header = PacketHeader{
                    .type = packet_type,
                    .status = if (is_last) Status{ .eom = true } else Status.normal,
                    .length = @intCast(chunk_len + HEADER_SIZE),
                    .packet_id = packet_id,
                };
                const head = header.pack();
                try self.stream.writeAll(&head);
                if (chunk_len > 0) try self.stream.writeAll(payload[offset .. offset + chunk_len]);
                offset += chunk_len;
                packet_id +%= 1; // wrap mod 256
                if (is_last) break;
            }
        }

        /// Read packets until EOM, returning the message type + reassembled payload.
        pub fn receiveMessage(self: *Self, allocator: std.mem.Allocator) !Message {
            var buf: std.ArrayList(u8) = .empty;
            errdefer buf.deinit(allocator);
            var message_type: ?PacketType = null;
            while (true) {
                var head: [HEADER_SIZE]u8 = undefined;
                try self.recvExact(&head);
                const header = try PacketHeader.unpack(&head);
                if (message_type == null) message_type = header.type;
                const start = buf.items.len;
                try buf.resize(allocator, start + header.payloadLength());
                try self.recvExact(buf.items[start..]);
                if (header.isEom()) break;
            }
            return .{ .type = message_type.?, .payload = try buf.toOwnedSlice(allocator) };
        }

        /// Read exactly `out.len` bytes, looping over short reads.
        fn recvExact(self: *Self, out: []u8) !void {
            var filled: usize = 0;
            while (filled < out.len) {
                const n = try self.stream.read(out[filled..]);
                if (n == 0) return error.ConnectionClosed;
                filled += n;
            }
        }
    };
}

/// Production socket binding: exposes the duck-typed Stream interface
/// (`read`/`writeAll`) over a real `std.Io.net` socket, so `Transport(*NetStream)`
/// talks to a live server. Offline tests use `FakeStream` instead.
///
/// Holds persistent buffered reader/writer that point at this struct's own
/// buffers, so a NetStream value must keep a stable address after `connect`
/// (don't copy it — pass it by pointer, as `Transport(*NetStream)` does).
pub const NetStream = struct {
    stream: std.Io.net.Stream,
    io: std.Io,
    read_buf: [DEFAULT_PACKET_SIZE]u8 = undefined,
    write_buf: [DEFAULT_PACKET_SIZE]u8 = undefined,
    sr: std.Io.net.Stream.Reader = undefined,
    sw: std.Io.net.Stream.Writer = undefined,

    /// Connect to `host:port` over TCP, wiring `self`'s reader/writer to its own
    /// buffers. `self` must not move afterward.
    pub fn connect(self: *NetStream, io: std.Io, host: []const u8, port: u16) !void {
        const addr = try std.Io.net.IpAddress.parse(host, port);
        self.* = .{ .stream = try addr.connect(io, .{ .mode = .stream }), .io = io };
        self.sr = self.stream.reader(io, &self.read_buf);
        self.sw = self.stream.writer(io, &self.write_buf);
    }

    pub fn read(self: *NetStream, out: []u8) !usize {
        return self.sr.interface.readSliceShort(out);
    }

    pub fn writeAll(self: *NetStream, bytes: []const u8) !void {
        try self.sw.interface.writeAll(bytes);
        try self.sw.interface.flush();
    }

    pub fn close(self: *NetStream) void {
        self.stream.close(self.io);
    }
};

// --- test doubles & helpers ---------------------------------------------------

const testing = std.testing;
const fixture = @import("fixture.zig");

/// Offline stand-in: `read` hands back at most one scripted chunk (and at most
/// `out.len` bytes) per call, so small chunks exercise partial-read reassembly;
/// once exhausted it returns 0 (peer closed). `writeAll` accumulates into `sent`.
const FakeStream = struct {
    chunks: []const []const u8,
    chunk_idx: usize = 0,
    chunk_off: usize = 0,
    sent: *std.ArrayList(u8),
    allocator: std.mem.Allocator,

    fn read(self: *FakeStream, out: []u8) !usize {
        if (out.len == 0 or self.chunk_idx >= self.chunks.len) return 0;
        const chunk = self.chunks[self.chunk_idx][self.chunk_off..];
        const n = @min(out.len, chunk.len);
        @memcpy(out[0..n], chunk[0..n]);
        self.chunk_off += n;
        if (self.chunk_off >= self.chunks[self.chunk_idx].len) {
            self.chunk_idx += 1;
            self.chunk_off = 0;
        }
        return n;
    }

    fn writeAll(self: *FakeStream, data: []const u8) !void {
        try self.sent.appendSlice(self.allocator, data);
    }
};

fn makePacket(allocator: std.mem.Allocator, ptype: PacketType, body: []const u8, eom: bool, packet_id: u8) ![]u8 {
    const header = PacketHeader{
        .type = ptype,
        .status = if (eom) Status{ .eom = true } else Status.normal,
        .length = @intCast(body.len + HEADER_SIZE),
        .packet_id = packet_id,
    };
    const head = header.pack();
    const out = try allocator.alloc(u8, HEADER_SIZE + body.len);
    @memcpy(out[0..HEADER_SIZE], &head);
    @memcpy(out[HEADER_SIZE..], body);
    return out;
}

const ParsedPacket = struct { header: PacketHeader, body: []const u8 };

fn splitPackets(allocator: std.mem.Allocator, data: []const u8) ![]ParsedPacket {
    var list: std.ArrayList(ParsedPacket) = .empty;
    errdefer list.deinit(allocator);
    var pos: usize = 0;
    while (pos < data.len) {
        const header = try PacketHeader.unpack(data[pos..]);
        try list.append(allocator, .{ .header = header, .body = data[pos + HEADER_SIZE .. pos + header.length] });
        pos += header.length;
    }
    return list.toOwnedSlice(allocator);
}

// --- receiveMessage tests -----------------------------------------------------

test "receive a single packet" {
    const a = testing.allocator;
    const pkt = try makePacket(a, .tabular_result, "hello", true, 1);
    defer a.free(pkt);

    var sent: std.ArrayList(u8) = .empty;
    defer sent.deinit(a);
    var fs = FakeStream{ .chunks = &.{pkt}, .sent = &sent, .allocator = a };
    var t = Transport(*FakeStream).init(&fs);

    const msg = try t.receiveMessage(a);
    defer a.free(msg.payload);
    try testing.expectEqual(PacketType.tabular_result, msg.type);
    try testing.expectEqualSlices(u8, "hello", msg.payload);
}

test "receive reassembles two packets" {
    const a = testing.allocator;
    const p1 = try makePacket(a, .tabular_result, "AAAA", false, 1);
    defer a.free(p1);
    const p2 = try makePacket(a, .tabular_result, "BBBB", true, 2);
    defer a.free(p2);

    var sent: std.ArrayList(u8) = .empty;
    defer sent.deinit(a);
    var fs = FakeStream{ .chunks = &.{ p1, p2 }, .sent = &sent, .allocator = a };
    var t = Transport(*FakeStream).init(&fs);

    const msg = try t.receiveMessage(a);
    defer a.free(msg.payload);
    try testing.expectEqualSlices(u8, "AAAABBBB", msg.payload);
}

test "receive handles recv() returning 3 bytes at a time" {
    const a = testing.allocator;
    const p1 = try makePacket(a, .tabular_result, "hello", false, 1);
    defer a.free(p1);
    const p2 = try makePacket(a, .tabular_result, " world", true, 2);
    defer a.free(p2);
    const stream = try std.mem.concat(a, u8, &.{ p1, p2 });
    defer a.free(stream);

    // Slice the stream into 3-byte chunks so reads cross header/packet boundaries.
    var chunks: std.ArrayList([]const u8) = .empty;
    defer chunks.deinit(a);
    var i: usize = 0;
    while (i < stream.len) : (i += 3) try chunks.append(a, stream[i..@min(i + 3, stream.len)]);

    var sent: std.ArrayList(u8) = .empty;
    defer sent.deinit(a);
    var fs = FakeStream{ .chunks = chunks.items, .sent = &sent, .allocator = a };
    var t = Transport(*FakeStream).init(&fs);

    const msg = try t.receiveMessage(a);
    defer a.free(msg.payload);
    try testing.expectEqualSlices(u8, "hello world", msg.payload);
}

test "receive on a closed socket raises" {
    const a = testing.allocator;
    var sent: std.ArrayList(u8) = .empty;
    defer sent.deinit(a);
    // Only a partial header arrives, then the peer closes (read -> 0).
    var fs = FakeStream{ .chunks = &.{&.{ 0x04, 0x01, 0x00 }}, .sent = &sent, .allocator = a };
    var t = Transport(*FakeStream).init(&fs);
    try testing.expectError(error.ConnectionClosed, t.receiveMessage(a));
}

test "receive rejects an undersized length field" {
    const a = testing.allocator;
    var sent: std.ArrayList(u8) = .empty;
    defer sent.deinit(a);
    // length field = 3 (< HEADER_SIZE).
    var fs = FakeStream{ .chunks = &.{&.{ 0x04, 0x01, 0x00, 0x03, 0x00, 0x00, 0x01, 0x00 }}, .sent = &sent, .allocator = a };
    var t = Transport(*FakeStream).init(&fs);
    try testing.expectError(error.PacketTooShort, t.receiveMessage(a));
}

test "captured server replies are all single-packet" {
    const a = testing.allocator;
    for ([_]u64{ 6, 9, 12 }) |frame| {
        const pkt = try fixture.raw(a, frame);
        defer a.free(pkt);
        const h = try PacketHeader.unpack(pkt);
        try testing.expect(h.isEom());
        try testing.expectEqual(@as(u8, 1), h.packet_id);
    }
}

test "receive reassembles a real payload re-framed into multiple packets" {
    const a = testing.allocator;
    const real = try fixture.payload(a, 9); // 373-byte LOGIN7 response payload
    defer a.free(real);

    // Re-frame the real payload into 100-byte packets and stitch it back.
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(a);
    var off: usize = 0;
    while (off < real.len) {
        const end = @min(off + 100, real.len);
        const pkt = try makePacket(a, .tabular_result, real[off..end], end == real.len, 1);
        defer a.free(pkt);
        try stream.appendSlice(a, pkt);
        off = end;
    }

    var sent: std.ArrayList(u8) = .empty;
    defer sent.deinit(a);
    var fs = FakeStream{ .chunks = &.{stream.items}, .sent = &sent, .allocator = a };
    var t = Transport(*FakeStream).init(&fs);

    const msg = try t.receiveMessage(a);
    defer a.free(msg.payload);
    try testing.expectEqualSlices(u8, real, msg.payload);
}

// --- sendMessage tests --------------------------------------------------------

test "send a single packet" {
    const a = testing.allocator;
    var sent: std.ArrayList(u8) = .empty;
    defer sent.deinit(a);
    var fs = FakeStream{ .chunks = &.{}, .sent = &sent, .allocator = a };
    var t = Transport(*FakeStream).init(&fs);
    try t.sendMessage(.sql_batch, "payload-bytes");

    const packets = try splitPackets(a, sent.items);
    defer a.free(packets);
    try testing.expectEqual(@as(usize, 1), packets.len);
    try testing.expectEqual(PacketType.sql_batch, packets[0].header.type);
    try testing.expect(packets[0].header.isEom());
    try testing.expectEqualSlices(u8, "payload-bytes", packets[0].body);
}

test "send chunks a large payload, EOM only on the last" {
    const a = testing.allocator;
    var sent: std.ArrayList(u8) = .empty;
    defer sent.deinit(a);
    var fs = FakeStream{ .chunks = &.{}, .sent = &sent, .allocator = a };
    var t = Transport(*FakeStream).init(&fs);
    t.packet_size = 16; // max payload per packet = 16 - 8 = 8 (below the spec floor, test only)

    var payload: [20]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i);
    try t.sendMessage(.sql_batch, &payload);

    const packets = try splitPackets(a, sent.items);
    defer a.free(packets);
    try testing.expectEqual(@as(usize, 3), packets.len);
    try testing.expectEqual(@as(usize, 8), packets[0].body.len);
    try testing.expectEqual(@as(usize, 8), packets[1].body.len);
    try testing.expectEqual(@as(usize, 4), packets[2].body.len);
    try testing.expect(!packets[0].header.isEom());
    try testing.expect(!packets[1].header.isEom());
    try testing.expect(packets[2].header.isEom());
    try testing.expectEqual(@as(u8, 1), packets[0].header.packet_id);
    try testing.expectEqual(@as(u8, 2), packets[1].header.packet_id);
    try testing.expectEqual(@as(u8, 3), packets[2].header.packet_id);
}

test "send an empty payload is one EOM packet" {
    const a = testing.allocator;
    var sent: std.ArrayList(u8) = .empty;
    defer sent.deinit(a);
    var fs = FakeStream{ .chunks = &.{}, .sent = &sent, .allocator = a };
    var t = Transport(*FakeStream).init(&fs);
    try t.sendMessage(.sql_batch, "");

    const packets = try splitPackets(a, sent.items);
    defer a.free(packets);
    try testing.expectEqual(@as(usize, 1), packets.len);
    try testing.expect(packets[0].header.isEom());
    try testing.expectEqual(@as(usize, 0), packets[0].body.len);
}

test "send then receive round-trips through the framing" {
    const a = testing.allocator;
    var sent: std.ArrayList(u8) = .empty;
    defer sent.deinit(a);
    var sender_fs = FakeStream{ .chunks = &.{}, .sent = &sent, .allocator = a };
    var sender = Transport(*FakeStream).init(&sender_fs);
    try sender.sendMessage(.prelogin, "the-payload");

    var sink: std.ArrayList(u8) = .empty;
    defer sink.deinit(a);
    var reader_fs = FakeStream{ .chunks = &.{sent.items}, .sent = &sink, .allocator = a };
    var reader = Transport(*FakeStream).init(&reader_fs);
    const msg = try reader.receiveMessage(a);
    defer a.free(msg.payload);
    try testing.expectEqual(PacketType.prelogin, msg.type);
    try testing.expectEqualSlices(u8, "the-payload", msg.payload);
}

test "packet size setter rejects out-of-spec values" {
    const a = testing.allocator;
    var sent: std.ArrayList(u8) = .empty;
    defer sent.deinit(a);
    var fs = FakeStream{ .chunks = &.{}, .sent = &sent, .allocator = a };
    var t = Transport(*FakeStream).init(&fs);
    try testing.expectError(error.InvalidPacketSize, t.setPacketSize(256));
    try testing.expectError(error.InvalidPacketSize, t.setPacketSize(40000));
    try t.setPacketSize(8192);
    try testing.expectEqual(@as(u16, 8192), t.packet_size);
}
