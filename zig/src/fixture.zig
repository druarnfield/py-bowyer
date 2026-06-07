//! Test-only helper: the byte-for-byte capture oracle.
//!
//! The capture is the SAME file the Python tests use
//! (`tests/fixtures/login_select1_plaintext.json`), embedded at compile time via
//! the `fixture_json` anonymous import wired up in build.zig and parsed with
//! std.json. `raw(frame)` mirrors the `raw` pytest fixture.

const std = @import("std");

const fixture_json = @embedFile("fixture_json");

/// Full on-the-wire bytes of captured packet `frame` (incl. the 8-byte TDS
/// header), hex-decoded from the shared JSON capture. Caller owns the result.
pub fn raw(allocator: std.mem.Allocator, frame: u64) ![]u8 {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_json, .{});
    defer parsed.deinit();

    const packets = parsed.value.object.get("packets").?.array;
    for (packets.items) |pkt| {
        const obj = pkt.object;
        if (@as(u64, @intCast(obj.get("frame").?.integer)) == frame) {
            const hex = obj.get("hex").?.string;
            const out = try allocator.alloc(u8, hex.len / 2);
            errdefer allocator.free(out);
            return try std.fmt.hexToBytes(out, hex);
        }
    }
    return error.FrameNotFound;
}

/// The captured PRELOGIN/LOGIN payload (header stripped) — what
/// Transport.receiveMessage would hand back. Caller owns the result.
pub fn payload(allocator: std.mem.Allocator, frame: u64) ![]u8 {
    const full = try raw(allocator, frame);
    defer allocator.free(full);
    return allocator.dupe(u8, full[8..]);
}

const testing = std.testing;

test "raw loads a captured frame" {
    const bytes = try raw(testing.allocator, 4);
    defer testing.allocator.free(bytes);
    try testing.expectEqual(@as(usize, 88), bytes.len);
    try testing.expectEqual(@as(u8, 0x12), bytes[0]); // PRELOGIN type byte
}

test "payload strips the 8-byte header" {
    const body = try payload(testing.allocator, 4);
    defer testing.allocator.free(body);
    try testing.expectEqual(@as(usize, 80), body.len);
}
