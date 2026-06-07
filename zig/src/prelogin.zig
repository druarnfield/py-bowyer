//! Build and parse PRELOGIN (Type 18) — the encryption/option negotiation.
//!
//! The payload is an option directory — `TOKEN(1) Offset(2,BE) Length(2,BE)`
//! entries terminated by 0xFF — followed by the data blobs the offsets point
//! into. Offsets/lengths are big-endian (the payload exception); all integer
//! serialization goes through `buffer`.
//!
//! v1 advertises VERSION + ENCRYPTION=not_sup so the server replies in plaintext.

const std = @import("std");
const c = @import("constants.zig");
const buffer = @import("buffer.zig");

const PreLoginOption = c.PreLoginOption;
const EncryptionLevel = c.EncryptionLevel;
const Writer = buffer.Writer;
const Reader = buffer.Reader;

// Client version advertised in the VERSION option (4-byte version + 2-byte
// subbuild). Driver-identity policy, kept next to the only code that uses it.
const CLIENT_VERSION = [4]u8{ 0, 0, 0, 1 };
const CLIENT_SUBBUILD: u16 = 0;

const OPTION_ENTRY_SIZE = 5; // token(1) + offset(2,BE) + length(2,BE)

/// One parsed PRELOGIN option; `data` borrows the input payload (no copy).
pub const Option = struct {
    token: PreLoginOption,
    data: []const u8,
};

/// Build a PRELOGIN payload (no packet header) advertising VERSION + ENCRYPTION.
/// Caller owns the returned slice.
pub fn buildPrelogin(allocator: std.mem.Allocator, encryption: EncryptionLevel) ![]u8 {
    var version_blob: [6]u8 = undefined;
    @memcpy(version_blob[0..4], &CLIENT_VERSION);
    std.mem.writeInt(u16, version_blob[4..6], CLIENT_SUBBUILD, .big);
    const enc_blob = [1]u8{@intFromEnum(encryption)};

    const Opt = struct { token: PreLoginOption, data: []const u8 };
    const options = [_]Opt{
        .{ .token = .version, .data = &version_blob },
        .{ .token = .encryption, .data = &enc_blob },
    };

    var out = Writer.init(allocator);
    errdefer out.deinit();

    // The data section starts right after the directory (one entry per option +
    // the 1-byte terminator). Write the directory with running offsets first...
    var offset: u16 = @intCast(options.len * OPTION_ENTRY_SIZE + 1);
    for (options) |opt| {
        try out.writeByte(@intFromEnum(opt.token));
        try out.writeInt(u16, offset, .big);
        try out.writeInt(u16, @intCast(opt.data.len), .big);
        offset += @intCast(opt.data.len);
    }
    try out.writeByte(@intFromEnum(PreLoginOption.terminator));
    // ...then the data blobs the offsets point at.
    for (options) |opt| try out.writeBytes(opt.data);

    return out.toOwnedSlice();
}

/// Parse a PRELOGIN response payload (header already stripped by the transport)
/// into a list of options whose `data` slices borrow `payload`. Caller frees the
/// returned slice. An unrecognized token is an error (unexpected server).
pub fn parsePrelogin(allocator: std.mem.Allocator, payload: []const u8) ![]Option {
    var r = Reader.init(payload);
    var list: std.ArrayList(Option) = .empty;
    errdefer list.deinit(allocator);
    while (true) {
        const token_byte = try r.readByte();
        if (token_byte == @intFromEnum(PreLoginOption.terminator)) break;
        const token = std.enums.fromInt(PreLoginOption, token_byte) orelse
            return error.UnknownPreLoginOption;
        const offset = try r.readInt(u16, .big);
        const length = try r.readInt(u16, .big);
        if (@as(usize, offset) + length > payload.len) return error.OptionOutOfBounds;
        try list.append(allocator, .{ .token = token, .data = payload[offset .. offset + length] });
    }
    return list.toOwnedSlice(allocator);
}

/// Return the server's ENCRYPTION level from a PRELOGIN response payload. Walks
/// the directory with zero allocation. Errors if there is no ENCRYPTION option.
pub fn parsePreloginEncryption(payload: []const u8) !EncryptionLevel {
    var r = Reader.init(payload);
    while (true) {
        const token_byte = try r.readByte();
        if (token_byte == @intFromEnum(PreLoginOption.terminator)) break;
        const offset = try r.readInt(u16, .big);
        const length = try r.readInt(u16, .big);
        if (token_byte == @intFromEnum(PreLoginOption.encryption)) {
            if (length < 1 or offset >= payload.len) return error.MissingEncryptionOption;
            return std.enums.fromInt(EncryptionLevel, payload[offset]) orelse
                error.InvalidEncryptionLevel;
        }
    }
    return error.MissingEncryptionOption;
}

// --- tests --------------------------------------------------------------------

const testing = std.testing;
const fixture = @import("fixture.zig");

fn findOption(options: []const Option, token: PreLoginOption) ?[]const u8 {
    for (options) |o| if (o.token == token) return o.data;
    return null;
}

test "build_prelogin is byte-exact" {
    const a = testing.allocator;
    const got = try buildPrelogin(a, .not_sup);
    defer a.free(got);
    const expected = [_]u8{
        0x00, 0x00, 0x0b, 0x00, 0x06, // VERSION: token, offset=11, len=6
        0x01, 0x00, 0x11, 0x00, 0x01, // ENCRYPTION: token, offset=17, len=1
        0xff, // terminator
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // VERSION data: version + subbuild
        0x02, // ENCRYPTION data: not_sup
    };
    try testing.expectEqualSlices(u8, &expected, got);
}

test "build_prelogin carries the requested encryption level" {
    const a = testing.allocator;
    for ([_]EncryptionLevel{ .off, .on, .not_sup, .req }) |level| {
        const got = try buildPrelogin(a, level);
        defer a.free(got);
        try testing.expectEqual(@intFromEnum(level), got[got.len - 1]);
    }
}

test "build_prelogin puts VERSION first" {
    const a = testing.allocator;
    const got = try buildPrelogin(a, .not_sup);
    defer a.free(got);
    try testing.expectEqual(@intFromEnum(PreLoginOption.version), got[0]);
}

test "parse encryption from captured frames 4 and 6" {
    const a = testing.allocator;
    for ([_]u64{ 4, 6 }) |frame| {
        const body = try fixture.payload(a, frame);
        defer a.free(body);
        try testing.expectEqual(EncryptionLevel.not_sup, try parsePreloginEncryption(body));
    }
}

test "parse returns every option (frame 4)" {
    const a = testing.allocator;
    const body = try fixture.payload(a, 4);
    defer a.free(body);
    const options = try parsePrelogin(a, body);
    defer a.free(options);

    try testing.expectEqual(@as(usize, 6), options.len);
    try testing.expectEqualSlices(
        u8,
        &.{ 0x08, 0x00, 0x09, 0x01, 0x00, 0x00 },
        findOption(options, .version).?,
    );
    try testing.expectEqualSlices(u8, &.{0x02}, findOption(options, .encryption).?);
}

test "parse handles zero-length options (frame 6)" {
    const a = testing.allocator;
    const body = try fixture.payload(a, 6);
    defer a.free(body);
    const options = try parsePrelogin(a, body);
    defer a.free(options);
    try testing.expectEqual(@as(usize, 0), findOption(options, .threadid).?.len);
    try testing.expectEqual(@as(usize, 0), findOption(options, .traceid).?.len);
}

test "build then parse round-trips for every encryption level" {
    const a = testing.allocator;
    for ([_]EncryptionLevel{ .off, .on, .not_sup, .req }) |level| {
        const payload = try buildPrelogin(a, level);
        defer a.free(payload);
        try testing.expectEqual(level, try parsePreloginEncryption(payload));
        const options = try parsePrelogin(a, payload);
        defer a.free(options);
        try testing.expectEqualSlices(
            u8,
            &.{ 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 },
            findOption(options, .version).?,
        );
    }
}

test "parse encryption raises when the option is absent" {
    // A directory with only VERSION (no ENCRYPTION option).
    const payload = [_]u8{
        0x00, 0x00, 0x06, 0x00, 0x06, // VERSION: token, offset=6, len=6
        0xff, // terminator
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // version data
    };
    try testing.expectError(error.MissingEncryptionOption, parsePreloginEncryption(&payload));
}
