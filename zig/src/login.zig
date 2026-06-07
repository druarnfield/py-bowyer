//! LOGIN7 (Type 16) + handshake — STUBS.
//!
//! Mirrors `src/bowyer/login.py`, which is currently scaffolded: every function
//! returns `error.NotImplemented` (the Zig analog of Python's NotImplementedError).
//! LOGIN7 encoding, password obfuscation, and the PRELOGIN→LOGIN7 handshake land
//! in a later phase, verified byte-for-byte against captured frame 8.

const std = @import("std");

/// The caller-facing inputs for a login: who connects, where, and as whom. The
/// high-level layer expands these into the dozens of low-level LOGIN7 fields.
pub const LoginConfig = struct {
    host: []const u8, // SQL Server hostname; also the LOGIN7 "server name"
    user: []const u8,
    password: []const u8,
    database: []const u8 = "", // "" → server default database
    app_name: []const u8 = "bowyer",
    client_host: []const u8 = "", // this client's hostname; "" is acceptable
    library: []const u8 = "bowyer",
};

/// Every explicit LOGIN7 protocol field — the byte-exact encoder's inputs.
pub const Login7Fields = struct {
    tds_version: u32 = 0,
    packet_size: u32 = 0,
    client_prog_ver: u32 = 0,
    client_pid: u32 = 0,
    connection_id: u32 = 0,
    option_flags1: u8 = 0,
    option_flags2: u8 = 0,
    type_flags: u8 = 0,
    option_flags3: u8 = 0,
    client_timezone: i32 = 0,
    client_lcid: u32 = 0,
    client_id_mac: [6]u8 = .{0} ** 6,
    host: []const u8 = "",
    user: []const u8 = "",
    password: []const u8 = "",
    app: []const u8 = "",
    server: []const u8 = "",
    library: []const u8 = "",
};

/// Encode a password into its LOGIN7 wire form: UTF-16LE, then per byte swap the
/// nibbles and XOR 0xA5. Caller owns the result.
pub fn obfuscatePassword(allocator: std.mem.Allocator, password: []const u8) ![]u8 {
    _ = allocator;
    _ = password;
    return error.NotImplemented;
}

/// Reverse `obfuscatePassword`. Caller owns the result.
pub fn deobfuscatePassword(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    _ = allocator;
    _ = data;
    return error.NotImplemented;
}

/// Build a complete LOGIN7 packet (header + message), byte-exact. Caller owns it.
pub fn buildLogin7(allocator: std.mem.Allocator, fields: Login7Fields) ![]u8 {
    _ = allocator;
    _ = fields;
    return error.NotImplemented;
}

/// Ergonomic wrapper: build LOGIN7 from a LoginConfig + driver defaults.
pub fn buildLogin7For(allocator: std.mem.Allocator, config: LoginConfig) ![]u8 {
    _ = allocator;
    _ = config;
    return error.NotImplemented;
}

/// Run PRELOGIN → LOGIN7 over `t`; return the raw Type-4 login reply. `t` is any
/// `Transport(Stream)`. Caller owns the result.
pub fn doHandshake(t: anytype, allocator: std.mem.Allocator, config: LoginConfig) ![]u8 {
    _ = t;
    _ = allocator;
    _ = config;
    return error.NotImplemented;
}

// --- tests --------------------------------------------------------------------

const testing = std.testing;

test "password obfuscation is not implemented yet" {
    try testing.expectError(error.NotImplemented, obfuscatePassword(testing.allocator, "pw"));
    try testing.expectError(error.NotImplemented, deobfuscatePassword(testing.allocator, "pw"));
}

test "LOGIN7 encoders are not implemented yet" {
    try testing.expectError(error.NotImplemented, buildLogin7(testing.allocator, .{}));
    const config = LoginConfig{ .host = "h", .user = "u", .password = "p" };
    try testing.expectError(error.NotImplemented, buildLogin7For(testing.allocator, config));
}

test "handshake is not implemented yet" {
    const config = LoginConfig{ .host = "h", .user = "u", .password = "p" };
    try testing.expectError(error.NotImplemented, doHandshake({}, testing.allocator, config));
}
