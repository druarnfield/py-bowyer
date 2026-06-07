//! Gated live integration test against a real SQL Server.
//!
//! Skipped unless built with `-Dlive` (and a server is reachable — see
//! `compose.yml`). Run: `docker compose up -d` then `zig build test -Dlive`.

const std = @import("std");
const build_options = @import("build_options");
const c = @import("constants.zig");
const transport = @import("transport.zig");
const prelogin = @import("prelogin.zig");

test "live: PRELOGIN over a real socket gets a Type-4 reply in plaintext" {
    if (!build_options.live) return error.SkipZigTest;

    const a = std.testing.allocator;
    const io = std.testing.io;

    var net: transport.NetStream = undefined;
    try net.connect(io, "127.0.0.1", 1433);
    defer net.close();
    var t = transport.Transport(*transport.NetStream).init(&net);

    const payload = try prelogin.buildPrelogin(a, .not_sup);
    defer a.free(payload);
    try t.sendMessage(.prelogin, payload);

    const msg = try t.receiveMessage(a);
    defer a.free(msg.payload);

    // Every server reply is a Type-4 (TABULAR_RESULT) message.
    try std.testing.expectEqual(c.PacketType.tabular_result, msg.type);
    // The server must not demand encryption, or plaintext v1 can't proceed.
    const enc = try prelogin.parsePreloginEncryption(msg.payload);
    try std.testing.expect(enc != .req);
}
