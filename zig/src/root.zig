//! bowyer — a pure-Zig Microsoft TDS driver.
//!
//! Phase 0–2 parity with the Python implementation: byte buffer, packet framing
//! and reassembly, protocol constants, and PRELOGIN build/parse. LOGIN7 and the
//! handshake are stubbed (see `login.zig`), mirroring the Python driver's state.

const std = @import("std");

pub const constants = @import("constants.zig");
pub const buffer = @import("buffer.zig");
pub const transport = @import("transport.zig");
pub const prelogin = @import("prelogin.zig");
pub const login = @import("login.zig");

test {
    // Pull every module's colocated `test` blocks into the test build.
    _ = constants;
    _ = buffer;
    _ = transport;
    _ = prelogin;
    _ = login;
    _ = @import("fixture.zig");
    _ = @import("live.zig");
}
