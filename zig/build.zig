const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The public library module, importable by consumers as `@import("bowyer")`.
    _ = b.addModule("bowyer", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    // `-Dlive` opts into the integration test that talks to a real SQL Server.
    const live = b.option(bool, "live", "run live integration tests against a SQL Server") orelse false;
    const options = b.addOptions();
    options.addOption(bool, "live", live);

    // A separate module for the test build so the public library module stays
    // free of the test-only fixture embed and build options.
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_mod.addOptions("build_options", options);
    // The byte-for-byte capture oracle is the SAME file the Python tests use; we
    // embed it (compile time) and parse it with std.json in fixture.zig.
    test_mod.addAnonymousImport("fixture_json", .{
        .root_source_file = b.path("../tests/fixtures/login_select1_plaintext.json"),
    });

    const tests = b.addTest(.{ .root_module = test_mod });
    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
}
