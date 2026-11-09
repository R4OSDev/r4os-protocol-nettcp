const std = @import("std");

/// Eigenstaendiger Bau aus dem Manifest.
///
/// Die build.zig zeigt seit 0.61.8 nur noch auf module.R4MF, statt Name,
/// Typ beziehungsweise Rolle und Metadaten ein zweites Mal hinzuschreiben.
/// Damit gibt es hier nichts mehr, was vom Manifest abweichen koennte.
pub fn build(b: *std.Build) void {
    const sdk_build = b.lazyImport(@This(), "r4os_sdk") orelse return;
    const sdk_dep = b.dependencyFromBuildZig(sdk_build, .{});
    const sdk = sdk_build.sdk(b, sdk_dep, .{});
    _ = sdk.addR4MF(b.path("module.R4MF"));
    const unit = b.addTest(.{ .root_module = b.createModule(.{ .root_source_file = b.path("src/tcp6.zig"), .target = b.graph.host, .optimize = .ReleaseSafe }) });
    unit.root_module.addImport("r4os", sdk.createR4osModule(b.graph.host, .ReleaseSafe));
    b.step("test", "Run TCP sequence, queue and terminal boundary cases").dependOn(&b.addRunArtifact(unit).step);
}
