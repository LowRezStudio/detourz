const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86_64,
            .os_tag = .windows,
            .abi = .gnu,
        },
    });

    const optimize = b.standardOptimizeOption(.{});

    // C++ Detours library.
    const detours_lib = buildDetours(b, target, optimize);

    // Main detours wrapper module.
    const lib_mod = b.addModule("detourz", .{
        .root_source_file = b.path("src/mod/detourz.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_mod.linkLibrary(detours_lib);

    // Internal shared module.
    const internal_mod = b.createModule(.{
        .root_source_file = b.path("src/mod/internal.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Utility application.
    const app_mod = b.createModule(.{
        .root_source_file = b.path("src/app/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    app_mod.addImport("detourz", lib_mod);
    app_mod.addImport("internal", internal_mod);

    const flags_dep = b.dependency("flags", .{
        .target = target,
        .optimize = optimize,
    });

    app_mod.addImport("flags", flags_dep.module("flags"));

    // Dlls.
    {
        // Detours for NtCreateFile, NtOpenFile.
        {
            const nt_file_mod = b.createModule(.{
                .root_source_file = b.path("src/dlls/detourz_nt_file.zig"),
                .target = target,
                .optimize = optimize,
            });
            nt_file_mod.addImport("detourz", lib_mod);
            nt_file_mod.addImport("internal", internal_mod);

            const nt_file_dll = b.addLibrary(.{
                .linkage = .dynamic,
                .name = "detourz_nt_file",
                .root_module = nt_file_mod,
            });
            b.installArtifact(nt_file_dll);
        }
    }

    const exe = b.addExecutable(.{
        .name = "detourz",
        .root_module = app_mod,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });
    const internal_unit_tests = b.addTest(.{
        .root_module = internal_mod,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const run_internal_unit_tests = b.addRunArtifact(internal_unit_tests);

    const app_unit_tests = b.addTest(.{
        .root_module = app_mod,
    });

    const run_app_unit_tests = b.addRunArtifact(app_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_app_unit_tests.step);
    test_step.dependOn(&run_internal_unit_tests.step);
}

fn buildDetours(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const detours_dep = b.dependency("detours", .{});

    // Create a static library for Detours
    const lib = b.addLibrary(.{
        .name = "detours",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });

    const source_files = &[_][]const u8{
        "detours.cpp",
        "modules.cpp",
        "disasm.cpp",
        "image.cpp",
        "creatwth.cpp",
        "disolx86.cpp",
        "disolx64.cpp",
        "disolia64.cpp",
        "disolarm.cpp",
        "disolarm64.cpp",
    };

    lib.addCSourceFiles(.{
        .root = detours_dep.path("src"),
        .files = source_files,

        // Could just do this, but I have been fixing the detected UB in my fork
        // instead.
        //
        .flags = &[_][]const u8{
            "-fno-sanitize=undefined",
        },
    });

    lib.root_module.link_libc = true;
    lib.root_module.link_libcpp = true;
    lib.root_module.linkSystemLibrary("kernel32", .{});

    switch (target.result.cpu.arch) {
        .x86 => {
            lib.root_module.addCMacro("DETOURS_X86", "1");
        },
        .x86_64 => {
            lib.root_module.addCMacro("DETOURS_X64", "1");
            lib.root_module.addCMacro("DETOURS_64BIT", "1");
        },
        .arm => {
            lib.root_module.addCMacro("DETOURS_ARM", "1");
        },
        .aarch64 => {
            lib.root_module.addCMacro("DETOURS_ARM64", "1");
            lib.root_module.addCMacro("DETOURS_64BIT", "1");
        },
        else => {
            std.debug.panic(
                "Unsupported CPU architecture: {}",
                .{target.result.cpu.arch},
            );
        },
    }

    lib.root_module.addCMacro("WIN32_LEAN_AND_MEAN", "");

    return lib;
}
