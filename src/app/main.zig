const std = @import("std");
const detours = @import("detourz");
const flags = @import("flags");

const inject_cmd = @import("inject.zig");
const run_cmd = @import("run.zig");
const imports_cmd = @import("imports.zig");
const exports_cmd = @import("exports.zig");

const log = std.log.scoped(.detourz);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const options = flags.parse(args, "detourz", Flags, .{});

    switch (options.command) {
        .payloads => |cmd| {
            const file = try std.fs.cwd().openFile(cmd.positional.file, .{});
            defer file.close();

            const binary = try detours.Binary.open(file.handle);
            defer binary.close() catch {};

            var it = binary.enumeratePayloads();
            while (it.next()) |payload| {
                log.info("GUID: {any} Size: {d} bytes", .{ payload.guid, payload.data.len });
            }
        },

        .exports => |cmd| {
            exports_cmd.run(allocator, cmd.positional.module) catch |err| {
                log.err("{}", .{err});
                std.process.exit(1);
            };
        },

        .imports => |cmd| {
            imports_cmd.run(allocator, cmd.positional.module) catch |err| {
                log.err("{}", .{err});
                std.process.exit(1);
            };
        },

        .run => |cmd| {
            run_cmd.run(allocator, cmd.positional.trailing) catch |err| {
                log.err("{}", .{err});
                std.process.exit(1);
            };
        },

        .inject => |cmd| {
            inject_cmd.run(allocator, cmd.positional.dll_path, cmd.positional.exe_path) catch |err| {
                log.err("{}", .{err});
                std.process.exit(1);
            };
        },

        .reset => |cmd| {
            inject_cmd.run(allocator, "", cmd.positional.exe_path) catch |err| {
                log.err("{}", .{err});
                std.process.exit(1);
            };
        },
    }
}

const Flags = struct {
    pub const description =
        \\Utility for working with Microsoft Detours.
        \\
        \\Usage:
        \\  detourz <command> [options]
        \\
        \\Example:
        \\  detourz run my_dll.dll my_dll2.dll my_exe.exe -- --foo --bar
        \\
        \\Commands:
        \\  payloads <file>
        \\  exports <file>
        \\  imports <file>
        \\  run <dll> <dll> ... <exe> [-- <exe_args>...]
        \\  inject <dll> <exe>
    ;

    command: union(enum) {
        payloads: struct {
            positional: struct {
                file: []const u8,

                pub const descriptions = .{
                    .file = "Path of PE file",
                };
            },
        },

        exports: struct {
            positional: struct {
                module: []const u8,

                pub const descriptions = .{
                    .module = "Path to the PE binary file to enumerate exports from",
                };
            },
        },

        run: struct {
            positional: struct {
                trailing: []const []const u8,

                // TODO -- Flags module can't print docs for this nicely AFAICT.
            },

            pub const description =
                \\Run an executable with injected DLLs.
                \\
                \\Usage:
                \\  detourz run <dll> <dll> ... <exe> [-- <exe_args>...]
                \\
                \\Example:
                \\  detourz run my_dll.dll my_dll2.dll my_exe.exe -- --foo --bar
                \\
                \\Arguments:
                \\  <dll> <dll> ...  DLLs to inject into the executable.
                \\  <exe>            Executable to run.
                \\  <exe_args>       Arguments to pass to the executable.
            ;
        },

        imports: struct {
            positional: struct {
                module: []const u8,

                pub const descriptions = .{
                    .module = "Path to the PE binary file to enumerate imports from",
                };
            },
        },

        inject: struct {
            positional: struct {
                dll_path: []const u8,
                exe_path: []const u8,

                pub const descriptions = .{
                    .dll_path = "Path to the DLL to inject",
                    .exe_path = "Path to the target executable file",
                };
            },

            pub const description =
                \\Inject a DLL into an executable file by adding it to the import table.
                \\
                \\Requires the DLL to export a function at ordinal #1, which any valid detours DLL has to.
                \\
                \\Usage:
                \\  detourz inject <dll_path> <exe_path>
                \\
                \\Example:
                \\  detourz inject my_hook.dll application.exe
            ;
        },

        reset: struct {
            positional: struct {
                exe_path: []const u8,

                pub const descriptions = .{
                    .exe_path = "Path to the target executable file",
                };
            },

            pub const description =
                \\Remove all previously injected imports from an executable file.
                \\
                \\Usage:
                \\  detourz reset <exe_path>
                \\
                \\Example:
                \\  detourz reset application.exe
            ;
        },

        pub const descriptions = .{
            .payloads = "List detours payloads in a PE binary",
            .exports = "List exports from a PE binary",
            .imports = "List imports from a PE binary",
            .run = "Run an executable with injected DLLs",
            .inject = "Inject a DLL into an executable's import table",
            .reset = "Remove all previously injected imports from an executable file",
        };
    },
};
