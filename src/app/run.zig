const std = @import("std");
const detours = @import("detourz");
const windows = std.os.windows;

const log = std.log.scoped(.run);

pub fn run(allocator: std.mem.Allocator, positional_args: []const []const u8) !void {
    // Split positional_args on "--"
    const separator_index = find_separator: {
        for (positional_args, 0..) |arg, i| {
            if (std.mem.eql(u8, arg, "--")) {
                break :find_separator i;
            }
        }
        log.err("Expected '--' separator in arguments", .{});
        return;
    };

    const left_args = positional_args[0..separator_index];
    const right_args = positional_args[separator_index + 1 ..];

    // Left side: dll_paths (>= 1) + exe_path (exactly 1)
    if (left_args.len < 2) {
        log.err("Expected at least 2 arguments before '--': dll_paths and exe_path", .{});
        return;
    }
    const dll_paths = left_args[0 .. left_args.len - 1];
    const exe_path = left_args[left_args.len - 1];

    // Right side: exe_args (>= 0)
    const exe_args = right_args;

    var startup_info = std.mem.zeroes(windows.STARTUPINFOW);
    var process_information = std.mem.zeroes(windows.PROCESS_INFORMATION);

    const cmd_line_args = try std.mem.join(allocator, " ", exe_args);
    defer allocator.free(cmd_line_args);
    const cmd_line = try std.mem.join(allocator, " ", &[_][]const u8{ exe_path, cmd_line_args });
    defer allocator.free(cmd_line);

    detours.createProcessWithDlls(
        allocator,
        exe_path,
        cmd_line,
        null,
        null,
        false,
        0,
        null,
        null,
        &startup_info,
        &process_information,
        dll_paths,
        null,
    ) catch |err| {
        switch (err) {
            detours.Error.Other => {
                log.err("{}", .{windows.GetLastError()});
            },
            else => {
                log.err("{}", .{err});
            },
        }
        std.process.exit(1);
    };

    windows.WaitForSingleObject(process_information.hProcess, windows.INFINITE) catch |err| {
        log.err("WaitForSingleObject: {}", .{err});
        std.process.exit(1);
    };

    var exit_code: u32 = 0;
    const ok = windows.kernel32.GetExitCodeProcess(process_information.hProcess, &exit_code);
    if (ok == windows.FALSE) {
        log.err("GetExitCodeProcess: {}", .{windows.GetLastError()});
        std.process.exit(1);
    }

    windows.CloseHandle(process_information.hProcess);
    windows.CloseHandle(process_information.hThread);

    if (exit_code > std.math.maxInt(u8)) {
        const STATUS_DLL_NOT_FOUND = 0xC0000135;
        const STATUS_INVALID_IMAGE_NOT_MZ = 0xC000012F;

        switch (exit_code) {
            STATUS_DLL_NOT_FOUND => {
                log.err("Failed to start application. DLL not found.", .{});
            },
            STATUS_INVALID_IMAGE_NOT_MZ => {
                log.err("Failed to start application. File is not a valid DLL.", .{});
            },
            else => {
                log.err("Failed to start application. GetExitCodeProcess => 0x{x:08}", .{exit_code});
            },
        }

        std.process.exit(1);
    }

    std.process.exit(@truncate(exit_code));
}
