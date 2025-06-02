const std = @import("std");
const detours = @import("detourz");

const log = std.log.scoped(.inject);

const windows = std.os.windows;

pub fn run(allocator: std.mem.Allocator, dll_path: []const u8, exe_path: []const u8) !void {
    if (dll_path.len > 0) {
        try validateDllExportsOrdinal1(dll_path);
    }

    try editExeImports(allocator, dll_path, exe_path);

    const stdout = std.io.getStdOut().writer();
    if (dll_path.len > 0) {
        stdout.print("Successfully injected {s} into {s}\n", .{ dll_path, exe_path }) catch return;
    } else {
        stdout.print("Successfully removed all imports from {s}\n", .{exe_path}) catch return;
    }
}

fn validateDllExportsOrdinal1(dll_path: []const u8) !void {
    const allocator = std.heap.page_allocator;
    const dll_path_w = try std.unicode.utf8ToUtf16LeAllocZ(allocator, dll_path);
    defer allocator.free(dll_path_w);

    const hDll = windows.LoadLibraryExW(
        dll_path_w.ptr,
        .dont_resolve_dll_references,
    ) catch |err| {
        log.err("LoadLibraryEx({s}) failed: {}", .{ dll_path, err });
        return err;
    };
    defer _ = windows.FreeLibrary(hDll);

    const cb = struct {
        fn exportCallback(
            context: ?*anyopaque,
            ordinal: windows.ULONG,
            name: ?[*:0]const u8,
            code: ?*anyopaque,
        ) callconv(.C) windows.BOOL {
            _ = name;
            _ = code;

            if (ordinal == 1) {
                const pfound = @as(*bool, @ptrCast(@alignCast(context.?)));
                pfound.* = true;
                return windows.FALSE;
            }

            return windows.TRUE;
        }
    };

    var found_ordinal_1 = false;
    detours.enumerateExports(hDll, &found_ordinal_1, cb.exportCallback) catch |err| {
        log.err("Failed to enumerate exports: {}", .{err});
        return err;
    };

    if (!found_ordinal_1) {
        log.err("{s} does not export function with ordinal #1", .{dll_path});
        return error.MissingOrdinal1;
    }
}

/// Reset the imports of an executable file, then add dll_path.
///
/// If dll_path is empty, remove any previously added imports.
///
/// TODO: Robust add/remove/reset.
fn editExeImports(allocator: std.mem.Allocator, dll_path: []const u8, exe_path: []const u8) !void {
    const dir = std.fs.cwd();

    // TODO: Use 'std.fs.atomicFile'?
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.detourz.tmp", .{exe_path});
    defer allocator.free(tmp_path);
    const backup_path = try std.fmt.allocPrint(allocator, "{s}.detourz.backup", .{exe_path});
    defer allocator.free(backup_path);

    // Make a copy of the original file, with edits applied.
    {
        const tmp_file = dir.createFile(tmp_path, .{}) catch |err| {
            log.err("Failed to create {s}: {}", .{ tmp_path, err });
            return err;
        };
        defer tmp_file.close();

        // Read the exe into memory for editing.
        const exe = x: {
            const exe_file = dir.openFile(exe_path, .{}) catch |err| {
                log.err("Failed to open {s}: {}", .{ exe_path, err });
                return err;
            };
            defer exe_file.close();

            break :x try detours.Binary.open(exe_file.handle);
        };
        defer exe.close() catch {};

        exe.resetImports() catch |err| {
            log.err("Failed to reset imports: {}", .{err});
            return err;
        };

        if (dll_path.len > 0) {
            const dll_name = std.fs.path.basename(dll_path);
            const dll_name_z = try allocator.dupeZ(u8, dll_name);
            defer allocator.free(dll_name_z);

            var context = CallbackContext{
                .dll_name = dll_name_z,
                .added_dll = false,
            };

            // Add the DLL.
            try exe.editImports(
                &context,
                addBywayCallback,
                null,
                null,
                null,
            );
        }

        // Print the imports.
        std.io.getStdOut().writer().print("Imports:\n", .{}) catch return;
        try exe.editImports(
            null,
            listBywayCallback,
            listFileCallback,
            null,
            null,
        );

        // Write the modified binary
        try exe.write(tmp_file.handle);
    }

    dir.rename(exe_path, backup_path) catch |err| {
        log.err("Failed to rename {s} to {s}: {}", .{ exe_path, backup_path, err });
        return err;
    };
    dir.rename(tmp_path, exe_path) catch |err| {
        log.err("Failed to rename {s} to {s}: {}", .{ tmp_path, exe_path, err });
        return err;
    };
    dir.deleteFile(backup_path) catch |err| {
        log.err("Failed to delete {s}: {}", .{ backup_path, err });
        return err;
    };
}

const CallbackContext = struct {
    dll_name: [:0]const u8,
    added_dll: bool,
};

fn addBywayCallback(
    context: ?*anyopaque,
    file: ?[*:0]const u8,
    out_file: *?[*:0]const u8,
) callconv(.C) windows.BOOL {
    const ctx = @as(*CallbackContext, @ptrCast(@alignCast(context.?)));

    if (file == null and !ctx.added_dll) {
        ctx.added_dll = true;
        out_file.* = ctx.dll_name;
    }

    return windows.TRUE;
}

fn listBywayCallback(
    context: ?*anyopaque,
    file: ?[*:0]const u8,
    out_file: *?[*:0]const u8,
) callconv(.C) windows.BOOL {
    _ = context;

    const stdout = std.io.getStdOut().writer();
    if (file) |f| {
        stdout.print("  {s}\n", .{f}) catch return windows.FALSE;
    }

    out_file.* = file;
    return windows.TRUE;
}

fn listFileCallback(
    context: ?*anyopaque,
    orig_file: [*:0]const u8,
    file: [*:0]const u8,
    out_file: *?[*:0]const u8,
) callconv(.C) windows.BOOL {
    _ = context;

    const stdout = std.io.getStdOut().writer();

    if (std.mem.eql(u8, std.mem.span(orig_file), std.mem.span(file))) {
        stdout.print("  {s}\n", .{orig_file}) catch return windows.FALSE;
    } else {
        stdout.print("  {s} -> {s}\n", .{ orig_file, file }) catch return windows.FALSE;
    }

    out_file.* = file;
    return windows.TRUE;
}
