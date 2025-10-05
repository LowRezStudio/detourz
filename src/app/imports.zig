const std = @import("std");
const detours = @import("detourz");
const windows = std.os.windows;

const log = std.log.scoped(.imports);

pub fn run(allocator: std.mem.Allocator, module_path: []const u8) !void {
    const wide_path = try std.unicode.utf8ToUtf16LeAllocZ(allocator, module_path);
    defer allocator.free(wide_path);

    const module_handle = try windows.LoadLibraryExW(
        wide_path.ptr,
        // .load_library_as_image_resource,
        .dont_resolve_dll_references,
    );
    defer _ = windows.FreeLibrary(module_handle);

    // Context for the import callbacks
    const ImportContext = struct {
        module_handle: windows.HMODULE,
        stdout: std.fs.File.Writer,
        current_module_handle: ?windows.HMODULE,
        current_module_name: ?[*:0]const u8,
    };

    var stdout = std.fs.File.stdout().writer(&.{});
    var context = ImportContext{
        .module_handle = module_handle,
        .stdout = stdout,
        .current_module_handle = null,
        .current_module_name = null,
    };

    stdout.interface.print("{s:>8} {s:<10} {s:<8} {s}\n", .{ "Ordinal", "RVA", "Name", "Module" }) catch return;

    const file_callback = struct {
        fn callback(
            pContext: ?*anyopaque,
            module: ?windows.HMODULE,
            pszName: ?[*:0]const u8,
        ) callconv(.c) windows.BOOL {
            const ctx = @as(*ImportContext, @ptrCast(@alignCast(pContext)));
            if (module == null and pszName == null) {
                return windows.TRUE;
            }

            if (module) |m| {
                ctx.stdout.interface.print("{any} {s}", .{ m, pszName.? }) catch return windows.TRUE;
            } else {
                ctx.stdout.interface.print("{s}", .{pszName.?}) catch return windows.TRUE;
            }

            ctx.current_module_handle = module;
            ctx.current_module_name = if (pszName) |n| n else "<unknown>";
            return windows.TRUE;
        }
    }.callback;

    const func_callback = struct {
        fn callback(
            pContext: ?*anyopaque,
            nOrdinal: windows.ULONG,
            pszName: ?[*:0]const u8,
            pvFunc: ?*anyopaque,
        ) callconv(.c) windows.BOOL {
            const ctx = @as(*ImportContext, @ptrCast(@alignCast(pContext)));

            if (nOrdinal == 0 and pszName == null and pvFunc == null) {
                return windows.TRUE;
            }

            ctx.stdout.interface.print("{d:>8}", .{nOrdinal}) catch return windows.FALSE;

            if (pvFunc) |addr| {
                const module_base = @intFromPtr(ctx.current_module_handle orelse ctx.module_handle);
                const addr_value = @intFromPtr(addr);
                const rva = if (addr_value > module_base) addr_value - module_base else addr_value;
                ctx.stdout.interface.print(" 0x{x:0>8}", .{rva}) catch return windows.FALSE;
            } else {
                ctx.stdout.interface.print(" {s:<10}", .{"<none>"}) catch return windows.FALSE;
            }

            const name_str = if (pszName) |n| n else "<none>";
            ctx.stdout.interface.print(" {s}", .{name_str}) catch return windows.FALSE;

            if (ctx.current_module_name) |mod| {
                ctx.stdout.interface.print(" {s}", .{mod}) catch return windows.FALSE;
            } else {
                ctx.stdout.interface.writeAll(" <unknown>") catch return windows.FALSE;
            }
            ctx.stdout.interface.print(" {?}", .{ctx.current_module_handle}) catch return windows.FALSE;

            ctx.stdout.interface.writeAll("\n") catch return windows.FALSE;
            return windows.TRUE;
        }
    }.callback;

    try detours.enumerateImports(module_handle, &context, file_callback, func_callback);
}
