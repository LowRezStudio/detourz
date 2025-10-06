const std = @import("std");
const windows = std.os.windows;
const builtin = @import("builtin");

const BinaryHandle = opaque {};

const WINAPI: std.builtin.CallingConvention = if (builtin.cpu.arch == .x86) .{ .x86_stdcall = .{} } else .c;

// Missing from windows.Win32Error.
const ERROR_INVALID_OPERATION: u32 = 4317;

pub const Error = error{
    BadExeFormat,
    ExeMarkedInvalid,
    InvalidBlock,
    InvalidData,
    InvalidExeSignature,
    InvalidHandle,
    InvalidOperation,
    ModNotFound,
    NotEnoughMemory,

    /// Check std.os.windows.GetLastError().
    Other,
};

// Generic error for BOOL functions failing without GetLastError
const GenericError = error{
    Failed,
};

fn checkLastError() Error!void {
    const code: windows.LONG = @intFromEnum(windows.GetLastError());
    try checkWin32Error(code);
}

fn checkWin32Error(code: windows.LONG) Error!void {
    const code_u32 = @as(u32, @bitCast(code));
    if (code_u32 == ERROR_INVALID_OPERATION) return Error.InvalidOperation;
    const win_err: windows.Win32Error = @enumFromInt(code_u32);
    return switch (win_err) {
        .SUCCESS => {},
        .BAD_EXE_FORMAT => Error.BadExeFormat,
        .EXE_MARKED_INVALID => Error.ExeMarkedInvalid,
        .INVALID_BLOCK => Error.InvalidBlock,
        .INVALID_DATA => Error.InvalidData,
        .INVALID_EXE_SIGNATURE => Error.InvalidExeSignature,
        .INVALID_HANDLE => Error.InvalidHandle,
        .MOD_NOT_FOUND => Error.ModNotFound,
        .NOT_ENOUGH_MEMORY => Error.NotEnoughMemory,
        else => Error.Other,
    };
}

fn checkBoolLastError(success: windows.BOOL) Error!void {
    if (success != windows.FALSE) return;
    try checkLastError();
    return Error.Other;
}

fn checkBoolGeneric(success: windows.BOOL) GenericError!void {
    if (success != windows.FALSE) return;
    return GenericError.Failed;
}

fn checkNotNullLastError(ptr: ?*anyopaque) Error!*anyopaque {
    if (ptr) |p| return p;
    try checkLastError();
    return Error.Other;
}

fn checkNotNullGeneric(ptr: ?*anyopaque) GenericError!*anyopaque {
    if (ptr) |p| return p;
    return GenericError.Failed;
}

/// Allocate an executable region near the given address.
pub fn allocateRegionWithinJumpBounds(pbTarget: ?*const anyopaque, allocated_size: *u32) ?*anyopaque {
    return DetourAllocateRegionWithinJumpBounds(pbTarget, allocated_size);
}

/// Attach a detour to a target function.
pub fn attach(target_fn_ptr: *?*anyopaque, detour_fn: ?*anyopaque) Error!void {
    const result = DetourAttach(target_fn_ptr, detour_fn);
    try checkWin32Error(result);
}

/// Attach a detour to a target function and retrieve additional detail.
pub fn attachEx(
    target_fn_ptr: *?*anyopaque,
    detour_fn: ?*anyopaque,
    real_trampoline: ?*?*anyopaque,
    real_target: ?*?*anyopaque,
    real_detour: ?*?*anyopaque,
) Error!void {
    const result = DetourAttachEx(
        target_fn_ptr,
        detour_fn,
        real_trampoline,
        real_target,
        real_detour,
    );
    try checkWin32Error(result);
}

const Payload = struct {
    data: []const u8,
    guid: windows.GUID,
};

/// Struct for operations on an opened binary file handle.
pub const Binary = struct {
    handle: *BinaryHandle,

    const Self = @This();

    /// Read the contents of a binary into memory for editing.
    pub fn open(file_handle: windows.HANDLE) Error!Self {
        if (DetourBinaryOpen(file_handle)) |handle| {
            return Self{ .handle = handle };
        }

        try checkLastError();
        return error.Other;
    }

    /// Close a binary opened for editing.
    pub fn close(self: Self) GenericError!void {
        const ok = DetourBinaryClose(self.handle);
        try checkBoolGeneric(ok);
    }

    /// Remove a payload from a binary.
    pub fn deletePayload(self: Self, guid: *const windows.GUID) GenericError!void {
        const ok = DetourBinaryDeletePayload(self.handle, guid);
        try checkBoolGeneric(ok);
    }

    /// Edit the import tables of a binary.
    pub fn editImports(
        self: Self,
        context: ?*anyopaque,
        byway_callback: ?BinaryBywayCallback,
        file_callback: ?BinaryFileCallback,
        symbol_callback: ?BinarySymbolCallback,
        commit_callback: ?BinaryCommitCallback,
    ) GenericError!void {
        const ok = DetourBinaryEditImports(
            self.handle,
            context,
            byway_callback,
            file_callback,
            symbol_callback,
            commit_callback,
        );
        try checkBoolGeneric(ok);
    }

    const PayloadIterator = struct {
        handle: *BinaryHandle,
        iterator: u32,

        pub fn next(self: *PayloadIterator) ?Payload {
            var payload: Payload = undefined;
            var data_size: u32 = undefined;

            const maybe_data = DetourBinaryEnumeratePayloads(
                self.handle,
                &payload.guid,
                &data_size,
                &self.iterator,
            );
            if (maybe_data) |data| {
                const p: [*]u8 = @ptrCast(data);
                payload.data = p[0..data_size];
                return payload;
            }

            return null;
        }
    };

    pub fn enumeratePayloads(self: Self) PayloadIterator {
        return PayloadIterator{
            .handle = self.handle,
            .iterator = 0,
        };
    }

    pub fn findPayload(self: Self, guid: *const windows.GUID) ?Payload {
        var data_size: u32 = undefined;

        const maybe_data = DetourBinaryFindPayload(
            self.handle,
            guid,
            &data_size,
        );
        if (maybe_data) |data| {
            const p: [*]u8 = @ptrCast(data);
            return Payload{
                .data = p[0..data_size],
                .guid = guid.*,
            };
        }

        return null;
    }

    /// Remove all payloads from a binary.
    pub fn purgePayloads(self: Self) GenericError!void {
        const ok = DetourBinaryPurgePayloads(self.handle);
        try checkBoolGeneric(ok);
    }

    /// Remove all edits by Detours of the binary's import table.
    pub fn resetImports(self: Self) GenericError!void {
        const ok = DetourBinaryResetImports(self.handle);
        try checkBoolGeneric(ok);
    }

    /// Attach or replace a payload in a binary.
    ///
    /// Returns pointer to the payload data within the binary structure, or null
    /// on failure.
    pub fn setPayload(self: Self, payload: Payload) GenericError!*anyopaque {
        const maybe_data = DetourBinarySetPayload(
            self.handle,
            payload.guid,
            payload.data.ptr,
            payload.data.len,
        );
        return try checkNotNullGeneric(maybe_data);
    }

    /// Write an updated binary to a file.
    pub fn write(self: Self, file_handle: windows.HANDLE) GenericError!void {
        const ok = DetourBinaryWrite(self.handle, file_handle);
        try checkBoolGeneric(ok);
    }
};

/// Return a pointer to the code that implements a function pointer, resolving
/// import table jumps.
///
/// Returns the address of the function's global data, or null if resolution
/// fails.
pub fn codeFromPointer(func_ptr: ?*anyopaque, globals_ptr: ?*?*anyopaque) ?*anyopaque {
    return DetourCodeFromPointer(func_ptr, globals_ptr);
}

/// Copy a payload into a target process.
pub fn copyPayloadToProcess(
    process_handle: windows.HANDLE,
    payload: Payload,
) Error!void {
    const ok = DetourCopyPayloadToProcess(
        process_handle,
        &payload.guid,
        payload.data.ptr,
        @intCast(payload.data.len),
    );
    try checkBoolLastError(ok);
}

/// Copy a payload into a target process and return a pointer to it in the
/// remote process.
///
/// Uses GetLastError on failure (returns null).
pub fn copyPayloadToProcessEx(
    process_handle: windows.HANDLE,
    guid: *const windows.GUID,
    data: ?*const anyopaque,
    data_size: u32,
) Error!*anyopaque {
    const result = DetourCopyPayloadToProcessEx(process_handle, guid, data, data_size);
    return checkNotNullLastError(result);
}

/// Wrapper for DetourCreateProcessWithDll (Deprecated). Uses CreateProcess error codes (GetLastError).
pub fn createProcessWithDll(
    application_name: ?[:0]const u16,
    command_line: ?[:0]u16,
    process_attributes: ?*windows.SECURITY_ATTRIBUTES,
    thread_attributes: ?*windows.SECURITY_ATTRIBUTES,
    inherit_handles: bool,
    creation_flags: u32,
    environment: ?*anyopaque,
    current_directory: ?[:0]const u16,
    startup_info: *windows.STARTUPINFOW,
    process_information: *windows.PROCESS_INFORMATION,
    dll_name: [:0]const u8,
    create_process_fn: ?CreateProcessRoutineW,
) Error!void {
    // Explicitly handle optional slice to optional C pointer conversion
    const app_name_ptr = if (application_name) |s| s.ptr else null;
    const cmd_line_ptr = if (command_line) |s| s.ptr else null;
    const cur_dir_ptr = if (current_directory) |s| s.ptr else null;

    const ok = DetourCreateProcessWithDllW(
        app_name_ptr,
        cmd_line_ptr,
        process_attributes,
        thread_attributes,
        if (inherit_handles) windows.TRUE else windows.FALSE,
        creation_flags,
        environment,
        cur_dir_ptr,
        startup_info,
        process_information,
        dll_name.ptr, // Implicit cast for non-optional
        create_process_fn,
    );
    try checkBoolLastError(ok);
}

/// Create a new process and load a DLL into it. Chooses appropriate 32/64 bit DLL.
/// Uses CreateProcess error codes (GetLastError).
pub fn createProcessWithDllEx(
    application_name: ?[:0]const u16,
    command_line: ?[:0]u16,
    process_attributes: ?*windows.SECURITY_ATTRIBUTES,
    thread_attributes: ?*windows.SECURITY_ATTRIBUTES,
    inherit_handles: bool,
    creation_flags: u32,
    environment: ?*anyopaque,
    current_directory: ?[:0]const u16,
    startup_info: *windows.STARTUPINFOW,
    process_information: *windows.PROCESS_INFORMATION,
    dll_name: [:0]const u8,
    create_process_fn: ?CreateProcessRoutineW,
) Error!void {
    const app_name_ptr = if (application_name) |s| s.ptr else null;
    const cmd_line_ptr = if (command_line) |s| s.ptr else null;
    const cur_dir_ptr = if (current_directory) |s| s.ptr else null;

    const ok = DetourCreateProcessWithDllExW(
        app_name_ptr,
        cmd_line_ptr,
        process_attributes,
        thread_attributes,
        if (inherit_handles) windows.TRUE else windows.FALSE,
        creation_flags,
        environment,
        cur_dir_ptr,
        startup_info,
        process_information,
        dll_name.ptr, // Implicit cast for non-optional
        create_process_fn,
    );
    try checkBoolLastError(ok);
}

pub fn createProcessWithDlls(
    allocator: std.mem.Allocator,
    application_name: ?[]const u8,
    command_line: ?[]const u8,
    process_attributes: ?*windows.SECURITY_ATTRIBUTES,
    thread_attributes: ?*windows.SECURITY_ATTRIBUTES,
    inherit_handles: bool,
    creation_flags: u32,
    environment: ?*anyopaque,
    current_directory: ?[]const u8,
    startup_info: *windows.STARTUPINFOW,
    process_information: *windows.PROCESS_INFORMATION,
    dll_paths: []const []const u8,
    create_process_fn: ?CreateProcessRoutineW,
) !void {
    const app_name =
        if (application_name) |s| try std.unicode.wtf8ToWtf16LeAllocZ(allocator, s) else null;
    const cmd_line =
        if (command_line) |s| try std.unicode.wtf8ToWtf16LeAllocZ(allocator, s) else null;
    const cur_dir =
        if (current_directory) |s| try std.unicode.wtf8ToWtf16LeAllocZ(allocator, s) else null;

    defer {
        if (app_name) |s| allocator.free(s);
        if (cmd_line) |s| allocator.free(s);
        if (cur_dir) |s| allocator.free(s);
    }

    // Null terminate the dll paths and pass an array of pointers.
    //
    // BUG -- Weirdly, the API expects a u8 string for this parameter even
    // though it takes wide strings for other parameters.
    var dll_paths_z = try std.ArrayList([*:0]const u8).initCapacity(allocator, dll_paths.len);
    defer {
        for (dll_paths_z.items) |path| {
            allocator.free(std.mem.span(path));
        }
        dll_paths_z.deinit(allocator);
    }

    for (dll_paths) |path| {
        const path_z = try allocator.dupeZ(u8, path);
        dll_paths_z.appendAssumeCapacity(path_z.ptr);
    }

    try createProcessWithDllsW(
        app_name,
        cmd_line,
        process_attributes,
        thread_attributes,
        inherit_handles,
        creation_flags,
        environment,
        cur_dir,
        startup_info,
        process_information,
        dll_paths_z.items,
        create_process_fn,
    );
}

/// Create a new process and load multiple DLLs into it.
///
/// Uses CreateProcess error codes (GetLastError).
pub fn createProcessWithDllsW(
    application_name: ?[:0]const u16,
    command_line: ?[:0]u16,
    process_attributes: ?*windows.SECURITY_ATTRIBUTES,
    thread_attributes: ?*windows.SECURITY_ATTRIBUTES,
    inherit_handles: bool,
    creation_flags: u32,
    environment: ?*anyopaque,
    current_directory: ?[:0]const u16,
    startup_info: *windows.STARTUPINFOW,
    process_information: *windows.PROCESS_INFORMATION,
    dll_paths: []const [*:0]const u8,
    create_process_fn: ?CreateProcessRoutineW,
) Error!void {
    const app_name_ptr = if (application_name) |s| s.ptr else null;
    const cmd_line_ptr = if (command_line) |s| s.ptr else null;
    const cur_dir_ptr = if (current_directory) |s| s.ptr else null;

    const ok = DetourCreateProcessWithDllsW(
        app_name_ptr,
        cmd_line_ptr,
        process_attributes,
        thread_attributes,
        if (inherit_handles) windows.TRUE else windows.FALSE,
        creation_flags,
        environment,
        cur_dir_ptr,
        startup_info,
        process_information,
        @intCast(dll_paths.len),
        dll_paths.ptr,
        create_process_fn,
    );
    try checkBoolLastError(ok);
}

/// Detach a detour from a target function.
pub fn detach(target_fn_ptr: *?*anyopaque, detour_fn: ?*anyopaque) Error!void {
    const result = DetourDetach(target_fn_ptr, detour_fn);
    try checkWin32Error(result);
}

/// Enumerate exports from a module.
pub fn enumerateExports(module_handle: ?windows.HMODULE, context: ?*anyopaque, callback: EnumerateExportCallback) Error!void {
    const ok = DetourEnumerateExports(module_handle, context, callback);
    try checkBoolLastError(ok);
}

/// Enumerate imports from a module.
pub fn enumerateImports(
    module_handle: ?windows.HMODULE,
    context: ?*anyopaque,
    file_callback: ?ImportFileCallback,
    func_callback: ?ImportFuncCallback,
) Error!void {
    const ok = DetourEnumerateImports(module_handle, context, file_callback, func_callback);
    try checkBoolLastError(ok);
}

/// Enumerate imports from a module, providing pointers into the IAT.
pub fn enumerateImportsEx(
    module_handle: ?windows.HMODULE,
    context: ?*anyopaque,
    file_callback: ?ImportFileCallback,
    func_callback: ?ImportFuncCallbackEx,
) Error!void {
    const ok = DetourEnumerateImportsEx(module_handle, context, file_callback, func_callback);
    try checkBoolLastError(ok);
}

/// Enumerate the PE binaries (modules) in the current process.
/// Pass null to start, pass the previous result to continue. Returns null when done.
pub fn enumerateModules(last_module: ?windows.HMODULE) ?windows.HMODULE {
    return DetourEnumerateModules(last_module);
}

/// Find the address of a target function by module path and function name.
/// Returns null if not found. (Module/Function names are ANSI/u8)
pub fn findFunction(module_path: [:0]const u8, function_name: [:0]const u8) ?*anyopaque {
    // Implicit cast from slice to C pointer for non-optional args works
    return DetourFindFunction(module_path, function_name);
}

/// Return the address of the specified payload within a specific module.
/// Uses GetLastError on failure (returns null).
pub fn findPayload(module_handle: ?windows.HMODULE, guid: *const windows.GUID, data_size: ?*u32) Error!*anyopaque {
    const result = DetourFindPayload(module_handle, guid, data_size);
    return checkNotNullLastError(result);
}

/// Return the address of the specified payload within any module in the current process.
/// Uses GetLastError on failure (returns null), including ERROR_MOD_NOT_FOUND.
pub fn findPayloadEx(guid: *const windows.GUID, data_size: ?*u32) Error!*anyopaque {
    const result = DetourFindPayloadEx(guid, data_size);
    return checkNotNullLastError(result);
}

/// Return the address of the specified payload within a remote process.
/// Uses GetLastError on failure (returns null).
pub fn findRemotePayload(process_handle: windows.HANDLE, guid: *const windows.GUID, data_size: ?*u32) Error!*anyopaque {
    const result = DetourFindRemotePayload(process_handle, guid, data_size);
    return checkNotNullLastError(result);
}

/// Find the PE binary module in a process containing a known address.
/// Returns null if not found.
pub fn getContainingModule(address: ?*anyopaque) ?windows.HMODULE {
    return DetourGetContainingModule(address);
}

/// Return the entry point for a module (or the main exe if null).
/// Uses GetLastError on failure (returns null).
pub fn getEntryPoint(module_handle: ?windows.HMODULE) Error!*anyopaque {
    const result = DetourGetEntryPoint(module_handle);
    return checkNotNullLastError(result);
}

/// Return the load size of a module in bytes.
/// Uses GetLastError on failure (returns 0).
pub fn getModuleSize(module_handle: ?windows.HMODULE) Error!u32 {
    const size = DetourGetModuleSize(module_handle);
    if (size == 0) {
        try checkLastError();
        return Error.Other;
    }

    return size;
}

/// Return the size in bytes of all payloads within a module.
/// Uses GetLastError on failure (returns 0), specifically ERROR_INVALID_HANDLE.
pub fn getSizeOfPayloads(module_handle: ?windows.HMODULE) Error!u32 {
    const size = DetourGetSizeOfPayloads(module_handle);
    if (size == 0 and windows.GetLastError() == .INVALID_HANDLE) {
        return Error.InvalidHandle;
    }
    return size;
}

/// Check if the current process is a helper process used for cross-bitness detouring.
pub fn isHelperProcess() bool {
    return DetourIsHelperProcess() != windows.FALSE;
}

/// Restore the in-memory import table after a process was started with CreateProcessWithDll*.
/// Should be called in DllMain PROCESS_ATTACH.
pub fn restoreAfterWith() Error!void {
    const ok = DetourRestoreAfterWith();
    try checkBoolLastError(ok);
}

/// Set whether to ignore (and not detour) functions too small for detouring.
/// Returns the previous setting.
pub fn setIgnoreTooSmall(ignore: bool) bool {
    const previous = DetourSetIgnoreTooSmall(if (ignore) windows.TRUE else windows.FALSE);
    return previous != windows.FALSE;
}

/// Set whether Detours retains trampoline allocation regions after trampolines are released.
/// Returns the previous setting.
pub fn setRetainRegions(retain: bool) bool {
    const previous = DetourSetRetainRegions(if (retain) windows.TRUE else windows.FALSE);
    return previous != windows.FALSE;
}

/// Set the lower bound of the system memory region Detours avoids for trampolines.
/// Returns the previous bound.
pub fn setSystemRegionLowerBound(lower_bound: ?*anyopaque) ?*anyopaque {
    return DetourSetSystemRegionLowerBound(lower_bound);
}

/// Set the upper bound of the system memory region Detours avoids for trampolines.
/// Returns the previous bound.
pub fn setSystemRegionUpperBound(upper_bound: ?*anyopaque) ?*anyopaque {
    return DetourSetSystemRegionUpperBound(upper_bound);
}

/// Abort the current transaction.
pub fn transactionAbort() Error!void {
    const result = DetourTransactionAbort();
    try checkWin32Error(result);
}

/// Begin a new transaction.
pub fn transactionBegin() Error!void {
    const result = DetourTransactionBegin();
    try checkWin32Error(result);
}

/// Commit the current transaction.
pub fn transactionCommit() Error!void {
    const result = DetourTransactionCommit();
    try checkWin32Error(result);
}

/// Commit the current transaction, getting the failing pointer on error.
pub fn transactionCommitEx(failed_pointer_out: *?*?*anyopaque) Error!void {
    const result = DetourTransactionCommitEx(failed_pointer_out);
    try checkWin32Error(result);
}

/// Enlist a thread for update in the current transaction.
pub fn updateThread(thread_handle: windows.HANDLE) Error!void {
    const result = DetourUpdateThread(thread_handle);
    try checkWin32Error(result);
}

extern fn DetourAllocateRegionWithinJumpBounds(
    pbTarget: ?*const anyopaque,
    pcbAllocatedSize: *windows.DWORD,
) callconv(WINAPI) ?*anyopaque;

extern fn DetourAttach(
    ppPointer: *?*anyopaque,
    pDetour: ?*anyopaque,
) callconv(WINAPI) windows.LONG;

extern fn DetourAttachEx(
    ppPointer: *?*anyopaque,
    pDetour: ?*anyopaque,
    ppRealTrampoline: ?*?*anyopaque,
    ppRealTarget: ?*?*anyopaque,
    ppRealDetour: ?*?*anyopaque,
) callconv(WINAPI) windows.LONG;

pub const BinaryBywayCallback = *const fn (
    pContext: ?*anyopaque,
    pszFile: ?[*:0]const u8,
    ppszOutFile: *?[*:0]const u8,
) callconv(WINAPI) windows.BOOL;

pub const BinaryCommitCallback = *const fn (
    pContext: ?*anyopaque,
) callconv(WINAPI) windows.BOOL;

pub const BinaryFileCallback = *const fn (
    pContext: ?*anyopaque,
    pszOrigFile: [*:0]const u8,
    pszFile: [*:0]const u8,
    ppszOutFile: *?[*:0]const u8,
) callconv(WINAPI) windows.BOOL;

pub const BinarySymbolCallback = *const fn (
    pContext: ?*anyopaque,
    nOrigOrdinal: windows.ULONG,
    nOrdinal: windows.ULONG,
    pnOutOrdinal: *windows.ULONG,
    pszOrigSymbol: ?[*:0]const u8,
    pszSymbol: ?[*:0]const u8,
    ppszOutSymbol: *?[*:0]const u8,
) callconv(WINAPI) windows.BOOL;

pub const EnumerateExportCallback = *const fn (
    pContext: ?*anyopaque,
    nOrdinal: windows.ULONG,
    pszName: ?[*:0]const u8,
    pCode: ?*anyopaque,
) callconv(WINAPI) windows.BOOL;

pub const ImportFileCallback = *const fn (
    pContext: ?*anyopaque,
    hModule: ?windows.HMODULE,
    pszName: ?[*:0]const u8,
) callconv(WINAPI) windows.BOOL;

pub const ImportFuncCallback = *const fn (
    pContext: ?*anyopaque,
    nOrdinal: windows.ULONG,
    pszName: ?[*:0]const u8,
    pvFunc: ?*anyopaque,
) callconv(WINAPI) windows.BOOL;

pub const ImportFuncCallbackEx = *const fn (
    pContext: ?*anyopaque,
    nOrdinal: windows.ULONG,
    pszName: ?[*:0]const u8,
    pvFunc: ?*?*anyopaque,
) callconv(WINAPI) windows.BOOL;

pub const CreateProcessRoutineW = *const fn (
    lpApplicationName: ?[*:0]const u16,
    lpCommandLine: ?[*:0]u16,
    lpProcessAttributes: ?*windows.SECURITY_ATTRIBUTES,
    lpThreadAttributes: ?*windows.SECURITY_ATTRIBUTES,
    bInheritHandles: windows.BOOL,
    dwCreationFlags: windows.DWORD,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?[*:0]const u16,
    lpStartupInfo: *windows.STARTUPINFOW,
    lpProcessInformation: *windows.PROCESS_INFORMATION,
) callconv(WINAPI) windows.BOOL;

extern fn DetourBinaryClose(
    pBinary: *BinaryHandle,
) callconv(WINAPI) windows.BOOL;

extern fn DetourBinaryDeletePayload(
    pBinary: *BinaryHandle,
    rguid: *const windows.GUID,
) callconv(WINAPI) windows.BOOL;

extern fn DetourBinaryEditImports(
    pBinary: *BinaryHandle,
    pContext: ?*anyopaque,
    pfByway: ?BinaryBywayCallback,
    pfFile: ?BinaryFileCallback,
    pfSymbol: ?BinarySymbolCallback,
    pfFinal: ?BinaryCommitCallback,
) callconv(WINAPI) windows.BOOL;

extern fn DetourBinaryEnumeratePayloads(
    pBinary: *BinaryHandle,
    pGuid: ?*windows.GUID,
    pcbData: *windows.DWORD,
    pnIterator: *windows.DWORD,
) callconv(WINAPI) ?*anyopaque;

extern fn DetourBinaryFindPayload(
    pBinary: *BinaryHandle,
    rguid: *const windows.GUID,
    pcbData: *windows.DWORD,
) callconv(WINAPI) ?*anyopaque;

extern fn DetourBinaryOpen(
    hFile: windows.HANDLE,
) callconv(WINAPI) ?*BinaryHandle;

extern fn DetourBinaryPurgePayloads(
    pBinary: *BinaryHandle,
) callconv(WINAPI) windows.BOOL;

extern fn DetourBinaryResetImports(
    pBinary: *BinaryHandle,
) callconv(WINAPI) windows.BOOL;

extern fn DetourBinarySetPayload(
    pBinary: *BinaryHandle,
    rguid: *const windows.GUID,
    pData: ?*const anyopaque,
    cbData: windows.DWORD,
) callconv(WINAPI) ?*anyopaque;

extern fn DetourBinaryWrite(
    pBinary: *BinaryHandle,
    hFile: windows.HANDLE,
) callconv(WINAPI) windows.BOOL;

extern fn DetourCodeFromPointer(
    pPointer: ?*anyopaque,
    ppGlobals: ?*?*anyopaque,
) callconv(WINAPI) ?*anyopaque;

extern fn DetourCopyPayloadToProcess(
    hProcess: windows.HANDLE,
    rguid: *const windows.GUID,
    pvData: ?*const anyopaque,
    cbData: windows.DWORD,
) callconv(WINAPI) windows.BOOL;

extern fn DetourCopyPayloadToProcessEx(
    hProcess: windows.HANDLE,
    rguid: *const windows.GUID,
    pvData: ?*const anyopaque,
    cbData: windows.DWORD,
) callconv(WINAPI) ?*anyopaque;

extern fn DetourCreateProcessWithDllW(
    lpApplicationName: ?[*:0]const u16,
    lpCommandLine: ?[*:0]u16,
    lpProcessAttributes: ?*windows.SECURITY_ATTRIBUTES,
    lpThreadAttributes: ?*windows.SECURITY_ATTRIBUTES,
    bInheritHandles: windows.BOOL,
    dwCreationFlags: windows.DWORD,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?[*:0]const u16,
    lpStartupInfo: *windows.STARTUPINFOW,
    lpProcessInformation: *windows.PROCESS_INFORMATION,
    lpDllName: [*:0]const u8,
    pfCreateProcessW: ?CreateProcessRoutineW,
) callconv(WINAPI) windows.BOOL;

extern fn DetourCreateProcessWithDllExW(
    lpApplicationName: ?[*:0]const u16,
    lpCommandLine: ?[*:0]u16,
    lpProcessAttributes: ?*windows.SECURITY_ATTRIBUTES,
    lpThreadAttributes: ?*windows.SECURITY_ATTRIBUTES,
    bInheritHandles: windows.BOOL,
    dwCreationFlags: windows.DWORD,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?[*:0]const u16,
    lpStartupInfo: *windows.STARTUPINFOW,
    lpProcessInformation: *windows.PROCESS_INFORMATION,
    lpDllName: [*:0]const u8,
    pfCreateProcessW: ?CreateProcessRoutineW,
) callconv(WINAPI) windows.BOOL;

extern fn DetourCreateProcessWithDllsW(
    lpApplicationName: ?[*:0]const u16,
    lpCommandLine: ?[*:0]u16,
    lpProcessAttributes: ?*windows.SECURITY_ATTRIBUTES,
    lpThreadAttributes: ?*windows.SECURITY_ATTRIBUTES,
    bInheritHandles: windows.BOOL,
    dwCreationFlags: windows.DWORD,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?[*:0]const u16,
    lpStartupInfo: *windows.STARTUPINFOW,
    lpProcessInformation: *windows.PROCESS_INFORMATION,
    nDlls: windows.DWORD,
    rlpDlls: [*]const [*:0]const u8,
    pfCreateProcessW: ?CreateProcessRoutineW,
) callconv(WINAPI) windows.BOOL;

extern fn DetourDetach(
    ppPointer: *?*anyopaque,
    pDetour: ?*anyopaque,
) callconv(WINAPI) windows.LONG;

extern fn DetourEnumerateExports(
    hModule: ?windows.HMODULE,
    pContext: ?*anyopaque,
    pfExport: EnumerateExportCallback,
) callconv(WINAPI) windows.BOOL;

extern fn DetourEnumerateImports(
    hModule: ?windows.HMODULE,
    pContext: ?*anyopaque,
    pfImportFile: ?ImportFileCallback,
    pfImportFunc: ?ImportFuncCallback,
) callconv(WINAPI) windows.BOOL;

extern fn DetourEnumerateImportsEx(
    hModule: ?windows.HMODULE,
    pContext: ?*anyopaque,
    pfImportFile: ?ImportFileCallback,
    pfImportFunc: ?ImportFuncCallbackEx,
) callconv(WINAPI) windows.BOOL;

extern fn DetourEnumerateModules(
    hModuleLast: ?windows.HMODULE,
) callconv(WINAPI) ?windows.HMODULE;

extern fn DetourFindFunction(
    pszModule: [*:0]const u8,
    pszFunction: [*:0]const u8,
) callconv(WINAPI) ?*anyopaque;

extern fn DetourFindPayload(
    hModule: ?windows.HMODULE,
    rguid: *const windows.GUID,
    pcbData: ?*windows.DWORD,
) callconv(WINAPI) ?*anyopaque;

extern fn DetourFindPayloadEx(
    rguid: *const windows.GUID,
    pcbData: ?*windows.DWORD,
) callconv(WINAPI) ?*anyopaque;

extern fn DetourFindRemotePayload(
    hProcess: windows.HANDLE,
    rguid: *const windows.GUID,
    pcbData: ?*windows.DWORD,
) callconv(WINAPI) ?*anyopaque;

pub const FinishHelperProcessCallback = *const fn (
    hwnd: windows.HWND,
    hinst: windows.HINSTANCE,
    lpszCmdLine: [*:0]u8,
    nCmdShow: windows.INT,
) callconv(WINAPI) void;

pub extern fn DetourFinishHelperProcess(
    hwnd: windows.HWND,
    hinst: windows.HINSTANCE,
    lpszCmdLine: [*:0]u8,
    nCmdShow: windows.INT,
) callconv(WINAPI) void;

extern fn DetourGetContainingModule(pvAddr: ?*anyopaque) callconv(WINAPI) ?windows.HMODULE;
extern fn DetourGetEntryPoint(hModule: ?windows.HMODULE) callconv(WINAPI) ?*anyopaque;
extern fn DetourGetModuleSize(hModule: ?windows.HMODULE) callconv(WINAPI) windows.ULONG;
extern fn DetourGetSizeOfPayloads(hModule: ?windows.HMODULE) callconv(WINAPI) windows.DWORD;
extern fn DetourIsHelperProcess() callconv(WINAPI) windows.BOOL;
extern fn DetourRestoreAfterWith() callconv(WINAPI) windows.BOOL;
extern fn DetourSetIgnoreTooSmall(fIgnore: windows.BOOL) callconv(WINAPI) windows.BOOL;
extern fn DetourSetRetainRegions(fRetain: windows.BOOL) callconv(WINAPI) windows.BOOL;
extern fn DetourSetSystemRegionLowerBound(pSystemRegionLowerBound: ?*anyopaque) callconv(WINAPI) ?*anyopaque;
extern fn DetourSetSystemRegionUpperBound(pSystemRegionUpperBound: ?*anyopaque) callconv(WINAPI) ?*anyopaque;
extern fn DetourTransactionAbort() callconv(WINAPI) windows.LONG;
extern fn DetourTransactionBegin() callconv(WINAPI) windows.LONG;
extern fn DetourTransactionCommit() callconv(WINAPI) windows.LONG;
extern fn DetourTransactionCommitEx(pppFailedPointer: ?*?*?*anyopaque) callconv(WINAPI) windows.LONG;
extern fn DetourUpdateThread(hThread: windows.HANDLE) callconv(WINAPI) windows.LONG;

test "refAllDecls" {
    std.testing.refAllDecls(@This());
}
