const std = @import("std");
const detours = @import("detourz");
const Bitfield = @import("internal").Bitfield;
const env_opts = @import("internal").env_opts;

const nt = @import("nt.zig");

const windows = std.os.windows;

const BOOL = windows.BOOL;
const HINSTANCE = windows.HINSTANCE;
const DWORD = windows.DWORD;
const PVOID = windows.PVOID;

const VT_100_RESET = "\x1b[0m";
const VT_100_DIM = "\x1b[2m";

const log = std.log.scoped(.detourz_nt_file);

var g_pfnNtCreateFile: *const @TypeOf(nt.NtCreateFile) = nt.NtCreateFile;
var g_pfnNtOpenFile: *const @TypeOf(nt.NtOpenFile) = nt.NtOpenFile;
var g_pfnNtClose: *const @TypeOf(nt.NtClose) = nt.NtClose;
var g_pfnNtQueryInformationFile: *const @TypeOf(nt.NtQueryInformationFile) = nt.NtQueryInformationFile;
var g_pfnNtReadFile: *const @TypeOf(nt.NtReadFile) = nt.NtReadFile;
var g_pfnNtWriteFile: *const @TypeOf(nt.NtWriteFile) = nt.NtWriteFile;
var g_pfnNtDeviceIoControlFile: *const @TypeOf(nt.NtDeviceIoControlFile) = nt.NtDeviceIoControlFile;

var g_env_opts = EnvOpts{};

threadlocal var g_inside_hook: bool = false;

const LogDestination = enum {
    none,
    // debug, // TODO
    stderr,
    stdout,
};

const EnvOpts = struct {
    log_level: std.log.Level = std.log.default_level,
    log: LogDestination = .stderr,
    verbose: bool = false,
    lookup: bool = true,
    hook_close: bool = false,
    dim: bool = false,
};

const env_opts_parse_opts = env_opts.ParseOpts{
    .unknown_option_handler = .warn,
};

const env_opts_key = std.unicode.utf8ToUtf16LeStringLiteral("DETOURZ");

const HandleName = struct {
    handle: ?windows.HANDLE,
    name: []const u8,

    fn init(handle: ?windows.HANDLE) HandleName {
        return HandleName{
            .handle = handle,
            .name = "",
        };
    }

    pub fn format(
        self: HandleName,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        const h = @intFromPtr(self.handle);

        if (self.name.len > 0) {
            try std.fmt.format(writer, "{d} (\"{s}\")", .{ h, self.name });
        } else {
            try std.fmt.format(writer, "{d}", .{h});
        }
    }
};

fn makeHandleName(handle: ?windows.HANDLE, allocator: std.mem.Allocator) HandleName {
    if (handle == null) {
        return HandleName.init(handle);
    }

    if (!g_env_opts.lookup) {
        return HandleName.init(handle);
    }

    var io_status_block: nt.IO_STATUS_BLOCK = undefined;

    const FileNameInfoBuf = struct {
        file_name_info: nt.FILE_NAME_INFORMATION = undefined,
        buffer: [1024 - @sizeOf(nt.FILE_NAME_INFORMATION)]u8 = undefined,
    };
    const file_name_info_buf = allocator.create(FileNameInfoBuf) catch return HandleName.init(handle);
    defer allocator.destroy(file_name_info_buf);

    const status = g_pfnNtQueryInformationFile(
        handle.?,
        &io_status_block,
        @ptrCast(@alignCast(file_name_info_buf)),
        @truncate(@sizeOf(FileNameInfoBuf)),
        .FileNameInformation,
    );

    if (status != .SUCCESS) {
        return HandleName.init(handle);
    }

    const name_wtf16 = file_name_info_buf.file_name_info.name();
    return HandleName{
        .handle = handle,
        .name = std.unicode.wtf16LeToWtf8Alloc(allocator, name_wtf16) catch "",
    };
}

fn makeBufferPreview(
    out: []u8,
    buffer: ?*anyopaque,
    length: windows.ULONG,
    bytes_transferred: windows.ULONG_PTR,
) []const u8 {
    if (buffer == null) {
        return out[0..0];
    }

    const bytes_to_show = @min(out.len, @min(length, bytes_transferred));
    const buf_p: [*]const u8 = @ptrCast(buffer.?);
    const buf_bytes = buf_p[0..bytes_to_show];

    var write_pos: usize = 0;

    for (buf_bytes) |b| {
        out[write_pos] = if (std.ascii.isPrint(b)) b else '·';
        write_pos += 1;
    }

    return out[0..write_pos];
}

fn bufferPreviewSuffix(preview: []const u8, bytes_transferred: windows.ULONG_PTR) []const u8 {
    if (preview.len == 0) return "";
    if (preview.len < bytes_transferred) return " ..." else return "";
}

fn NtCreateFile_Hook(
    FileHandle: **anyopaque,
    DesiredAccess: nt.AccessMask,
    ObjectAttributes: *nt.OBJECT_ATTRIBUTES,
    IoStatusBlock: *nt.IO_STATUS_BLOCK,
    AllocationSize: ?*windows.LARGE_INTEGER,
    FileAttributes: nt.FileAttributes,
    ShareAccess: nt.ShareAccess,
    CreateDisposition: nt.CreationDisposition,
    CreateOptions: nt.CreateOptions,
    EaBuffer: ?*anyopaque,
    EaLength: windows.ULONG,
) callconv(.c) windows.NTSTATUS {
    const status = g_pfnNtCreateFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        AllocationSize,
        FileAttributes,
        ShareAccess,
        CreateDisposition,
        CreateOptions,
        EaBuffer,
        EaLength,
    );

    if (g_inside_hook) {
        return status;
    }
    g_inside_hook = true;
    defer g_inside_hook = false;

    var tmp_buf: [4096]u8 = undefined;
    var stack_allocator = std.heap.FixedBufferAllocator.init(tmp_buf[0..]);
    const tmp_allocator = stack_allocator.allocator();

    const attrs: *nt.OBJECT_ATTRIBUTES = @ptrCast(@alignCast(ObjectAttributes));
    const object_name = attrs.ObjectName.*;
    const object_name_len = object_name.Length / @sizeOf(@TypeOf(object_name.Buffer.?[0]));
    const name_wtf16 = object_name.Buffer.?[0..object_name_len];
    const name_wtf8 = std.unicode.wtf16LeToWtf8Alloc(tmp_allocator, name_wtf16) catch "?";

    const root_dir_name = makeHandleName(ObjectAttributes.RootDirectory, tmp_allocator);

    const fmt =
        \\NtCreateFile(
        \\  FileHandle        => {any}
        \\  DesiredAccess     =  {any}
        \\  ObjectAttributes  =  {{
        \\    ObjectName               =  "{s}",
        \\    Attributes               =  {any},
        \\    Length                   =  {any},
        \\    RootDirectory            =  {any},
        \\    SecurityDescriptor       =  {any},
        \\    SecurityQualityOfService =  {any},
        \\  }}
        \\  IoStatusBlock     => {any}
        \\  AllocationSize    =  {any}
        \\  FileAttributes    =  {any}
        \\  ShareAccess       =  {any}
        \\  CreateDisposition =  {any}
        \\  CreateOptions     =  {any}
        \\  EaBuffer          =  {any}
        \\  EaLength          =  {any}
        \\) => {any}
    ;

    log.info(
        fmt,
        .{
            @intFromPtr(FileHandle.*),
            DesiredAccess,

            // ObjectAttributes,
            name_wtf8,
            ObjectAttributes.Attributes,
            ObjectAttributes.Length,
            root_dir_name,
            ObjectAttributes.SecurityDescriptor,
            ObjectAttributes.SecurityQualityOfService,

            IoStatusBlock,
            AllocationSize,
            FileAttributes,
            ShareAccess,
            CreateDisposition,
            CreateOptions,
            EaBuffer,
            EaLength,

            nt.Status.init(status),
        },
    );

    return status;
}

fn NtCreateFile_Hook_Short(
    FileHandle: **anyopaque,
    DesiredAccess: nt.AccessMask,
    ObjectAttributes: *nt.OBJECT_ATTRIBUTES,
    IoStatusBlock: *nt.IO_STATUS_BLOCK,
    AllocationSize: ?*windows.LARGE_INTEGER,
    FileAttributes: nt.FileAttributes,
    ShareAccess: nt.ShareAccess,
    CreateDisposition: nt.CreationDisposition,
    CreateOptions: nt.CreateOptions,
    EaBuffer: ?*anyopaque,
    EaLength: windows.ULONG,
) callconv(.c) windows.NTSTATUS {
    const status = g_pfnNtCreateFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        AllocationSize,
        FileAttributes,
        ShareAccess,
        CreateDisposition,
        CreateOptions,
        EaBuffer,
        EaLength,
    );

    if (g_inside_hook) {
        return status;
    }
    g_inside_hook = true;
    defer g_inside_hook = false;

    var tmp_buf: [4096]u8 = undefined;
    var stack_allocator = std.heap.FixedBufferAllocator.init(tmp_buf[0..]);
    const tmp_allocator = stack_allocator.allocator();

    const attrs: *nt.OBJECT_ATTRIBUTES = @ptrCast(@alignCast(ObjectAttributes));
    const object_name = attrs.ObjectName.*;
    const object_name_len = object_name.Length / @sizeOf(@TypeOf(object_name.Buffer.?[0]));
    const name_wtf16 = object_name.Buffer.?[0..object_name_len];
    const name_wtf8 = std.unicode.wtf16LeToWtf8Alloc(tmp_allocator, name_wtf16) catch "?";

    const root_dir_name = makeHandleName(ObjectAttributes.RootDirectory, tmp_allocator);

    const fmt =
        \\NtCreateFile(parent = {any}, path = "{s}", access = ({any})) => {any} [io_status = {any}, handle = {d}]
    ;

    log.info(
        fmt,
        .{
            root_dir_name,
            name_wtf8,
            ShareAccess,
            nt.Status.init(status),
            IoStatusBlock.Information,
            @intFromPtr(FileHandle.*),
        },
    );

    return status;
}

fn NtOpenFile_Hook(
    FileHandle: *windows.HANDLE,
    DesiredAccess: nt.AccessMask,
    ObjectAttributes: *nt.OBJECT_ATTRIBUTES,
    IoStatusBlock: *nt.IO_STATUS_BLOCK,
    ShareAccess: nt.ShareAccess,
    OpenOptions: nt.OpenOptions,
) callconv(.c) windows.NTSTATUS {
    const status = g_pfnNtOpenFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        ShareAccess,
        OpenOptions,
    );

    if (g_inside_hook) {
        return status;
    }
    g_inside_hook = true;
    defer g_inside_hook = false;

    var tmp_buf: [4096]u8 = undefined;
    var stack_allocator = std.heap.FixedBufferAllocator.init(tmp_buf[0..]);
    const tmp_allocator = stack_allocator.allocator();

    const attrs: *nt.OBJECT_ATTRIBUTES = @ptrCast(@alignCast(ObjectAttributes));
    const object_name = attrs.ObjectName.*;
    const object_name_len = object_name.Length / @sizeOf(@TypeOf(object_name.Buffer.?[0]));
    const name_wtf16 = object_name.Buffer.?[0..object_name_len];
    const name_wtf8 = std.unicode.wtf16LeToWtf8Alloc(tmp_allocator, name_wtf16) catch "?";

    // Query root directory name if present and option is enabled
    const root_dir_name = makeHandleName(ObjectAttributes.RootDirectory, tmp_allocator);

    const fmt =
        \\NtOpenFile(
        \\  FileHandle        => {any}
        \\  DesiredAccess     =  {any}
        \\  ObjectAttributes  =  {{
        \\    ObjectName               =  "{s}",
        \\    Attributes               =  {any},
        \\    Length                   =  {any},
        \\    RootDirectory            =  {any},
        \\    SecurityDescriptor       =  {any},
        \\    SecurityQualityOfService =  {any},
        \\  }}
        \\  IoStatusBlock     => {any}
        \\  ShareAccess       =  {any}
        \\  OpenOptions       =  {any}
        \\) => {any}
    ;

    log.info(
        fmt,
        .{
            @intFromPtr(FileHandle.*),
            DesiredAccess,

            // ObjectAttributes,
            name_wtf8,
            ObjectAttributes.Attributes,
            ObjectAttributes.Length,
            root_dir_name,
            ObjectAttributes.SecurityDescriptor,
            ObjectAttributes.SecurityQualityOfService,

            IoStatusBlock,
            ShareAccess,
            OpenOptions,

            nt.Status.init(status),
        },
    );

    return status;
}

fn NtOpenFile_Hook_Short(
    FileHandle: **anyopaque,
    DesiredAccess: nt.AccessMask,
    ObjectAttributes: *nt.OBJECT_ATTRIBUTES,
    IoStatusBlock: *nt.IO_STATUS_BLOCK,
    ShareAccess: nt.ShareAccess,
    OpenOptions: nt.OpenOptions,
) callconv(.c) windows.NTSTATUS {
    const status = g_pfnNtOpenFile(
        FileHandle,
        DesiredAccess,
        ObjectAttributes,
        IoStatusBlock,
        ShareAccess,
        OpenOptions,
    );

    if (g_inside_hook) {
        return status;
    }
    g_inside_hook = true;
    defer g_inside_hook = false;

    var tmp_buf: [4096]u8 = undefined;
    var stack_allocator = std.heap.FixedBufferAllocator.init(tmp_buf[0..]);
    const tmp_allocator = stack_allocator.allocator();

    const attrs: *nt.OBJECT_ATTRIBUTES = @ptrCast(@alignCast(ObjectAttributes));
    const object_name = attrs.ObjectName.*;
    const object_name_len = object_name.Length / @sizeOf(@TypeOf(object_name.Buffer.?[0]));
    const name_wtf16 = object_name.Buffer.?[0..object_name_len];
    const name_wtf8 = std.unicode.wtf16LeToWtf8Alloc(tmp_allocator, name_wtf16) catch "?";

    const root_dir_name = makeHandleName(ObjectAttributes.RootDirectory, tmp_allocator);

    const fmt =
        \\NtOpenFile(parent = {any}, path = "{s}", access = ({any})) => {any} [io_status = {any}, handle = {d}]
    ;

    log.info(
        fmt,
        .{
            root_dir_name,
            name_wtf8,
            DesiredAccess,
            nt.Status.init(status),
            IoStatusBlock.Information,
            @intFromPtr(FileHandle.*),
        },
    );

    return status;
}

fn NtClose_Hook(
    Handle: windows.HANDLE,
) callconv(.c) windows.NTSTATUS {
    if (g_inside_hook) {
        const status = g_pfnNtClose(Handle);
        return status;
    }
    g_inside_hook = true;
    defer g_inside_hook = false;

    const status = g_pfnNtClose(Handle);

    const fmt =
        \\NtClose(handle = {d}) => {any}
    ;

    log.info(
        fmt,
        .{
            @intFromPtr(Handle),
            nt.Status.init(status),
        },
    );

    return status;
}

fn NtReadFile_Hook(
    FileHandle: windows.HANDLE,
    Event: ?windows.HANDLE,
    ApcRoutine: ?*anyopaque,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *nt.IO_STATUS_BLOCK_ReadWrite,
    Buffer: *anyopaque,
    Length: windows.ULONG,
    ByteOffset: ?*windows.LARGE_INTEGER,
    Key: ?*windows.ULONG,
) callconv(.c) windows.NTSTATUS {
    const status = g_pfnNtReadFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        Buffer,
        Length,
        ByteOffset,
        Key,
    );

    if (g_inside_hook) {
        return status;
    }
    g_inside_hook = true;
    defer g_inside_hook = false;

    var tmp_buf: [4096]u8 = undefined;
    var stack_allocator = std.heap.FixedBufferAllocator.init(tmp_buf[0..]);
    const tmp_allocator = stack_allocator.allocator();

    var preview_buf: [16]u8 = undefined;
    const buffer_preview = makeBufferPreview(&preview_buf, Buffer, Length, IoStatusBlock.BytesTransferred);

    const fmt =
        \\NtReadFile(
        \\  FileHandle    =  {any}
        \\  Event         =  {?}
        \\  ApcRoutine    =  {?}
        \\  ApcContext    =  {?}
        \\  IoStatusBlock => {any}
        \\  Buffer        =  {?} => [{s}{s}]
        \\  Length        =  {any}
        \\  ByteOffset    =  {?}
        \\  Key           =  {?}
        \\) => {any}
    ;

    log.info(
        fmt,
        .{
            makeHandleName(FileHandle, tmp_allocator),
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            Buffer,
            buffer_preview,
            bufferPreviewSuffix(buffer_preview, IoStatusBlock.BytesTransferred),
            Length,
            ByteOffset,
            Key,
            nt.Status.init(status),
        },
    );

    return status;
}

fn NtReadFile_Hook_Short(
    FileHandle: windows.HANDLE,
    Event: ?windows.HANDLE,
    ApcRoutine: ?*anyopaque,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *nt.IO_STATUS_BLOCK_ReadWrite,
    Buffer: *anyopaque,
    Length: windows.ULONG,
    ByteOffset: ?*windows.LARGE_INTEGER,
    Key: ?*windows.ULONG,
) callconv(.c) windows.NTSTATUS {
    const status = g_pfnNtReadFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        Buffer,
        Length,
        ByteOffset,
        Key,
    );

    if (g_inside_hook) {
        return status;
    }
    g_inside_hook = true;
    defer g_inside_hook = false;

    var tmp_buf: [4096]u8 = undefined;
    var stack_allocator = std.heap.FixedBufferAllocator.init(tmp_buf[0..]);
    const tmp_allocator = stack_allocator.allocator();

    var preview_buf: [16]u8 = undefined;
    const buffer_preview = makeBufferPreview(&preview_buf, Buffer, Length, IoStatusBlock.BytesTransferred);

    const fmt =
        \\NtReadFile(handle = {any}, length = {any}, offset = {?}) => {any} [bytes_transferred = {any}: [{s}{s}]]
    ;

    log.info(
        fmt,
        .{
            makeHandleName(FileHandle, tmp_allocator),
            Length,
            ByteOffset,
            nt.Status.init(status),
            IoStatusBlock.BytesTransferred,
            buffer_preview,
            bufferPreviewSuffix(buffer_preview, IoStatusBlock.BytesTransferred),
        },
    );

    return status;
}

fn NtWriteFile_Hook(
    FileHandle: windows.HANDLE,
    Event: ?windows.HANDLE,
    ApcRoutine: ?*anyopaque,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *nt.IO_STATUS_BLOCK_ReadWrite,
    Buffer: *anyopaque,
    Length: windows.ULONG,
    ByteOffset: ?*windows.LARGE_INTEGER,
    Key: ?*windows.ULONG,
) callconv(.c) windows.NTSTATUS {
    const status = g_pfnNtWriteFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        Buffer,
        Length,
        ByteOffset,
        Key,
    );

    if (g_inside_hook) {
        return status;
    }
    g_inside_hook = true;
    defer g_inside_hook = false;

    var tmp_buf: [4096]u8 = undefined;
    var stack_allocator = std.heap.FixedBufferAllocator.init(tmp_buf[0..]);
    const tmp_allocator = stack_allocator.allocator();

    var preview_buf: [16]u8 = undefined;
    const buffer_preview = makeBufferPreview(&preview_buf, Buffer, Length, IoStatusBlock.BytesTransferred);

    const fmt =
        \\NtWriteFile(
        \\  FileHandle    =  {any}
        \\  Event         =  {?}
        \\  ApcRoutine    =  {?}
        \\  ApcContext    =  {?}
        \\  IoStatusBlock => {any}
        \\  Buffer        =  {?} => [{s}{s}]
        \\  Length        =  {any}
        \\  ByteOffset    =  {?}
        \\  Key           =  {?}
        \\) => {any}
    ;

    log.info(
        fmt,
        .{
            makeHandleName(FileHandle, tmp_allocator),
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            Buffer,
            buffer_preview,
            bufferPreviewSuffix(buffer_preview, IoStatusBlock.BytesTransferred),
            Length,
            ByteOffset,
            Key,
            nt.Status.init(status),
        },
    );

    return status;
}

fn NtWriteFile_Hook_Short(
    FileHandle: windows.HANDLE,
    Event: ?windows.HANDLE,
    ApcRoutine: ?*anyopaque,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *nt.IO_STATUS_BLOCK_ReadWrite,
    Buffer: *anyopaque,
    Length: windows.ULONG,
    ByteOffset: ?*windows.LARGE_INTEGER,
    Key: ?*windows.ULONG,
) callconv(.c) windows.NTSTATUS {
    const status = g_pfnNtWriteFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        Buffer,
        Length,
        ByteOffset,
        Key,
    );

    if (g_inside_hook) {
        return status;
    }
    g_inside_hook = true;
    defer g_inside_hook = false;

    var tmp_buf: [4096]u8 = undefined;
    var stack_allocator = std.heap.FixedBufferAllocator.init(tmp_buf[0..]);
    const tmp_allocator = stack_allocator.allocator();

    var preview_buf: [16]u8 = undefined;
    const buffer_preview = makeBufferPreview(&preview_buf, Buffer, Length, IoStatusBlock.BytesTransferred);

    const fmt =
        \\NtWriteFile(handle = {any}, length = {any}, offset = {?}) => {any} [bytes_transferred = {any}: [{s}{s}]]
    ;

    log.info(
        fmt,
        .{
            makeHandleName(FileHandle, tmp_allocator),
            Length,
            ByteOffset,
            nt.Status.init(status),
            IoStatusBlock.BytesTransferred,
            buffer_preview,
            bufferPreviewSuffix(buffer_preview, IoStatusBlock.BytesTransferred),
        },
    );

    return status;
}

fn NtDeviceIoControlFile_Hook(
    FileHandle: windows.HANDLE,
    Event: ?windows.HANDLE,
    ApcRoutine: ?*anyopaque,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *nt.IO_STATUS_BLOCK_ReadWrite,
    IoControlCode: windows.ULONG,
    InputBuffer: ?*anyopaque,
    InputBufferLength: windows.ULONG,
    OutputBuffer: ?*anyopaque,
    OutputBufferLength: windows.ULONG,
) callconv(.c) windows.NTSTATUS {
    const status = g_pfnNtDeviceIoControlFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength,
    );

    if (g_inside_hook) {
        return status;
    }
    g_inside_hook = true;
    defer g_inside_hook = false;

    var tmp_buf: [4096]u8 = undefined;
    var stack_allocator = std.heap.FixedBufferAllocator.init(tmp_buf[0..]);
    const tmp_allocator = stack_allocator.allocator();

    var input_preview_buf: [16]u8 = undefined;
    var output_preview_buf: [16]u8 = undefined;

    const input_preview = makeBufferPreview(&input_preview_buf, InputBuffer, InputBufferLength, InputBufferLength);
    const output_preview = makeBufferPreview(&output_preview_buf, OutputBuffer, OutputBufferLength, OutputBufferLength);

    const fmt =
        \\NtDeviceIoControlFile(
        \\  FileHandle         =  {any}
        \\  Event              =  {?}
        \\  ApcRoutine         =  {?}
        \\  ApcContext         =  {?}
        \\  IoStatusBlock      => {any}
        \\  IoControlCode      =  0x{X}
        \\  InputBuffer        =  {?} = [{s}{s}]
        \\  InputBufferLength  =  {any}
        \\  OutputBuffer       =  {?} => [{s}{s}]
        \\  OutputBufferLength =  {any}
        \\) => {any}
    ;

    log.info(
        fmt,
        .{
            makeHandleName(FileHandle, tmp_allocator),
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            IoControlCode,
            InputBuffer,
            input_preview,
            bufferPreviewSuffix(input_preview, InputBufferLength),
            InputBufferLength,
            OutputBuffer,
            output_preview,
            bufferPreviewSuffix(output_preview, IoStatusBlock.BytesTransferred),
            OutputBufferLength,
            nt.Status.init(status),
        },
    );

    return status;
}

fn NtDeviceIoControlFile_Hook_Short(
    FileHandle: windows.HANDLE,
    Event: ?windows.HANDLE,
    ApcRoutine: ?*anyopaque,
    ApcContext: ?*anyopaque,
    IoStatusBlock: *nt.IO_STATUS_BLOCK_ReadWrite,
    IoControlCode: windows.ULONG,
    InputBuffer: ?*anyopaque,
    InputBufferLength: windows.ULONG,
    OutputBuffer: ?*anyopaque,
    OutputBufferLength: windows.ULONG,
) callconv(.c) windows.NTSTATUS {
    const status = g_pfnNtDeviceIoControlFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength,
    );

    if (g_inside_hook) {
        return status;
    }
    g_inside_hook = true;
    defer g_inside_hook = false;

    var tmp_buf: [4096]u8 = undefined;
    var stack_allocator = std.heap.FixedBufferAllocator.init(tmp_buf[0..]);
    const tmp_allocator = stack_allocator.allocator();

    var input_preview_buf: [16]u8 = undefined;
    var output_preview_buf: [16]u8 = undefined;

    const input_preview = if (InputBuffer) |buf|
        makeBufferPreview(&input_preview_buf, buf, InputBufferLength, InputBufferLength)
    else
        "";

    const output_preview = if (OutputBuffer) |buf|
        makeBufferPreview(&output_preview_buf, buf, OutputBufferLength, IoStatusBlock.BytesTransferred)
    else
        "";

    const fmt =
        \\NtDeviceIoControlFile(handle = {any}, ioctl = 0x{X}, in_len = {any}, out_len = {any}) => {any} [bytes_transferred = {any}: in=`{s}` out=`{s}`]
    ;

    log.info(
        fmt,
        .{
            makeHandleName(FileHandle, tmp_allocator),
            IoControlCode,
            InputBufferLength,
            OutputBufferLength,
            nt.Status.init(status),
            IoStatusBlock.BytesTransferred,
            input_preview,
            output_preview,
        },
    );

    return status;
}

const Reason = enum(c_int) {
    process_detach = 0,
    process_attach = 1,
    thread_attach = 2,
    thread_detach = 3,
    process_verifier = 4,
    _,
};

// Detected and called by Zig's standard library.
//
// Has to be called by the function exported as ordinal 1, which it will be if
// we don't export anything else.
pub fn DllMain(hModule: HINSTANCE, dwReason: DWORD, lpReserved: PVOID) callconv(.winapi) BOOL {
    _ = hModule;
    _ = lpReserved;
    const reason: Reason = @enumFromInt(dwReason);

    return dllMain(reason) catch |e| {
        const reason_str = std.enums.tagName(Reason, reason) orelse "<unknown>";
        log.err("DLL {s} failed ({s}): {any}", .{ reason_str, @src().file, e });
        return windows.FALSE;
    };
}

fn selectHook(comptime hook_verbose: anytype, comptime hook_short: anytype) *anyopaque {
    return if (g_env_opts.verbose) @ptrCast(@constCast(hook_verbose)) else @ptrCast(@constCast(hook_short));
}

fn dllMain(reason: Reason) !BOOL {
    if (detours.isHelperProcess()) {
        return windows.TRUE;
    }

    switch (reason) {
        .process_attach => {
            g_env_opts = env_opts.parse(
                log,
                EnvOpts,
                env_opts_parse_opts,
                std.process.getenvW(env_opts_key),
            ) catch |err| {
                log.err("Failed to parse env opts: {any}", .{err});
                return err;
            };

            detours.restoreAfterWith() catch |err| {
                switch (err) {
                    detours.Error.ModNotFound => {
                        // This will happen when the DLL hasn't been injected by
                        // detours.createProcessWithDlls.
                        //
                        // E.g.:
                        //
                        //   * by launching after using `detourz inject hooks.dll app.exe`.
                        //   * linking against the DLL normally.
                    },
                    else => {
                        log.err("restoreAfterWith: {any}", .{err});
                        return err;
                    },
                }
            };
            {
                try detours.transactionBegin();

                try detours.updateThread(windows.GetCurrentThread());

                try detours.attach(
                    @ptrCast(&g_pfnNtCreateFile),
                    selectHook(&NtCreateFile_Hook, &NtCreateFile_Hook_Short),
                );

                try detours.attach(
                    @ptrCast(&g_pfnNtOpenFile),
                    selectHook(&NtOpenFile_Hook, &NtOpenFile_Hook_Short),
                );

                try detours.attach(
                    @ptrCast(&g_pfnNtReadFile),
                    selectHook(&NtReadFile_Hook, &NtReadFile_Hook_Short),
                );

                try detours.attach(
                    @ptrCast(&g_pfnNtWriteFile),
                    selectHook(&NtWriteFile_Hook, &NtWriteFile_Hook_Short),
                );

                try detours.attach(
                    @ptrCast(&g_pfnNtDeviceIoControlFile),
                    selectHook(&NtDeviceIoControlFile_Hook, &NtDeviceIoControlFile_Hook_Short),
                );

                if (g_env_opts.hook_close) try detours.attach(
                    @ptrCast(&g_pfnNtClose),
                    @ptrCast(@constCast(&NtClose_Hook)),
                );

                try detours.transactionCommit();
            }
        },

        .process_detach => {
            detours.transactionBegin() catch |err| {
                log.err("detours.transactionBegin: {any}", .{err});
                return err;
            };
            detours.updateThread(windows.GetCurrentThread()) catch |err| {
                log.err("detours.updateThread: {any}", .{err});
                return err;
            };
            detours.detach(
                @ptrCast(&g_pfnNtCreateFile),
                selectHook(&NtCreateFile_Hook, &NtCreateFile_Hook_Short),
            ) catch |err| {
                log.err("detours.detach: {any}", .{err});
                return err;
            };
            detours.detach(
                @ptrCast(&g_pfnNtOpenFile),
                selectHook(&NtOpenFile_Hook, &NtOpenFile_Hook_Short),
            ) catch |err| {
                log.err("detours.detach: {any}", .{err});
                return err;
            };
            detours.detach(
                @ptrCast(&g_pfnNtReadFile),
                selectHook(&NtReadFile_Hook, &NtReadFile_Hook_Short),
            ) catch |err| {
                log.err("detours.detach: {any}", .{err});
                return err;
            };
            detours.detach(
                @ptrCast(&g_pfnNtWriteFile),
                selectHook(&NtWriteFile_Hook, &NtWriteFile_Hook_Short),
            ) catch |err| {
                log.err("detours.detach: {any}", .{err});
                return err;
            };
            detours.detach(
                @ptrCast(&g_pfnNtDeviceIoControlFile),
                selectHook(&NtDeviceIoControlFile_Hook, &NtDeviceIoControlFile_Hook_Short),
            ) catch |err| {
                log.err("detours.detach: {any}", .{err});
                return err;
            };
            if (g_env_opts.hook_close) detours.detach(
                @ptrCast(&g_pfnNtClose),
                @ptrCast(@constCast(&NtClose_Hook)),
            ) catch |err| {
                log.err("detours.detach: {any}", .{err});
                return err;
            };
            detours.transactionCommit() catch |err| {
                log.err("detours.transactionCommit: {any}", .{err});
                return err;
            };
        },

        else => {},
    }

    return windows.TRUE;
}

pub const std_options: std.Options = .{
    .logFn = logFn,
};

fn logFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (comptime !std.log.logEnabled(level, scope)) return;
    if (@intFromEnum(level) > @intFromEnum(g_env_opts.log_level)) return;
    if (g_env_opts.log == .none) return;

    const writer: std.fs.File.Writer = switch (g_env_opts.log) {
        .stderr => std.fs.File.stderr().writer(&.{}),
        .stdout => std.fs.File.stdout().writer(&.{}),
        // .debug => outputDebugStringAWriter.any(), // TODO
        else => return,
    };

    const level_txt = comptime level.asText();
    const prefix2 = if (scope == .default) ": " else "(" ++ @tagName(scope) ++ "): ";
    var buf_writer = writer.interface;

    nosuspend {
        if (g_env_opts.dim) {
            buf_writer.writeAll(VT_100_RESET ++ VT_100_DIM) catch return;
        }
        buf_writer.print(level_txt ++ prefix2 ++ format ++ "\n", args) catch return;
        if (g_env_opts.dim) {
            buf_writer.writeAll(VT_100_RESET) catch return;
        }
        buf_writer.flush() catch return;
    }
}

// TODO -- Not possible to implement properly yet.
// extern "kernel32" fn OutputDebugStringA(lpOutputString: [*:0]const u8) void;

// fn outputDebugStringA(_: void, bytes: []const u8) error{}!usize {
//     _ = bytes;
//     @panic("todo: OutputDebugStringA");
//     // OutputDebugStringA(bytes.ptr);
//     // return bytes.len;
// }

// const OutputDebugStringAWriter = std.io.GenericWriter(void, error{}, outputDebugStringA);
// const outputDebugStringAWriter: OutputDebugStringAWriter = .{ .context = {} };
