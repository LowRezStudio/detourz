const std = @import("std");
const Bitfield = @import("internal").Bitfield;

const windows = std.os.windows;
pub const BOOL = windows.BOOL;
pub const BOOLEAN = windows.BOOLEAN;
pub const HINSTANCE = windows.HINSTANCE;
pub const DWORD = windows.DWORD;
pub const PVOID = windows.PVOID;
pub const ULONG = windows.ULONG;
pub const ULONG_PTR = windows.ULONG_PTR;
pub const WCHAR = windows.WCHAR;
pub const NTSTATUS = windows.NTSTATUS;
pub const ACCESS_MASK = windows.ACCESS_MASK;
pub const HANDLE = windows.HANDLE;

pub const Status = extern struct {
    value: Enum,

    const Self = @This();

    const Enum = NTSTATUS;

    pub fn init(value: Enum) Self {
        return Self{ .value = value };
    }

    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return formatEnum(Enum, self.value, fmt, options, writer);
    }
};

pub const NtCreateFileIoStatus = enum(ULONG_PTR) {
    FILE_SUPERSEDED = 0x00000000,
    FILE_OPENED = 0x00000001,
    FILE_CREATED = 0x00000002,
    FILE_OVERWRITTEN = 0x00000003,
    FILE_EXISTS = 0x00000004,
    FILE_DOES_NOT_EXIST = 0x00000005,
    _,

    pub const Int = @typeInfo(@This()).@"enum".tag_type;

    pub fn fromInt(value: Int) @This() {
        return @enumFromInt(value);
    }

    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return formatEnum(@This(), self, fmt, options, writer);
    }
};

pub const ObjectAttributeBits = enum(u32) {
    OBJ_PROTECT_CLOSE = 0x00000001,
    OBJ_INHERIT = 0x00000002,
    OBJ_AUDIT_OBJECT_CLOSE = 0x00000004,
    OBJ_NO_RIGHTS_UPGRADE = 0x00000008,
    OBJ_PERMANENT = 0x00000010,
    OBJ_EXCLUSIVE = 0x00000020,
    OBJ_CASE_INSENSITIVE = 0x00000040,
    OBJ_OPENIF = 0x00000080,
    OBJ_OPENLINK = 0x00000100,
    OBJ_KERNEL_HANDLE = 0x00000200,
    OBJ_FORCE_ACCESS_CHECK = 0x00000400,
    OBJ_IGNORE_IMPERSONATED_DEVICEMAP = 0x00000800,
    OBJ_DONT_REPARSE = 0x00001000,
    // OBJ_VALID_ATTRIBUTES = 0x00001FF2,
};

pub const ObjectAttributes = Bitfield(ObjectAttributeBits);

pub const AccessMaskBits = enum(u32) {
    GENERIC_READ = windows.GENERIC_READ,
    GENERIC_WRITE = windows.GENERIC_WRITE,
    GENERIC_EXECUTE = windows.GENERIC_EXECUTE,
    GENERIC_ALL = windows.GENERIC_ALL,
    DELETE = windows.DELETE,
    FILE_READ_DATA = windows.FILE_READ_DATA,
    FILE_READ_ATTRIBUTES = windows.FILE_READ_ATTRIBUTES,
    FILE_READ_EA = windows.FILE_READ_EA,
    READ_CONTROL = windows.READ_CONTROL,
    FILE_WRITE_DATA = windows.FILE_WRITE_DATA,
    FILE_WRITE_ATTRIBUTES = windows.FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_EA = windows.FILE_WRITE_EA,
    FILE_APPEND_DATA = windows.FILE_APPEND_DATA,
    WRITE_DAC = windows.WRITE_DAC,
    WRITE_OWNER = windows.WRITE_OWNER,
    SYNCHRONIZE = windows.SYNCHRONIZE,
    FILE_EXECUTE = windows.FILE_EXECUTE,
    // FILE_LIST_DIRECTORY = windows.FILE_LIST_DIRECTORY, // === FILE_READ_DATA
    // FILE_TRAVERSE = windows.FILE_TRAVERSE, // === FILE_EXECUTE
    _,
};

pub const AccessMask = Bitfield(AccessMaskBits);

pub const ShareAccessBits = enum(u32) {
    FILE_SHARE_READ = windows.FILE_SHARE_READ,
    FILE_SHARE_WRITE = windows.FILE_SHARE_WRITE,
    FILE_SHARE_DELETE = windows.FILE_SHARE_DELETE,
};

pub const ShareAccess = Bitfield(ShareAccessBits);

pub const CreationDisposition = enum(ULONG) {
    FILE_SUPERSEDE = 0x00000000,
    FILE_OPEN = 0x00000001,
    FILE_CREATE = 0x00000002,
    FILE_OPEN_IF = 0x00000003,
    FILE_OVERWRITE = 0x00000004,
    FILE_OVERWRITE_IF = 0x00000005,
    _,

    pub const Int = @typeInfo(@This()).@"enum".tag_type;

    pub fn fromInt(value: Int) @This() {
        return @enumFromInt(value);
    }

    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return formatEnum(@This(), self, fmt, options, writer);
    }
};

pub const FileAttributeBits = enum(u32) {
    FILE_ATTRIBUTE_READONLY = windows.FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_HIDDEN = windows.FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_SYSTEM = windows.FILE_ATTRIBUTE_SYSTEM,
    FILE_ATTRIBUTE_DIRECTORY = windows.FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_ARCHIVE = windows.FILE_ATTRIBUTE_ARCHIVE,
    FILE_ATTRIBUTE_DEVICE = windows.FILE_ATTRIBUTE_DEVICE,
    FILE_ATTRIBUTE_NORMAL = windows.FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_TEMPORARY = windows.FILE_ATTRIBUTE_TEMPORARY,
    FILE_ATTRIBUTE_SPARSE_FILE = windows.FILE_ATTRIBUTE_SPARSE_FILE,
    FILE_ATTRIBUTE_REPARSE_POINT = windows.FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_COMPRESSED = windows.FILE_ATTRIBUTE_COMPRESSED,
    FILE_ATTRIBUTE_OFFLINE = windows.FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED = windows.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
    FILE_ATTRIBUTE_ENCRYPTED = windows.FILE_ATTRIBUTE_ENCRYPTED,
    FILE_ATTRIBUTE_INTEGRITY_STREAM = windows.FILE_ATTRIBUTE_INTEGRITY_STREAM,
    FILE_ATTRIBUTE_VIRTUAL = windows.FILE_ATTRIBUTE_VIRTUAL,
    FILE_ATTRIBUTE_NO_SCRUB_DATA = windows.FILE_ATTRIBUTE_NO_SCRUB_DATA,
    // FILE_ATTRIBUTE_EA = 0x00040000, // === FILE_ATTRIBUTE_RECALL_ON_OPEN
    FILE_ATTRIBUTE_PINNED = 0x00080000,
    FILE_ATTRIBUTE_UNPINNED = 0x00100000,
    FILE_ATTRIBUTE_RECALL_ON_OPEN = windows.FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
};

pub const FileAttributes = Bitfield(FileAttributeBits);

pub const CreateOptionsBits = enum(u32) {
    FILE_APPEND_DATA = windows.FILE_APPEND_DATA,
    // FILE_SEQUENTIAL_ONLY = windows.FILE_SEQUENTIAL_ONLY, // === FILE_APPEND_DATA
    FILE_COMPLETE_IF_OPLOCKED = windows.FILE_COMPLETE_IF_OPLOCKED,
    FILE_CREATE = windows.FILE_CREATE,
    // FILE_WRITE_THROUGH = windows.FILE_WRITE_THROUGH, // === FILE_CREATE
    FILE_CREATE_TREE_CONNECTION = windows.FILE_CREATE_TREE_CONNECTION,
    FILE_DELETE_ON_CLOSE = windows.FILE_DELETE_ON_CLOSE,
    FILE_NO_EA_KNOWLEDGE = windows.FILE_NO_EA_KNOWLEDGE,
    FILE_NO_INTERMEDIATE_BUFFERING = windows.FILE_NO_INTERMEDIATE_BUFFERING,
    FILE_NON_DIRECTORY_FILE = windows.FILE_NON_DIRECTORY_FILE,
    FILE_OPEN = windows.FILE_OPEN,
    // FILE_DIRECTORY_FILE = windows.FILE_DIRECTORY_FILE, // === FILE_OPEN
    FILE_OPEN_BY_FILE_ID = windows.FILE_OPEN_BY_FILE_ID,
    FILE_OPEN_FOR_BACKUP_INTENT = windows.FILE_OPEN_FOR_BACKUP_INTENT,
    FILE_OPEN_IF = windows.FILE_OPEN_IF,
    FILE_OPEN_REPARSE_POINT = windows.FILE_OPEN_REPARSE_POINT,
    FILE_OPEN_REQUIRING_OPLOCK = 0x00010000, // windows.FILE_OPEN_REQUIRING_OPLOCK,
    FILE_RANDOM_ACCESS = windows.FILE_RANDOM_ACCESS,
    FILE_RESERVE_OPFILTER = windows.FILE_RESERVE_OPFILTER,
    // FILE_SYNCHRONOUS_IO = windows.FILE_SYNCHRONOUS_IO,
    FILE_SYNCHRONOUS_IO_ALERT = windows.FILE_SYNCHRONOUS_IO_ALERT,
    FILE_SYNCHRONOUS_IO_NONALERT = windows.FILE_SYNCHRONOUS_IO_NONALERT,
    _,
};

pub const CreateOptions = Bitfield(CreateOptionsBits);
pub const OpenOptions = CreateOptions;

pub const SECURITY_QUALITY_OF_SERVICE = extern struct {
    Length: DWORD,
    ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL,
    ContextTrackingMode: SECURITY_CONTEXT_TRACKING_MODE,
    EffectiveOnly: windows.BOOLEAN,

    const Self = @This();

    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        return writer.print("{{ Length = {}, ImpersonationLevel = {}, ContextTrackingMode = {}, EffectiveOnly = {} }}", .{
            self.Length,
            self.ImpersonationLevel,
            self.ContextTrackingMode,
            self.EffectiveOnly,
        });
    }
};

pub const SECURITY_DESCRIPTOR_CONTROL_BITS = enum(u16) {
    SE_OWNER_DEFAULTED = 0x0001,
    SE_GROUP_DEFAULTED = 0x0002,
    SE_DACL_PRESENT = 0x0004,
    SE_DACL_DEFAULTED = 0x0008,
    SE_SACL_PRESENT = 0x0010,
    SE_SACL_DEFAULTED = 0x0020,
    SE_DACL_AUTO_INHERIT_REQ = 0x0100,
    SE_SACL_AUTO_INHERIT_REQ = 0x0200,
    SE_DACL_AUTO_INHERITED = 0x0400,
    SE_SACL_AUTO_INHERITED = 0x0800,
    SE_DACL_PROTECTED = 0x1000,
    SE_SACL_PROTECTED = 0x2000,
    SE_RM_CONTROL_VALID = 0x4000,
    SE_SELF_RELATIVE = 0x8000,
};

pub const SECURITY_DESCRIPTOR_CONTROL = Bitfield(SECURITY_DESCRIPTOR_CONTROL_BITS);

pub const SECURITY_DESCRIPTOR = extern struct {
    Revision: u8,
    Sbz1: u8,
    Control: SECURITY_DESCRIPTOR_CONTROL,
    Owner: ?*anyopaque, // PSID
    Group: ?*anyopaque, // PSID
    Sacl: ?*anyopaque, // PACL
    Dacl: ?*anyopaque, // PACL

    const Self = @This();

    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        return writer.print("{{ Revision = {}, Sbz1 = {}, Control = {}, Owner = {*}, Group = {*}, Sacl = {*}, Dacl = {*} }}", .{
            self.Revision,
            self.Sbz1,
            self.Control,
            self.Owner,
            self.Group,
            self.Sacl,
            self.Dacl,
        });
    }
};

fn formatEnum(
    comptime T: type,
    self: T,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;

    const tag_name = std.enums.tagName(T, self) orelse {
        const size = std.fmt.comptimePrint("{d}", .{@sizeOf(T) * 2});
        return writer.print("0x{x:0" ++ size ++ "}", .{@intFromEnum(self)});
    };

    var parts = std.mem.splitBackwardsScalar(u8, tag_name, '.');
    const last = parts.next().?;

    return writer.writeAll(last);
}

pub const SECURITY_IMPERSONATION_LEVEL = enum(u32) {
    SecurityAnonymous,
    SecurityIdentification,
    SecurityImpersonation,
    SecurityDelegation,
    _,

    pub const Int = @typeInfo(@This()).@"enum".tag_type;

    pub fn fromInt(value: Int) @This() {
        return @enumFromInt(value);
    }

    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return formatEnum(@This(), self, fmt, options, writer);
    }
};

pub const SECURITY_CONTEXT_TRACKING_MODE = enum(u8) {
    SECURITY_STATIC_TRACKING = 0,
    SECURITY_DYNAMIC_TRACKING = 1,
    _,

    pub const Int = @typeInfo(@This()).@"enum".tag_type;

    pub fn fromInt(value: Int) @This() {
        return @enumFromInt(value);
    }

    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return formatEnum(@This(), self, fmt, options, writer);
    }
};

const FILE_INFORMATION_CLASS = enum(u32) {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation = 2,
    FileBothDirectoryInformation = 3,
    FileBasicInformation = 4,
    FileStandardInformation = 5,
    FileInternalInformation = 6,
    FileEaInformation = 7,
    FileAccessInformation = 8,
    FileNameInformation = 9,
    FileRenameInformation = 10,
    FileLinkInformation = 11,
    FileNamesInformation = 12,
    FileDispositionInformation = 13,
    FilePositionInformation = 14,
    FileFullEaInformation = 15,
    FileModeInformation = 16,
    FileAlignmentInformation = 17,
    FileAllInformation = 18,
    FileAllocationInformation = 19,
    FileEndOfFileInformation = 20,
    FileAlternateNameInformation = 21,
    FileStreamInformation = 22,
    FilePipeInformation = 23,
    FilePipeLocalInformation = 24,
    FilePipeRemoteInformation = 25,
    FileMailslotQueryInformation = 26,
    FileMailslotSetInformation = 27,
    FileCompressionInformation = 28,
    FileObjectIdInformation = 29,
    FileCompletionInformation = 30,
    FileMoveClusterInformation = 31,
    FileQuotaInformation = 32,
    FileReparsePointInformation = 33,
    FileNetworkOpenInformation = 34,
    FileAttributeTagInformation = 35,
    FileTrackingInformation = 36,
    FileIdBothDirectoryInformation = 37,
    FileIdFullDirectoryInformation = 38,
    FileValidDataLengthInformation = 39,
    FileShortNameInformation = 40,
    FileIoCompletionNotificationInformation = 41,
    FileIoStatusBlockRangeInformation = 42,
    FileIoPriorityHintInformation = 43,
    FileSfioReserveInformation = 44,
    FileSfioVolumeInformation = 45,
    FileHardLinkInformation = 46,
    FileProcessIdsUsingFileInformation = 47,
    FileNormalizedNameInformation = 48,
    FileNetworkPhysicalNameInformation = 49,
    FileIdGlobalTxDirectoryInformation = 50,
    FileIsRemoteDeviceInformation = 51,
    FileUnusedInformation = 52,
    FileNumaNodeInformation = 53,
    FileStandardLinkInformation = 54,
    FileRemoteProtocolInformation = 55,
    FileRenameInformationBypassAccessCheck = 56,
    FileLinkInformationBypassAccessCheck = 57,
    FileVolumeNameInformation = 58,
    FileIdInformation = 59,
    FileIdExtdDirectoryInformation = 60,
    FileReplaceCompletionInformation = 61,
    FileHardLinkFullIdInformation = 62,
    FileIdExtdBothDirectoryInformation = 63,
    FileDispositionInformationEx = 64,
    FileRenameInformationEx = 65,
    FileRenameInformationExBypassAccessCheck = 66,
    FileDesiredStorageClassInformation = 67,
    FileStatInformation = 68,
    FileMemoryPartitionInformation = 69,
    FileStatLxInformation = 70,
    FileCaseSensitiveInformation = 71,
    FileLinkInformationEx = 72,
    FileLinkInformationExBypassAccessCheck = 73,
    FileStorageReserveIdInformation = 74,
    FileCaseSensitiveInformationForceAccessCheck = 75,
    FileKnownFolderInformation = 76,
    FileMaximumInformation = 77,
};

pub const FILE_NAME_INFORMATION = extern struct {
    FileNameLength: ULONG,
    FileName: [1]WCHAR,

    const Self = @This();

    pub fn name(self: *const Self) []const u16 {
        const name_ptr: [*]const u16 = @ptrCast(&self.FileName[0]);
        const name_len = self.FileNameLength / @sizeOf(u16);
        return name_ptr[0..name_len];
    }
};

pub const OBJECT_ATTRIBUTES = extern struct {
    Length: ULONG,
    RootDirectory: ?HANDLE,
    ObjectName: *windows.UNICODE_STRING,
    Attributes: ObjectAttributes,
    SecurityDescriptor: ?*SECURITY_DESCRIPTOR,
    SecurityQualityOfService: ?*SECURITY_QUALITY_OF_SERVICE,
};

pub const IO_STATUS_BLOCK = extern struct {
    u: extern union {
        Status: Status,
        Pointer: ?*anyopaque,
    },
    Information: NtCreateFileIoStatus,

    const Self = @This();

    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        return writer.print("{{ Status = {}, Information = {} }}", .{
            self.u.Status,
            self.Information,
        });
    }
};

pub const IO_STATUS_BLOCK_ReadWrite = extern struct {
    u: extern union {
        Status: Status,
        Pointer: ?*anyopaque,
    },
    BytesTransferred: ULONG_PTR,

    const Self = @This();

    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        return writer.print("{{ Status = {}, BytesTransferred = {} }}", .{
            self.u.Status,
            self.BytesTransferred,
        });
    }
};

pub extern "ntdll" fn NtOpenFile(
    FileHandle: *HANDLE,
    DesiredAccess: AccessMask,
    ObjectAttributes: *OBJECT_ATTRIBUTES,
    IoStatusBlock: *IO_STATUS_BLOCK,
    ShareAccess: ShareAccess,
    OpenOptions: OpenOptions,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtCreateFile(
    FileHandle: *HANDLE,
    DesiredAccess: AccessMask,
    ObjectAttributes: *OBJECT_ATTRIBUTES,
    IoStatusBlock: *IO_STATUS_BLOCK,
    AllocationSize: ?*windows.LARGE_INTEGER,
    FileAttributes: FileAttributes,
    ShareAccess: ShareAccess,
    CreateDisposition: CreationDisposition,
    CreateOptions: CreateOptions,
    EaBuffer: ?*anyopaque,
    EaLength: ULONG,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtQueryInformationFile(
    FileHandle: HANDLE,
    IoStatusBlock: *IO_STATUS_BLOCK,
    FileInformation: *anyopaque,
    Length: ULONG,
    FileInformationClass: FILE_INFORMATION_CLASS,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtReadFile(
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?*anyopaque, // PIO_APC_ROUTINE
    ApcContext: ?*anyopaque,
    IoStatusBlock: *IO_STATUS_BLOCK_ReadWrite,
    Buffer: *anyopaque,
    Length: ULONG,
    ByteOffset: ?*windows.LARGE_INTEGER,
    Key: ?*ULONG,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtWriteFile(
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?*anyopaque, // PIO_APC_ROUTINE
    ApcContext: ?*anyopaque,
    IoStatusBlock: *IO_STATUS_BLOCK_ReadWrite,
    Buffer: *anyopaque,
    Length: ULONG,
    ByteOffset: ?*windows.LARGE_INTEGER,
    Key: ?*ULONG,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtDeviceIoControlFile(
    FileHandle: HANDLE,
    Event: ?HANDLE,
    ApcRoutine: ?*anyopaque, // PIO_APC_ROUTINE
    ApcContext: ?*anyopaque,
    IoStatusBlock: *IO_STATUS_BLOCK_ReadWrite,
    IoControlCode: ULONG,
    InputBuffer: ?*anyopaque,
    InputBufferLength: ULONG,
    OutputBuffer: ?*anyopaque,
    OutputBufferLength: ULONG,
) callconv(.winapi) NTSTATUS;

pub extern "ntdll" fn NtClose(
    Handle: HANDLE,
) callconv(.winapi) NTSTATUS;
