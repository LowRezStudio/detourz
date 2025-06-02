const std = @import("std");

/// Provides custom formatting for bitfields.
///
/// Example:
///
/// ```
/// const Access = enum(u32) {
///     Read = 0x00000001,
///     Write = 0x00000002,
///     Execute = 0x00000004,
///     _, // Undocumented secret = 0x00000008,
/// };
/// const AccessBitfield = Bitfield(Access);
///
/// const access_bits: u32 = 0x01 | 0x02 | 0x08;
/// const access = AccessBitfield.init(access_bits);
/// std.debug.print("{}\n", .{access}); // "Read | Write | 0x00000008"
/// ```
pub fn Bitfield(comptime FlagEnum: type) type {
    comptime {
        if (@typeInfo(FlagEnum) != .@"enum") {
            @compileError("Bitfield requires an enum type parameter");
        }
    }

    const EnumInt = @typeInfo(FlagEnum).@"enum".tag_type;

    return extern struct {
        bits: EnumInt,

        const Self = @This();

        pub const ALL_KNOWN: EnumInt = blk: {
            var result: EnumInt = 0;
            for (@typeInfo(FlagEnum).@"enum".fields) |field| {
                result |= @intFromEnum(@field(FlagEnum, field.name));
            }
            break :blk result;
        };

        pub fn init(bits: EnumInt) Self {
            return .{ .bits = bits };
        }

        pub fn format(
            self: Self,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            _ = fmt;
            _ = options;

            if (self.bits == 0) {
                return writer.writeAll("NONE");
            }

            const known_bits = self.bits & ALL_KNOWN;
            const flag_count = @popCount(known_bits);

            if (flag_count == 0) {
                // Only unknown flags
                return writer.print("0x{x}", .{self.bits});
            }

            var flags_written: EnumInt = 0;

            // Write all known flags using @tagName
            inline for (@typeInfo(FlagEnum).@"enum".fields) |field| {
                const flag_value = @intFromEnum(@field(FlagEnum, field.name));
                if (self.bits & flag_value != 0) {
                    // Write separator if not the first flag
                    if (flags_written > 0) {
                        try writer.writeAll(" | ");
                    }

                    try writer.writeAll(@tagName(@field(FlagEnum, field.name)));
                    flags_written += 1;
                }
            }

            const unknown_bits = self.bits & ~ALL_KNOWN;
            if (unknown_bits != 0) {
                if (flags_written > 0) {
                    try writer.writeAll(" | ");
                }

                const width = @sizeOf(EnumInt) * 2;
                const width_str = std.fmt.comptimePrint("{d}", .{width});
                try writer.print("0x{x:0" ++ width_str ++ "}", .{unknown_bits});
            }
        }
    };
}

test "Bitfield" {
    const Access = enum(u32) {
        Read = 0x00000001,
        Write = 0x00000002,
        Execute = 0x00000004,
        _, // Undocumented secret = 0x00000008,
    };
    const AccessBitfield = Bitfield(Access);

    const access_bits: u32 = 0x01 | 0x02 | 0x08;
    const access = AccessBitfield.init(access_bits);
    try std.testing.expectFmt(
        "Read | Write | 0x00000008",
        "{}",
        .{access},
    );
}
