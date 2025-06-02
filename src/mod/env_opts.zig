const std = @import("std");

fn parseEnvValBool(val: []const u16) !bool {
    const true_str = std.unicode.utf8ToUtf16LeStringLiteral("true");
    const false_str = std.unicode.utf8ToUtf16LeStringLiteral("false");
    const one_str = std.unicode.utf8ToUtf16LeStringLiteral("1");
    const zero_str = std.unicode.utf8ToUtf16LeStringLiteral("0");

    if (std.mem.eql(u16, val, true_str)) {
        return true;
    }
    if (std.mem.eql(u16, val, one_str)) {
        return true;
    }
    if (std.mem.eql(u16, val, false_str)) {
        return false;
    }
    if (std.mem.eql(u16, val, zero_str)) {
        return false;
    }

    return error.InvalidValue;
}

fn boolValidValues() []const u8 {
    return "true, false, 1, 0";
}

fn getEnumParseFn(comptime EnumType: type) (fn ([]const u16) anyerror!EnumType) {
    return struct {
        fn parse(val_: []const u16) !EnumType {
            return parseEnvValEnum(EnumType, val_);
        }
    }.parse;
}

fn parseEnvValEnum(comptime EnumType: type, val: []const u16) !EnumType {
    inline for (std.meta.fields(EnumType)) |field| {
        const field_name_utf16 = std.unicode.utf8ToUtf16LeStringLiteral(field.name);
        if (std.mem.eql(u16, val, field_name_utf16)) {
            return @field(EnumType, field.name);
        }
    }

    return error.InvalidValue;
}

fn enumValidValues(comptime EnumType: type) []const u8 {
    comptime var valid_values: []const u8 = "";
    const fields = std.meta.fields(EnumType);
    const len = fields.len;
    inline for (fields, 0..) |field, i| {
        valid_values = valid_values ++ "`" ++ field.name ++ "`";
        if (i != len - 1) {
            valid_values = valid_values ++ ", ";
        }
    }
    return valid_values;
}

fn parseEnvValInt(comptime IntType: type, val: []const u16) !IntType {
    // Convert UTF-16 to UTF-8 for parsing
    var utf8_buf: [64]u8 = undefined;
    const utf8_len = std.unicode.utf16LeToUtf8(utf8_buf[0..], val) catch {
        return error.InvalidValue;
    };
    const utf8_str = utf8_buf[0..utf8_len];

    return std.fmt.parseInt(IntType, utf8_str, 0) catch error.InvalidValue;
}

fn intValidValues(comptime IntType: type) []const u8 {
    const min_val = std.math.minInt(IntType);
    const max_val = std.math.maxInt(IntType);
    return std.fmt.comptimePrint("{} .. {}", .{ min_val, max_val });
}

fn getIntParseFn(comptime IntType: type) (fn ([]const u16) anyerror!IntType) {
    return struct {
        fn parse(val_: []const u16) !IntType {
            return parseEnvValInt(IntType, val_);
        }
    }.parse;
}

fn optName(buf: []u8, name: []const u16) []const u8 {
    const name_len = std.unicode.utf16LeToUtf8(buf, name) catch {
        return "<invalid string encoding>";
    };

    return buf[0..name_len];
}

pub const ParseOpts = struct {
    const UnknownOptionHandler = enum {
        @"error", // Print to log.err and fail.
        warn, // Print to log.warn and succeed.
        ignore, // Ignore and succeed.
    };

    unknown_option_handler: UnknownOptionHandler = .ignore,
};

fn null_log(comptime format: []const u8, args: anytype) void {
    _ = format;
    _ = args;
}

pub fn parse(
    comptime log: anytype,
    comptime Opts: type,
    comptime parse_opts: ParseOpts,
    val: ?[]const u16,
) !Opts {
    var opts = Opts{};

    if (val == null) {
        return opts;
    }

    const comma = std.unicode.utf8ToUtf16LeStringLiteral(",");
    const equals = std.unicode.utf8ToUtf16LeStringLiteral("=");

    const unknown_log_fn = switch (parse_opts.unknown_option_handler) {
        .@"error" => log.err,
        .warn => log.warn,
        else => null_log,
    };

    var err_msg_buf: [256]u8 = undefined;
    var any_unknown = false;

    var opt_it = std.mem.splitSequence(u16, val.?, comma);
    while (opt_it.next()) |opt_str| {
        var kv_it = std.mem.splitSequence(u16, opt_str, equals);

        const k = kv_it.next();
        const v = kv_it.next();
        const end = kv_it.next();

        if (k == null) break;

        var parsed = false;

        inline for (std.meta.fields(Opts)) |field| {
            if (std.mem.eql(u16, std.unicode.utf8ToUtf16LeStringLiteral(field.name), k.?)) {
                const field_type_info = @typeInfo(field.type);
                const valid_values = switch (field_type_info) {
                    .bool => boolValidValues(),
                    .@"enum" => enumValidValues(field.type),
                    .int => intValidValues(field.type),
                    else => unreachable,
                };

                if (v == null) {
                    const opt_str_u8 = optName(&err_msg_buf, opt_str);
                    log.err(
                        "Missing value for option: `{s}` (expected `key=value` format, valid values: `{s}`)",
                        .{
                            opt_str_u8,
                            valid_values,
                        },
                    );
                    return error.MissingValue;
                }

                if (end != null) {
                    const opt_str_u8 = optName(&err_msg_buf, opt_str);
                    log.err(
                        "Invalid option: `{s}` (expected `key=value` format, valid values: `{s}`)",
                        .{
                            opt_str_u8,
                            valid_values,
                        },
                    );
                    return error.InvalidFormat;
                }

                const parse_fn = switch (field_type_info) {
                    .bool => parseEnvValBool,
                    .@"enum" => getEnumParseFn(field.type),
                    .int => getIntParseFn(field.type),
                    else => {
                        @compileError(
                            "Unsupported field type `" ++ @typeName(field.type) ++ "` for field `" ++ field.name ++ "`",
                        );
                    },
                };

                @field(opts, field.name) = parse_fn(v.?) catch |err| {
                    const value_u8 = optName(&err_msg_buf, v.?);

                    log.err(
                        "Failed to parse value `{s}` for option `{s}` with type `{s}`. Valid values: {s}. Error: {}",
                        .{
                            value_u8,
                            field.name,
                            @typeName(field.type),
                            valid_values,
                            err,
                        },
                    );
                    return err;
                };
                parsed = true;
                break;
            }
        }

        if (!parsed) {
            any_unknown = true;
            const opt_str_u8 = optName(&err_msg_buf, k.?);
            unknown_log_fn("Unknown option: `{s}`", .{opt_str_u8});
        }
    }

    if (any_unknown) {
        unknown_log_fn("Known options:", .{});
        inline for (std.meta.fields(Opts)) |field| {
            const field_type_info = @typeInfo(field.type);
            const valid_values = switch (field_type_info) {
                .bool => boolValidValues(),
                .@"enum" => enumValidValues(field.type),
                .int => intValidValues(field.type),
                else => {},
            };

            unknown_log_fn("  - `{s}` ({s})", .{ field.name, valid_values });
        }

        if (parse_opts.unknown_option_handler == .@"error") {
            return error.UnknownOption;
        }
    }

    return opts;
}

test "parse - basic functionality" {
    const testing = std.testing;

    const TestOpts = struct {
        debug: bool = false,
        mode: enum { dev, prod, testing } = .dev,
        @"verbose logging": bool = false,
    };

    const TestLog = struct {
        fn err(comptime format: []const u8, args: anytype) void {
            _ = format;
            _ = args;
        }
        fn warn(comptime format: []const u8, args: anytype) void {
            _ = format;
            _ = args;
        }
    };

    // Test null input
    {
        const opts = try parse(TestLog, TestOpts, .{}, null);
        try testing.expectEqual(false, opts.debug);
        try testing.expectEqual(@as(@TypeOf(opts.mode), .dev), opts.mode);
        try testing.expectEqual(false, opts.@"verbose logging");
    }

    // Test single boolean option
    {
        const opts = try parse(TestLog, TestOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("debug=true"));
        try testing.expectEqual(true, opts.debug);
        try testing.expectEqual(@as(@TypeOf(opts.mode), .dev), opts.mode);
    }

    // Test enum option with spaces in name
    {
        const opts = try parse(TestLog, TestOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("verbose logging=1"));
        try testing.expectEqual(true, opts.@"verbose logging");
    }

    // Test multiple options
    {
        const opts = try parse(TestLog, TestOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("debug=true,mode=prod,verbose logging=false"));
        try testing.expectEqual(true, opts.debug);
        try testing.expectEqual(@as(@TypeOf(opts.mode), .prod), opts.mode);
        try testing.expectEqual(false, opts.@"verbose logging");
    }
}

test "parse - error cases" {
    const testing = std.testing;

    const TestOpts = struct {
        debug: bool = false,
        mode: enum { dev, prod } = .dev,
    };

    const TestLog = struct {
        fn err(comptime format: []const u8, args: anytype) void {
            _ = format;
            _ = args;
        }
        fn warn(comptime format: []const u8, args: anytype) void {
            _ = format;
            _ = args;
        }
    };

    // Test missing value
    try testing.expectError(error.MissingValue, parse(TestLog, TestOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("debug")));

    // Test invalid format (multiple equals)
    try testing.expectError(error.InvalidFormat, parse(TestLog, TestOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("debug=true=extra")));

    // Test invalid boolean value
    try testing.expectError(error.InvalidValue, parse(TestLog, TestOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("debug=invalid")));

    // Test invalid enum value
    try testing.expectError(error.InvalidValue, parse(TestLog, TestOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("mode=invalid")));
}

test "parse - unknown option handling" {
    const testing = std.testing;

    const TestOpts = struct {
        debug: bool = false,
    };

    const TestLog = struct {
        fn err(comptime format: []const u8, args: anytype) void {
            _ = format;
            _ = args;
        }
        fn warn(comptime format: []const u8, args: anytype) void {
            _ = format;
            _ = args;
        }
    };

    // Test unknown option with error handler
    try testing.expectError(error.UnknownOption, parse(TestLog, TestOpts, .{ .unknown_option_handler = .@"error" }, std.unicode.utf8ToUtf16LeStringLiteral("unknown=value")));

    // Test unknown option with warn handler (should succeed)
    {
        const opts = try parse(TestLog, TestOpts, .{ .unknown_option_handler = .warn }, std.unicode.utf8ToUtf16LeStringLiteral("unknown=value,debug=true"));
        try testing.expectEqual(true, opts.debug);
    }

    // Test unknown option with ignore handler (should succeed)
    {
        const opts = try parse(TestLog, TestOpts, .{ .unknown_option_handler = .ignore }, std.unicode.utf8ToUtf16LeStringLiteral("unknown=value,debug=false"));
        try testing.expectEqual(false, opts.debug);
    }
}

test "parse - enum with spaces" {
    const testing = std.testing;

    const ComplexOpts = struct {
        @"log level": enum { @"very quiet", quiet, normal, verbose, @"very verbose" } = .normal,
        enabled: bool = true,
    };

    const TestLog = struct {
        fn err(comptime format: []const u8, args: anytype) void {
            _ = format;
            _ = args;
        }
        fn warn(comptime format: []const u8, args: anytype) void {
            _ = format;
            _ = args;
        }
    };

    // Test enum with spaces
    {
        const opts = try parse(TestLog, ComplexOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("log level=very quiet"));
        try testing.expectEqual(@as(@TypeOf(opts.@"log level"), .@"very quiet"), opts.@"log level");
    }

    {
        const opts = try parse(TestLog, ComplexOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("log level=very verbose,enabled=false"));
        try testing.expectEqual(@as(@TypeOf(opts.@"log level"), .@"very verbose"), opts.@"log level");
        try testing.expectEqual(false, opts.enabled);
    }
}

test "parse - integer support" {
    const testing = std.testing;

    const IntOpts = struct {
        port: u16 = 8080,
        timeout: i32 = -1,
        @"max connections": u32 = 100,
        offset: i8 = 0,
    };

    const TestLog = struct {
        fn err(comptime format: []const u8, args: anytype) void {
            _ = format;
            _ = args;
        }
        fn warn(comptime format: []const u8, args: anytype) void {
            _ = format;
            _ = args;
        }
    };

    // Test default values
    {
        const opts = try parse(TestLog, IntOpts, .{}, null);
        try testing.expectEqual(@as(u16, 8080), opts.port);
        try testing.expectEqual(@as(i32, -1), opts.timeout);
        try testing.expectEqual(@as(u32, 100), opts.@"max connections");
        try testing.expectEqual(@as(i8, 0), opts.offset);
    }

    // Test single integer option
    {
        const opts = try parse(TestLog, IntOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("port=3000"));
        try testing.expectEqual(@as(u16, 3000), opts.port);
        try testing.expectEqual(@as(i32, -1), opts.timeout);
    }

    // Test negative integer
    {
        const opts = try parse(TestLog, IntOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("timeout=-5000"));
        try testing.expectEqual(@as(i32, -5000), opts.timeout);
    }

    // Test multiple integer options
    {
        const opts = try parse(TestLog, IntOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("port=9000,max connections=500,offset=127"));
        try testing.expectEqual(@as(u16, 9000), opts.port);
        try testing.expectEqual(@as(u32, 500), opts.@"max connections");
        try testing.expectEqual(@as(i8, 127), opts.offset);
    }

    // Test zero values
    {
        const opts = try parse(TestLog, IntOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("port=0,timeout=0"));
        try testing.expectEqual(@as(u16, 0), opts.port);
        try testing.expectEqual(@as(i32, 0), opts.timeout);
    }
}

test "parse - integer error cases" {
    const testing = std.testing;

    const IntOpts = struct {
        port: u16 = 8080,
        count: i8 = 0,
    };

    const TestLog = struct {
        fn err(comptime format: []const u8, args: anytype) void {
            _ = format;
            _ = args;
        }
        fn warn(comptime format: []const u8, args: anytype) void {
            _ = format;
            _ = args;
        }
    };

    // Test invalid integer value (non-numeric)
    try testing.expectError(error.InvalidValue, parse(TestLog, IntOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("port=abc")));

    // Test integer overflow for u16
    try testing.expectError(error.InvalidValue, parse(TestLog, IntOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("port=70000")));

    // Test negative value for unsigned integer
    try testing.expectError(error.InvalidValue, parse(TestLog, IntOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("port=-1")));

    // Test integer overflow for i8
    try testing.expectError(error.InvalidValue, parse(TestLog, IntOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("count=200")));

    // Test integer underflow for i8
    try testing.expectError(error.InvalidValue, parse(TestLog, IntOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("count=-200")));

    // Test floating point number (should fail)
    try testing.expectError(error.InvalidValue, parse(TestLog, IntOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("port=80.5")));
}

test "parse - mixed types with integers" {
    const testing = std.testing;

    const MixedOpts = struct {
        debug: bool = false,
        port: u16 = 8080,
        mode: enum { dev, prod, testing } = .dev,
        @"max workers": i32 = 4,
        @"verbose logging": bool = false,
        priority: i8 = 0,
    };

    const TestLog = struct {
        fn err(comptime format: []const u8, args: anytype) void {
            _ = format;
            _ = args;
        }
        fn warn(comptime format: []const u8, args: anytype) void {
            _ = format;
            _ = args;
        }
    };

    // Test mixed types in a single parse call
    {
        const opts = try parse(TestLog, MixedOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("debug=true,port=3000,mode=prod,max workers=8,verbose logging=false,priority=-5"));
        try testing.expectEqual(true, opts.debug);
        try testing.expectEqual(@as(u16, 3000), opts.port);
        try testing.expectEqual(@as(@TypeOf(opts.mode), .prod), opts.mode);
        try testing.expectEqual(@as(i32, 8), opts.@"max workers");
        try testing.expectEqual(false, opts.@"verbose logging");
        try testing.expectEqual(@as(i8, -5), opts.priority);
    }

    // Test partial configuration with mixed types
    {
        const opts = try parse(TestLog, MixedOpts, .{}, std.unicode.utf8ToUtf16LeStringLiteral("port=9000,debug=1"));
        try testing.expectEqual(true, opts.debug);
        try testing.expectEqual(@as(u16, 9000), opts.port);
        try testing.expectEqual(@as(@TypeOf(opts.mode), .dev), opts.mode); // default value
        try testing.expectEqual(@as(i32, 4), opts.@"max workers"); // default value
    }
}
