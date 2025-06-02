# detourz

`detourz` is Zig wrapper for [Microsoft Detours](https://github.com/microsoft/Detours), a library for intercepting function calls on Windows. For a full explanation of how it works, consult the [official wiki](https://github.com/microsoft/Detours/wiki).

In short, the typical usage pattern is to build your hooking code (using the Detours API) into a DLL, and then to run your target executable with that DLL injected into it, which Detours can also facilitate.

This project provides a few different things:

* A Zig module that wraps the Detours C API to make it slightly nicer to use from Zig.
* `detourz.exe`, a multipurpose command-line that tool exposes some of the functionality of Detours, most importantly:
    * Running an executable with injected DLLs (`detourz run`). This is equivalent to the `withdll.exe` sample in Detours.
    * Modifying an executable to inject DLLs permanently (`detourz inject`). This is equivalent to the `setdll.exe` sample in Detours.
* `detourz_nt_file.dll`, a DLL that hooks several functions from the Windows Nt* APIs related to files, and prints the results of the calls.
    * It also serves as an example of how to write your own hooks and create a DLL that you can then use with `detourz run`.
    * Hooked APIs: `NtCreateFile`, `NtOpenFile`, `NtReadFile`, `NtWriteFile`, `NtDeviceIoControlFile`, `NtClose`.

## Requirements

- Windows.
- Zig compiler (version 0.14.0)

## Building

```sh
zig build
```

## Usage

```
Usage: detourz [-h | --help] <command>

Utility for working with Microsoft Detours.

Usage:
  detourz <command> [options]

Example:
  detourz run my_dll.dll my_dll2.dll my_exe.exe -- --foo --bar

Commands:
  payloads <file>
  exports <file>
  imports <file>
  run <dll> <dll> ... <exe> [-- <exe_args>...]
  inject <dll> <exe>

Options:

  -h, --help Show this help and exit

Commands:

  payloads List detours payloads in a PE binary
  exports  List exports from a PE binary
  run      Run an executable with injected DLLs
  imports  List imports from a PE binary
  inject   Inject a DLL into an executable's import table
  reset    Remove all previously injected imports from an executable file
```

## Usage as a library

Inside your project:

```
zig fetch --save git+https://github.com/jhark/detourz.git
```

`build.zig`:

```zig
  const detourz_dep = b.dependency("detourz", .{
      .target = target,
      .optimize = optimize,
  });

  exe_mod.addImport("detourz", detourz_dep.module("detourz"));
```

## Demo

Application to trace, `my_cat.zig`:

```zig
const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const stdout = std.io.getStdOut();

    if (args.len <= 1) {
        std.log.err("Expected one or more file paths", .{});
    }

    for (args[1..]) |arg| {
        const file = std.fs.cwd().openFile(arg, .{ .mode = .read_only }) catch |err| {
            std.log.err("{s}: {}", .{ arg, err });
            std.process.exit(1);
        };
        _ = try file.copyRangeAll(0, stdout, 0, std.math.maxInt(u64));
    }
}
```

Run the application with `detourz_nt_file.dll` injected, which will hook and print basic Nt* file APIs.

```sh
zig-out/bin/detourz.exe run zig-out/bin/detourz_nt_file.dll my_cat.exe -- hello_world.txt
```

```
info(detourz_nt_file): NtCreateFile(parent = 96 ("\Users\Joe\dev\detourz"), path = "hello_world.txt", access = (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) => SUCCESS [io_status = FILE_OPENED, handle = 180]
info(detourz_nt_file): NtReadFile(handle = 180 ("\Users\Joe\dev\detourz\hello_world.txt"), length = 32768, offset = i64@a4d41f6ed0) => SUCCESS [bytes_transferred = 13: [Hello world.�]]
Hello world.
info(detourz_nt_file): NtWriteFile(handle = 12, length = 13, offset = i64@a4d41f6ec0) => SUCCESS [bytes_transferred = 13: [Hello world.�]]
info(detourz_nt_file): NtReadFile(handle = 180 ("\Users\Joe\dev\detourz\hello_world.txt"), length = 32768, offset = i64@a4d41f6ed0) => END_OF_FILE [bytes_transferred = 0: []]
```


Again, with more verbosity.

The DLL has some options that it reads from the `DETOURZ` environment variable.

 
```sh
zig build
DETOURZ="verbose=true" zig-out/bin/detourz.exe run zig-out/bin/detourz_nt_file.dll my_cat.exe -- hello_world.txt
```

Output

```
info(detourz_nt_file): NtCreateFile(
  FileHandle        => 192
  DesiredAccess     =  GENERIC_READ | SYNCHRONIZE
  ObjectAttributes  =  {
    ObjectName               =  "hello_world.txt",
    Attributes               =  NONE,
    Length                   =  48,
    RootDirectory            =  96 ("\Users\Joe\dev\detourz"),
    SecurityDescriptor       =  null,
    SecurityQualityOfService =  null,
  }
  IoStatusBlock     => { Status = SUCCESS, Information = FILE_OPENED }
  AllocationSize    =  null
  FileAttributes    =  FILE_ATTRIBUTE_NORMAL
  ShareAccess       =  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
  CreateDisposition =  FILE_OPEN
  CreateOptions     =  FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
  EaBuffer          =  null
  EaLength          =  0
) => SUCCESS
info(detourz_nt_file): NtReadFile(
  FileHandle    =  192 ("\Users\Joe\dev\detourz\hello_world.txt")
  Event         =  null
  ApcRoutine    =  null
  ApcContext    =  anyopaque@cb8fbf72a8
  IoStatusBlock => { Status = SUCCESS, BytesTransferred = 13 }
  Buffer        =  anyopaque@cb8fbf7468 => [Hello world.�]
  Length        =  32768
  ByteOffset    =  i64@cb8fbf7200
  Key           =  null
) => SUCCESS
Hello world.
info(detourz_nt_file): NtWriteFile(
  FileHandle    =  12
  Event         =  null
  ApcRoutine    =  null
  ApcContext    =  anyopaque@cb8fbf72a0
  IoStatusBlock => { Status = SUCCESS, BytesTransferred = 13 }
  Buffer        =  anyopaque@cb8fbf7468 => [Hello world.�]
  Length        =  13
  ByteOffset    =  i64@cb8fbf71f0
  Key           =  null
) => SUCCESS
info(detourz_nt_file): NtReadFile(
  FileHandle    =  192 ("\Users\Joe\dev\detourz\hello_world.txt")
  Event         =  null
  ApcRoutine    =  null
  ApcContext    =  anyopaque@cb8fbf72a8
  IoStatusBlock => { Status = END_OF_FILE, BytesTransferred = 0 }
  Buffer        =  anyopaque@cb8fbf7468 => []
  Length        =  32768
  ByteOffset    =  i64@cb8fbf7200
  Key           =  null
) => END_OF_FILE
```