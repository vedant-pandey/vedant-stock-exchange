const std = @import("std");
const log = std.log.scoped(.@"utils/socket");
const posix = std.posix;

const serverTypes = @import("../types.zig");
const serverConsts = @import("../constants.zig");

// Set socket to non-blocking mode
pub inline fn setNonBlocking(fd: i32) !void {
    const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
    _ = try posix.fcntl(fd, posix.F.SETFL, flags | 0x800);
}

pub inline fn initSocket() !posix.socket_t {
    const listenSocket = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch |err| {
        log.err("Error while initializing socket, err {}\n", .{err});
        return serverTypes.VSEError.SocketInitializationError;
    };

    log.debug("Socket created {}\n", .{listenSocket});

    // Enable reuse address
    const opt: u32 = 1;
    posix.setsockopt(listenSocket, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&opt)) catch |err| {
        log.err("Error while setting socket options REUSEADDR, err {}\n", .{err});
        return serverTypes.VSEError.SocketInitializationError;
    };

    // Enable TCP_NODELAY to disable Nagle's algorithm
    posix.setsockopt(listenSocket, posix.IPPROTO.TCP, posix.TCP.NODELAY, std.mem.asBytes(&opt)) catch |err| {
        log.warn("Error setting TCP_NODELAY: {}", .{err});
    };

    // Make listen socket non-blocking
    try setNonBlocking(listenSocket);
    return listenSocket;
}

pub inline fn bindSocket(listenSocket: posix.socket_t) !void {
    const serverAddrIn: posix.sockaddr.in = posix.sockaddr.in{
        .port = std.mem.nativeTo(u16, serverConsts.PORT, std.builtin.Endian.big),
        .addr = 0, // INADDR_ANY
    };

    posix.bind(
        listenSocket,
        @as(*const posix.sockaddr, @ptrCast(&serverAddrIn)),
        @sizeOf(posix.sockaddr.in),
    ) catch |err| {
        log.err("Socket bind failed with err {}\n", .{err});
        return serverTypes.VSEError.SocketBindError;
    };

    posix.listen(listenSocket, serverConsts.QUEUE_SIZE) catch |err| {
        log.err("Socket listen failed with err {}", .{err});
        return serverTypes.VSEError.SocketListenError;
    };
}
