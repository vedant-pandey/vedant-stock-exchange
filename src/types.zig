const std = @import("std");
const posix = std.posix;
const serverConsts = @import("constants.zig");

pub const ConnectionState = enum {
    NEW,
    CONNECTED,
    DISCONNECTED,
};

pub const SocketState = struct {
    clientAddr: u32 = 0,
    clientPort: u16 = 0,
    state: ConnectionState = ConnectionState.NEW,
    buffer: [serverConsts.READ_BUFFER_SIZE]u8 = undefined,
    last_activity: i64 = 0, // For timeout management
    pollFd: posix.pollfd = posix.pollfd{
        .fd = -1,
        .events = 0,
        .revents = 0,
    },
};

pub const ClientsMAL = std.MultiArrayList(SocketState);

pub const VSEError = error{
    ClientMultiArrayInitFailed,
    InvalidClientFd,
    SocketInitializationError,
    SocketBindError,
    SocketListenError,
    PosixPollFailed,
    NoSlotsAvailable,
};

