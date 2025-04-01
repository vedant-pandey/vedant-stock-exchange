const std = @import("std");
const posix = std.posix;
const serverConsts = @import("constants.zig");
const log = std.log.scoped(.types);

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
    InvalidRequest,
};

pub const VSE = struct {
    pub const Error = error{
        ClientMultiArrayInitFailed,
        InvalidClientFd,
        SocketInitializationError,
        SocketBindError,
        SocketListenError,
        PosixPollFailed,
        NoSlotsAvailable,
        InvalidRequest,
    };
    pub const SystemError = error{};
};

pub const Request = struct {
    pub const Validation = enum {
        SUCCESS,
        FAILED,
    };
    pub const Method = enum {
        GET,
        POST,
        PUT,
        DELETE,
        HEAD,
        null,

        pub inline fn getReqMethod(reqStr: []const u8) ?Request.Method {
            return std.meta.stringToEnum(Request.Method, reqStr);
        }

        pub inline fn performValidation(self: Method, pathAndParams: []const u8) Validation {
            // FIXME: handle path based validation
            const pathIter = std.mem.splitSequence(u8, pathAndParams, "?");
            _ = pathIter;

            switch (self) {
                .GET => {
                    log.debug("Received a get request", .{});
                },

                else => {
                    log.err("Unknown method encountered {}", .{self});
                    return Validation.FAILED;
                },
            }

            return Validation.SUCCESS;
        }
    };
};
