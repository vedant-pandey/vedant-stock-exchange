const std = @import("std");
const posix = std.posix;
const log = std.log.scoped(.main);

const QUEUE_SIZE = 10;
const READ_BUFFER_SIZE = 4 * 1024;
const MAX_CONNECTIONS = 256;

const ConnectionState = enum { STATE_NEW, STATE_CONNECTED, STATE_DISCONNECTED };

const ClientState = struct {
    fd: i32 = -1,
    state: ConnectionState = ConnectionState.STATE_NEW,
    buffer: [READ_BUFFER_SIZE]u8 = undefined,
};

var ClientsMAL = std.MultiArrayList(ClientState){};
var memoryBuffer: [MAX_CONNECTIONS * @sizeOf(ClientState)]u8 = undefined;

const VSESystemError = error{
    ClientMultiArrayInitFailed,
    InvalidClientFd,
};

const VSEConnectionError = error{
    SocketInitializationError,
    SocketBindError,
    SocketListenError,
    PosixPollFailed,
    NoSlotsAvailable,
};

fn findFreeSlot() VSEConnectionError!usize {
    for (ClientsMAL.items(.fd), 0..) |fd, i| {
        if (fd == -1) return i;
    }
    return VSEConnectionError.NoSlotsAvailable;
}

fn findSlotByFd(fd: i32) VSESystemError!usize {
    for (ClientsMAL.items(.fd), 0..) |clientfd, i| {
        if (clientfd == fd) {
            return i;
        }
    }

    return VSESystemError.InvalidClientFd;
}

fn initClientsMAL() VSESystemError!void {
    var fba = std.heap.FixedBufferAllocator.init(&memoryBuffer);

    log.debug(
        \\Initialized clients multi array list with size 
        \\{} bytes client state * {} Max connections = {} bytes, 
        \\storing in buffer of size {} bytes
    , .{
        @sizeOf(ClientState),
        MAX_CONNECTIONS,
        (@sizeOf(ClientState) * MAX_CONNECTIONS),
        memoryBuffer.len,
    });
    ClientsMAL.setCapacity(fba.allocator(), MAX_CONNECTIONS) catch |err| {
        log.err("Error while initializing client multi array list, err {}", .{err});
        return VSESystemError.ClientMultiArrayInitFailed;
    };

    inline for (0..(MAX_CONNECTIONS)) |i| {
        ClientsMAL.insert(fba.allocator(), i, ClientState{}) catch |err| {
            log.err("error while initializing clients multi array list for index {} with len {}, err {}", .{ i, ClientsMAL.len, err });
            return VSESystemError.ClientMultiArrayInitFailed;
        };
    }
}

fn getIpAddr(bigEndianAddr: u32) [4]u8 {
    const a: u8 = @truncate((bigEndianAddr >> 24) & 0xFF);
    const b: u8 = @truncate((bigEndianAddr >> 16) & 0xFF);
    const c: u8 = @truncate((bigEndianAddr >> 8) & 0xFF);
    const d: u8 = @truncate((bigEndianAddr >> 0) & 0xFF);
    return [4]u8{d, c, b, a};
}

pub fn main() !void {
    try initClientsMAL();
    log.debug("Initialized clients multi array list with size {} bytes", .{(@sizeOf(ClientState) * MAX_CONNECTIONS)});

    const listenSocket: posix.socket_t = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch |err| {
        log.err("Error while initializing socket, err {}\n", .{err});
        return VSEConnectionError.SocketInitializationError;
    };
    log.debug("Socket created {}\n", .{listenSocket});

    const opt: u32 = 1;
    posix.setsockopt(listenSocket, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&opt)) catch |err| {
        log.err("Error while setting cosket options, err {}\n", .{err});
        return VSEConnectionError.SocketInitializationError;
    };
    log.debug("Socket options set successfully.\n", .{});

    const serverAddrIn: posix.sockaddr.in = posix.sockaddr.in{
        .port = std.mem.nativeTo(u16, 3000, std.builtin.Endian.big),
        .addr = 0,
    };

    var clientAddrIn: posix.sockaddr.in = undefined;
    var clientAddrLen: u32 = @sizeOf(posix.sockaddr.in);

    posix.bind(
        listenSocket,
        @as(*const posix.sockaddr, @ptrCast(&serverAddrIn)),
        @sizeOf(posix.sockaddr.in),
    ) catch |err| {
        log.err("Socket bind failed with err {}\n", .{err});
        return VSEConnectionError.SocketBindError;
    };

    posix.listen(listenSocket, QUEUE_SIZE) catch |err| {
        log.err("Socket listen failed with err {}", .{err});
        return VSEConnectionError.SocketListenError;
    };

    // 1 extra to listen on bind socket for new connections
    var pollFdArray: [MAX_CONNECTIONS + 1]posix.pollfd = [_]posix.pollfd{posix.pollfd{
        .fd = -1,
        .events = posix.POLL.IN, // For negative fd value this is ignored
        .revents = 0,
    }} ** (MAX_CONNECTIONS + 1);

    pollFdArray[0].fd = listenSocket;
    pollFdArray[0].events = posix.POLL.IN;

    while (true) {
        var ii: u16 = 1;
        for (ClientsMAL.items(.fd)) |clientFd| {
            if (clientFd != -1) {
                log.debug("Found an fd lying around {}", .{clientFd});
                pollFdArray[ii].fd = clientFd;
                ii += 1;
            }
        }

        var readyEvents = posix.poll(&pollFdArray, -1) catch |err| {
            log.err("Error while calling poll, err {}\n", .{err});
            return VSEConnectionError.PosixPollFailed;
        };

        log.debug("Poll event!", .{});

        if (pollFdArray[0].revents & posix.POLL.IN != 0) {
            const connectionFd = posix.accept(listenSocket, @as(*posix.sockaddr, @ptrCast(&clientAddrIn)), &clientAddrLen, 0) catch |err| {
                log.err("Error while accept syscall, err {}", .{err});
                continue;
            };


            const slot = findFreeSlot() catch |err| {
                log.err("error no free slot available for the new connection, err {}", .{err});
                posix.close(connectionFd);
                continue;
            };

            ClientsMAL.items(.fd)[slot] = connectionFd;
            ClientsMAL.items(.state)[slot] = ConnectionState.STATE_CONNECTED;

            readyEvents -= 1;
        }

        for (pollFdArray[1..], 1..) |pollFd, pi| {
            if (readyEvents <= 0) break;
            readyEvents -= 1;

            const fd = pollFd.fd;
            const slot = findSlotByFd(fd) catch |err| {
                log.err("Invalid fd received err {} for fd {}", .{err, fd});
                pollFdArray[pi].fd = -1;
                // posix.close(fd);
                continue;
            };

            const bytes_read = posix.read(fd, &ClientsMAL.items(.buffer)[slot]) catch |err| {
                log.err("Error while reading client data, err {}\n", .{err});
                posix.close(fd);
                ClientsMAL.items(.fd)[slot] = -1;
                ClientsMAL.items(.state)[slot] = ConnectionState.STATE_DISCONNECTED;
                continue;
            };

            if (bytes_read == 0) {
                log.debug("No more data to read, closing connection fd {}", .{fd});
                posix.close(fd);
                ClientsMAL.items(.fd)[slot] = -1;
                ClientsMAL.items(.state)[slot] = ConnectionState.STATE_DISCONNECTED;
                continue;
            }

            log.info("Data received from client {} {s}", .{ ClientsMAL.items(.fd)[slot], ClientsMAL.items(.buffer)[slot] });
        }
    }
}
