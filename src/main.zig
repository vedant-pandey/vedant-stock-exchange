const std = @import("std");
const posix = std.posix;
const log = std.log.scoped(.main);

const QUEUE_SIZE = 128; // Increased from 10
const READ_BUFFER_SIZE = 16 * 1024; // Increased from 4K
const MAX_SOCKETS = 1000 + 1; // One extra for listen socket
const PORT = 3000;
const POLL_TIMEOUT_MS = 100; // Add timeout instead of infinite wait
const IDLE_TIMEOUT_MS = 30 * 1000; // 30 seconds
const STATS_TIMEOUT_MS = 10 * 1000; // 10 seconds

// Pre-computed HTTP response headers
const HTTP_RESPONSE_PREFIX = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ";
const HTTP_RESPONSE_SUFFIX = "\r\nConnection: keep-alive\r\n\r\n";

pub const log_level = std.log.Level.err;

const ConnectionState = enum {
    NEW,
    CONNECTED,
    DISCONNECTED,
};

const SocketState = struct {
    clientAddr: u32 = 0,
    clientPort: u16 = 0,
    state: ConnectionState = ConnectionState.NEW,
    buffer: [READ_BUFFER_SIZE]u8 = undefined,
    last_activity: i64 = 0, // For timeout management
    pollFd: posix.pollfd = posix.pollfd{
        .fd = -1,
        .events = 0,
        .revents = 0,
    },
};

var ClientsMAL = std.MultiArrayList(SocketState){};
var memoryBuffer: [MAX_SOCKETS * @sizeOf(SocketState)]u8 = undefined;

const VSEError = error{
    ClientMultiArrayInitFailed,
    InvalidClientFd,
    SocketInitializationError,
    SocketBindError,
    SocketListenError,
    PosixPollFailed,
    NoSlotsAvailable,
};

fn findFreeSlot() VSEError!usize {
    // Use bitmap or free list for faster slot finding
    for (ClientsMAL.items(.pollFd), 0..) |pollFd, i| {
        if (pollFd.fd < 0) return i;
    }
    return VSEError.NoSlotsAvailable;
}

fn findSlotByFd(fd: i32) VSEError!usize {
    // Consider using a hashmap for O(1) lookup instead of O(n)
    for (ClientsMAL.items(.pollFd), 0..) |pollFd, i| {
        if (pollFd.fd == fd) {
            return i;
        }
    }

    return VSEError.InvalidClientFd;
}

fn initClientsMAL() VSEError!void {
    var fba = std.heap.FixedBufferAllocator.init(&memoryBuffer);

    log.debug(
        \\Initialized clients multi array list with size 
        \\{} bytes client state * {} Max connections = {} bytes, 
        \\storing in buffer of size {} bytes
    , .{
        @sizeOf(SocketState),
        MAX_SOCKETS,
        (@sizeOf(SocketState) * MAX_SOCKETS),
        memoryBuffer.len,
    });
    ClientsMAL.setCapacity(fba.allocator(), MAX_SOCKETS) catch |err| {
        log.err("Error while initializing client multi array list, err {}", .{err});
        return VSEError.ClientMultiArrayInitFailed;
    };

    // Initialize all slots with default ClientState
    for (0..(MAX_SOCKETS)) |i| {
        ClientsMAL.insert(fba.allocator(), i, SocketState{}) catch |err| {
            log.err(
                \\error while initializing clients multi array list for index {} with len {}, err {}
            , .{ i, ClientsMAL.len, err });
            return VSEError.ClientMultiArrayInitFailed;
        };
    }
}

fn logIpAddr(msg: []const u8, slot: usize) void {
    const bigEndianAddr = ClientsMAL.items(.clientAddr)[slot];
    const port = ClientsMAL.items(.clientPort)[slot];
    const a: u8 = @truncate((bigEndianAddr >> 24) & 0xFF);
    const b: u8 = @truncate((bigEndianAddr >> 16) & 0xFF);
    const c: u8 = @truncate((bigEndianAddr >> 8) & 0xFF);
    const d: u8 = @truncate((bigEndianAddr >> 0) & 0xFF);
    log.debug("{s} {}.{}.{}.{}:{}", .{
        msg,
        d,
        c,
        b,
        a,
        std.mem.bigToNative(u16, port),
    });
}

fn disconnectClient(slot: usize) void {
    logIpAddr("Disconnecting client ", slot);
    posix.close(ClientsMAL.items(.pollFd)[slot].fd);
    ClientsMAL.items(.pollFd)[slot].fd = ~ClientsMAL.items(.pollFd)[slot].fd;
    ClientsMAL.items(.pollFd)[slot].revents = 0;
    ClientsMAL.items(.state)[slot] = ConnectionState.DISCONNECTED;
}

fn registerClient(slot: usize, connectionFd: posix.socket_t, clientAddrIn: posix.sockaddr.in) void {
    // Store the new connection
    ClientsMAL.items(.pollFd)[slot].fd = connectionFd;
    ClientsMAL.items(.pollFd)[slot].events = posix.POLL.IN;
    ClientsMAL.items(.state)[slot] = ConnectionState.CONNECTED;
    ClientsMAL.items(.last_activity)[slot] = std.time.milliTimestamp();
    ClientsMAL.items(.clientAddr)[slot] = clientAddrIn.addr;
    ClientsMAL.items(.clientPort)[slot] = clientAddrIn.port;

    logIpAddr("New connection established from", slot);
}

// Optimized to reduce string formatting overhead
fn respondClient(slot: usize, bytes_read: usize) void {
    const fd = ClientsMAL.items(.pollFd)[slot].fd;

    // Pre-allocate a single buffer for headers and content
    var responseBuffer: [READ_BUFFER_SIZE + 256]u8 = undefined;

    // Format the Content-Length part
    var lenBuf: [16]u8 = undefined;
    const lenStr = std.fmt.bufPrint(&lenBuf, "{d}", .{bytes_read}) catch return;

    // Copy prefix
    var pos: usize = 0;
    @memcpy(responseBuffer[pos .. pos + HTTP_RESPONSE_PREFIX.len], HTTP_RESPONSE_PREFIX);
    pos += HTTP_RESPONSE_PREFIX.len;

    // Copy content length
    @memcpy(responseBuffer[pos .. pos + lenStr.len], lenStr);
    pos += lenStr.len;

    // Copy suffix
    @memcpy(responseBuffer[pos .. pos + HTTP_RESPONSE_SUFFIX.len], HTTP_RESPONSE_SUFFIX);
    pos += HTTP_RESPONSE_SUFFIX.len;

    // Copy message body
    @memcpy(responseBuffer[pos .. pos + bytes_read], ClientsMAL.items(.buffer)[slot][0..bytes_read]);
    pos += bytes_read;

    // Use writev to send in one syscall (would be ideal)
    // But we'll use a single write instead for this implementation
    _ = posix.write(fd, responseBuffer[0..pos]) catch |err| {
        log.err("Error writing response to client, err {}", .{err});
    };

    // Update last activity time
    ClientsMAL.items(.last_activity)[slot] = std.time.milliTimestamp();
}

// Set socket to non-blocking mode
fn setNonBlocking(fd: i32) !void {
    const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
    _ = try posix.fcntl(fd, posix.F.SETFL, flags | 0x800);
}

fn initSocket() !posix.socket_t {
    const listenSocket = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch |err| {
        log.err("Error while initializing socket, err {}\n", .{err});
        return VSEError.SocketInitializationError;
    };

    log.debug("Socket created {}\n", .{listenSocket});

    // Enable reuse address
    const opt: u32 = 1;
    posix.setsockopt(listenSocket, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&opt)) catch |err| {
        log.err("Error while setting socket options REUSEADDR, err {}\n", .{err});
        return VSEError.SocketInitializationError;
    };

    // Enable TCP_NODELAY to disable Nagle's algorithm
    posix.setsockopt(listenSocket, posix.IPPROTO.TCP, posix.TCP.NODELAY, std.mem.asBytes(&opt)) catch |err| {
        log.warn("Error setting TCP_NODELAY: {}", .{err});
    };

    // Make listen socket non-blocking
    try setNonBlocking(listenSocket);
    return listenSocket;
}

fn bindSocket(listenSocket: posix.socket_t) !void {
    const serverAddrIn: posix.sockaddr.in = posix.sockaddr.in{
        .port = std.mem.nativeTo(u16, PORT, std.builtin.Endian.big),
        .addr = 0, // INADDR_ANY
    };

    posix.bind(
        listenSocket,
        @as(*const posix.sockaddr, @ptrCast(&serverAddrIn)),
        @sizeOf(posix.sockaddr.in),
    ) catch |err| {
        log.err("Socket bind failed with err {}\n", .{err});
        return VSEError.SocketBindError;
    };

    posix.listen(listenSocket, QUEUE_SIZE) catch |err| {
        log.err("Socket listen failed with err {}", .{err});
        return VSEError.SocketListenError;
    };
}

fn cycleOfAcceptance(listenSocket: posix.socket_t) !u32 {
    var connectionsHandled: u32 = 0;
    var clientAddrIn: posix.sockaddr.in = undefined;
    var clientAddrLen: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    while (true) {
        const connectionFd = posix.accept(
            listenSocket,
            @as(*posix.sockaddr, @ptrCast(&clientAddrIn)),
            &clientAddrLen,
            0,
        ) catch |err| switch (err) {
            posix.AcceptError.WouldBlock => break,
            else => {
                log.err("Error while accept syscall, err {}", .{err});
                break;
            },
        };

        const slot = findFreeSlot() catch |err| {
            log.err("Error no free slot available for the new connection, err {}", .{err});
            posix.close(connectionFd);
            break;
        };

        log.debug("Found a slot at ind {}", .{slot});

        // Set new socket to non-blocking
        setNonBlocking(connectionFd) catch |err| {
            log.err("Failed to set client socket non-blocking: {}", .{err});
            posix.close(connectionFd);
            continue;
        };

        registerClient(slot, connectionFd, clientAddrIn);

        connectionsHandled += 1;
    }
    return connectionsHandled;
}

fn cycleOfServing(listenSocket: posix.socket_t) !void {
    var connectionsHandled: u32 = 0;
    var requestsHandled: u64 = 0;
    var lastStatsTime = std.time.milliTimestamp();

    ClientsMAL.items(.pollFd)[0].fd = listenSocket;
    ClientsMAL.items(.pollFd)[0].events = posix.POLL.IN;
    ClientsMAL.items(.last_activity)[0] = std.math.maxInt(i64);

    while (true) {
        const readyCount = posix.poll(ClientsMAL.items(.pollFd), POLL_TIMEOUT_MS) catch |err| {
            log.err("Error while calling poll, err {}\n", .{err});
            unreachable;
        };

        const currentTime = std.time.milliTimestamp();
        if (currentTime - lastStatsTime > STATS_TIMEOUT_MS) {
            log.info("Stats - Connections: {}, Requests: {}", .{ connectionsHandled, requestsHandled });
            const current_time = std.time.milliTimestamp();

            for (ClientsMAL.items(.pollFd), ClientsMAL.items(.last_activity), 0..) |*pollFd, last_activity, i| {
                if (pollFd.fd > 0 and (current_time - last_activity) > IDLE_TIMEOUT_MS) {
                    log.debug("Closing idle connection on fd {}", .{pollFd.fd});
                    disconnectClient(i);
                }
            }

            lastStatsTime = currentTime;
        }

        if (readyCount <= 0) {
            continue;
        }

        if (ClientsMAL.items(.pollFd)[0].revents & posix.POLL.IN != 0) {
            connectionsHandled += cycleOfAcceptance(listenSocket) catch {
                continue;
            };
        }

        for (ClientsMAL.items(.pollFd)[1..], 1..) |pollFd, i| {
            log.debug("pollFd {} at {}\n", .{ pollFd, i });
            const fd = pollFd.fd;
            if (fd < 0 or pollFd.revents == 0) {
                continue;
            }

            if (pollFd.revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL) != 0) {
                log.debug("Error or hangup on fd {}, closing connection", .{fd});
                disconnectClient(i);
                continue;
            }

            // Read data if available
            if (pollFd.revents & posix.POLL.IN != 0) {
                log.debug("received some data somewhere", .{});

                const bytes_read = posix.read(fd, &ClientsMAL.items(.buffer)[i]) catch |err| switch (err) {
                    posix.ReadError.WouldBlock => {
                        log.debug("would block received during posix read for client {}", .{i});
                        continue;
                    },
                    else => {
                        log.err("Error while reading client data, err {}\n", .{err});
                        disconnectClient(i);
                        continue;
                    },
                };

                if (bytes_read == 0) {
                    log.debug("Client disconnected, closing fd {}", .{fd});
                    disconnectClient(i);
                    continue;
                }

                // Update activity timestamp
                ClientsMAL.items(.last_activity)[i] = std.time.milliTimestamp();

                // Only log at debug level to reduce logging overhead
                log.debug("Received {} bytes from client {}", .{ bytes_read, fd });

                respondClient(i, bytes_read);
                requestsHandled += 1;
            }
        }
    }
}

pub fn main() VSEError!void {
    try initClientsMAL();
    log.debug("Initialized clients multi array list with size {} bytes", .{(@sizeOf(SocketState) * MAX_SOCKETS)});

    const listenSocket: posix.socket_t = initSocket() catch |err| {
        log.err("Error while initializing socket, err {}", .{err});
        return VSEError.SocketInitializationError;
    };
    defer posix.close(listenSocket);

    try bindSocket(listenSocket);
    log.info("Server started on port {}\n", .{PORT});

    try cycleOfServing(listenSocket);
}
