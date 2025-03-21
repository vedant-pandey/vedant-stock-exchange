const std = @import("std");
const posix = std.posix;
const log = std.log.scoped(.main);

const QUEUE_SIZE = 128; // Increased from 10
const READ_BUFFER_SIZE = 16 * 1024; // Increased from 4K
const MAX_SOCKETS = 1000 + 1; // One extra for listen socket
const PORT = 3000;
const POLL_TIMEOUT_MS = 100; // Add timeout instead of infinite wait

// Pre-computed HTTP response headers
const HTTP_RESPONSE_PREFIX = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ";
const HTTP_RESPONSE_SUFFIX = "\r\nConnection: keep-alive\r\n\r\n";

const ConnectionState = enum {
    NEW,
    CONNECTED,
    DISCONNECTED,
};

const SocketState = struct {
    fd: i32 = -1,
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
    for (ClientsMAL.items(.fd), 0..) |fd, i| {
        if (fd == -1) return i;
    }
    return VSEError.NoSlotsAvailable;
}

fn findSlotByFd(fd: i32) VSEError!usize {
    // Consider using a hashmap for O(1) lookup instead of O(n)
    for (ClientsMAL.items(.fd), 0..) |clientfd, i| {
        if (clientfd == fd) {
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
    inline for (0..(MAX_SOCKETS)) |i| {
        ClientsMAL.insert(fba.allocator(), i, SocketState{}) catch |err| {
            log.err(
                \\error while initializing clients multi array list for index {} with len {}, err {}
            ,
                .{
                    i,
                    ClientsMAL.len,
                    err,
                },
            );
            return VSEError.ClientMultiArrayInitFailed;
        };
    }
}

// Utility function to get human-readable IP address
fn getIpAddr(bigEndianAddr: u32) [4]u8 {
    const a: u8 = @truncate((bigEndianAddr >> 24) & 0xFF);
    const b: u8 = @truncate((bigEndianAddr >> 16) & 0xFF);
    const c: u8 = @truncate((bigEndianAddr >> 8) & 0xFF);
    const d: u8 = @truncate((bigEndianAddr >> 0) & 0xFF);
    return [4]u8{ d, c, b, a };
}

fn disconnectClient(slot: usize) void {
    posix.close(ClientsMAL.items(.fd)[slot]);
    ClientsMAL.items(.fd)[slot] = -1;
    ClientsMAL.items(.state)[slot] = ConnectionState.DISCONNECTED;
}

// Optimized to reduce string formatting overhead
fn respondClient(slot: usize, bytes_read: usize) void {
    const fd = ClientsMAL.items(.fd)[slot];

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
inline fn setNonBlocking(fd: i32) !void {
    const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
    _ = try posix.fcntl(fd, posix.F.SETFL, flags | 0x800);
}

// Clean up idle connections
inline fn cleanupIdleConnections() void {
    const current_time = std.time.milliTimestamp();
    const idle_timeout_ms = 30 * 1000; // 30 seconds

    for (ClientsMAL.items(.fd), ClientsMAL.items(.last_activity), 0..) |fd, last_activity, i| {
        if (fd != -1 and (current_time - last_activity) > idle_timeout_ms) {
            log.debug("Closing idle connection on fd {}", .{fd});
            disconnectClient(i);
        }
    }
}

inline fn initSocket() !posix.socket_t {
    const listenSocket: posix.socket_t = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch |err| {
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

inline fn bindSocket(listenSocket: posix.socket_t) !void {
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

pub fn main() VSEError!void {
    try initClientsMAL();
    log.debug("Initialized clients multi array list with size {} bytes", .{(@sizeOf(SocketState) * MAX_SOCKETS)});

    const listenSocket = initSocket() catch |err| {
        log.err("Error while initializing socket, err {}", .{err});
        return VSEError.SocketInitializationError;
    };
    defer posix.close(listenSocket);

    try bindSocket(listenSocket);
    log.info("Server listening on port {}\n", .{PORT});

    // 1 extra for listen socket at index 0

    // Monitoring variables
    var connections_handled: u64 = 0;
    var requests_handled: u64 = 0;
    var last_stats_time = std.time.milliTimestamp();

    while (true) {
        // Reset poll array for each iteration
        @memset(ClientsMAL.items(.pollFd), posix.pollfd{
            .fd = -1,
            .events = posix.POLL.IN,
            .revents = 0,
        });

        ClientsMAL.items(.pollFd)[0] = listenSocket;

        // Add active client connections to poll array
        var pollCount: usize = 1; // Start at 1 because listen socket is at index 0
        for (ClientsMAL.items(.fd), ClientsMAL.items(.state)) |clientFd, state| {
            if (clientFd != -1 and state == ConnectionState.CONNECTED) {
                if (pollCount < MAX_SOCKETS) {
                    ClientsMAL.items(.pollFd)[pollCount].fd = listenSocket;
                    pollCount += 1;
                } else {
                    log.warn("Poll array full, can't monitor all connections", .{});
                    break;
                }
            }
        }

        // Wait for events with timeout instead of infinite wait
        const readyCount = posix.poll(ClientsMAL.items(.pollFd)[0..pollCount], POLL_TIMEOUT_MS) catch |err| {
            log.err("Error while calling poll, err {}\n", .{err});
            return VSEError.PosixPollFailed;
        };

        // Periodically clean up idle connections and print stats
        const current_time = std.time.milliTimestamp();
        if (current_time - last_stats_time > 10000) { // Every 10 seconds
            log.info("Stats - Connections: {}, Requests: {}", .{ connections_handled, requests_handled });
            cleanupIdleConnections();
            last_stats_time = current_time;
        }

        if (readyCount <= 0) {
            continue;
        }

        // Handle new connections on the listen socket
        if (ClientsMAL.items(.pollFd)[0].revents & posix.POLL.IN != 0) {
            var clientAddrIn: posix.sockaddr.in = undefined;
            var clientAddrLen: posix.socklen_t = @sizeOf(posix.sockaddr.in);

            // Accept as many connections as possible in one go
            while (true) {
                const connectionFd = posix.accept(
                    listenSocket,
                    @as(*posix.sockaddr, @ptrCast(&clientAddrIn)),
                    &clientAddrLen,
                    0,
                ) catch |err| {
                    if (err == error.WouldBlock) {
                        // No more connections to accept right now
                        break;
                    }
                    log.err("Error while accept syscall, err {}", .{err});
                    break;
                };

                // Set new socket to non-blocking
                setNonBlocking(connectionFd) catch |err| {
                    log.err("Failed to set client socket non-blocking: {}", .{err});
                    posix.close(connectionFd);
                    continue;
                };

                const slot = findFreeSlot() catch |err| {
                    log.err("Error no free slot available for the new connection, err {}", .{err});
                    posix.close(connectionFd);
                    continue;
                };

                // Store the new connection
                ClientsMAL.items(.fd)[slot] = connectionFd;
                ClientsMAL.items(.state)[slot] = ConnectionState.CONNECTED;
                ClientsMAL.items(.last_activity)[slot] = std.time.milliTimestamp();

                const ipAddr = getIpAddr(clientAddrIn.addr);
                log.debug("New connection from {}.{}.{}.{}:{} assigned to slot {}", .{ ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3], std.mem.bigToNative(u16, clientAddrIn.port), slot });

                connections_handled += 1;
            }
        }

        // Handle client data - batch process to reduce loop overhead
        for (ClientsMAL.items(.pollFd)[1..pollCount]) |pollFd| {
            const fd = pollFd.fd;
            if (fd == -1 or pollFd.revents == 0) {
                continue;
            }

            // Find which client this is
            const slot = findSlotByFd(fd) catch |err| {
                log.err("Invalid fd received err {} for fd {}", .{ err, fd });
                posix.close(fd);
                continue;
            };

            // Check for error or hangup conditions
            if (pollFd.revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL) != 0) {
                log.debug("Error or hangup on fd {}, closing connection", .{fd});
                disconnectClient(slot);
                continue;
            }

            // Read data if available
            if (pollFd.revents & posix.POLL.IN != 0) {
                const bytes_read = posix.read(fd, &ClientsMAL.items(.buffer)[slot]) catch |err| {
                    switch (err) {
                        error.WouldBlock => continue,
                        else => {
                            log.err("Error while reading client data, err {}\n", .{err});
                            disconnectClient(slot);
                            continue;
                        },
                    }
                };

                if (bytes_read == 0) {
                    log.debug("Client disconnected, closing fd {}", .{fd});
                    disconnectClient(slot);
                    continue;
                }

                // Update activity timestamp
                ClientsMAL.items(.last_activity)[slot] = std.time.milliTimestamp();

                // Only log at debug level to reduce logging overhead
                log.debug("Received {} bytes from client {}", .{ bytes_read, fd });

                respondClient(slot, bytes_read);
                requests_handled += 1;
            }
        }
    }
}
