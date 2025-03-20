const std = @import("std");
const posix = std.posix;
const log = std.log.scoped(.main);

const QUEUE_SIZE = 10;
const READ_BUFFER_SIZE = 4 * 1024;
const MAX_CONNECTIONS = 1000;
const PORT = 3000;

const ConnectionState = enum {
    NEW,
    CONNECTED,
    DISCONNECTED,
};

const ClientState = struct {
    fd: i32 = -1,
    state: ConnectionState = ConnectionState.NEW,
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

    // Initialize all slots with default ClientState
    inline for (0..(MAX_CONNECTIONS)) |i| {
        ClientsMAL.insert(fba.allocator(), i, ClientState{}) catch |err| {
            log.err("error while initializing clients multi array list for index {} with len {}, err {}", .{ i, ClientsMAL.len, err });
            return VSESystemError.ClientMultiArrayInitFailed;
        };
    }
}

// Utility function to get human-readable IP address (kept for potential future use)
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

fn respondClient(slot: usize, bytes_read: usize) void {
    var responseBuffer: [READ_BUFFER_SIZE + 100]u8 = undefined; // Extra space for headers

    // Create a basic HTTP response
    const response = std.fmt.bufPrint(&responseBuffer, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
        bytes_read,
        ClientsMAL.items(.buffer)[slot][0..bytes_read],
    }) catch |err| {
        log.err("Error formatting HTTP response: {}", .{err});
        return;
    };
    _ = posix.write(ClientsMAL.items(.fd)[slot], response) catch |err| {
        log.err("Error writing response to client, err {}", .{err});
    };
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
        log.err("Error while setting socket options, err {}\n", .{err});
        return VSEConnectionError.SocketInitializationError;
    };
    log.debug("Socket options set successfully.\n", .{});

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
        posix.close(listenSocket);
        return VSEConnectionError.SocketBindError;
    };

    posix.listen(listenSocket, QUEUE_SIZE) catch |err| {
        log.err("Socket listen failed with err {}", .{err});
        posix.close(listenSocket);
        return VSEConnectionError.SocketListenError;
    };

    log.info("Server listening on port {}\n", .{PORT});

    // 1 extra for listen socket at index 0
    var pollFdArray: [MAX_CONNECTIONS + 1]posix.pollfd = undefined;

    while (true) {
        // Reset poll array for each iteration
        for (0..(MAX_CONNECTIONS + 1)) |i| {
            pollFdArray[i] = posix.pollfd{
                .fd = -1,
                .events = posix.POLL.IN,
                .revents = 0,
            };
        }

        // Set listen socket in poll array
        pollFdArray[0].fd = listenSocket;
        pollFdArray[0].events = posix.POLL.IN;

        // Add active client connections to poll array
        var pollCount: usize = 1; // Start at 1 because listen socket is at index 0
        for (ClientsMAL.items(.fd), ClientsMAL.items(.state)) |clientFd, state| {
            if (clientFd != -1 and state == ConnectionState.CONNECTED) {
                if (pollCount < pollFdArray.len) {
                    pollFdArray[pollCount].fd = clientFd;
                    pollFdArray[pollCount].events = posix.POLL.IN;
                    pollCount += 1;
                } else {
                    log.warn("Poll array full, can't monitor all connections", .{});
                    break;
                }
            }
        }

        // Wait for events (-1 for indefinite timeout)
        const readyCount = posix.poll(pollFdArray[0..pollCount], -1) catch |err| {
            log.err("Error while calling poll, err {}\n", .{err});
            return VSEConnectionError.PosixPollFailed;
        };

        if (readyCount <= 0) {
            log.debug("Poll returned {} events", .{readyCount});
            continue;
        }

        // Handle new connections on the listen socket
        if (pollFdArray[0].revents & posix.POLL.IN != 0) {
            var clientAddrIn: posix.sockaddr.in = undefined;
            var clientAddrLen: posix.socklen_t = @sizeOf(posix.sockaddr.in);

            const connectionFd = posix.accept(listenSocket, @as(*posix.sockaddr, @ptrCast(&clientAddrIn)), &clientAddrLen, 0) catch |err| {
                log.err("Error while accept syscall, err {}", .{err});
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

            const ipAddr = getIpAddr(clientAddrIn.addr);
            log.info("New connection from {}.{}.{}.{}:{} assigned to slot {}", .{ ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3], std.mem.bigToNative(u16, clientAddrIn.port), slot });
        }

        // Handle client data
        for (pollFdArray[1..pollCount]) |pollFd| {
            const fd = pollFd.fd;
            if (fd == -1 or pollFd.revents == 0) {
                continue;
            }

            // Find which client this is
            const slot = findSlotByFd(fd) catch |err| {
                log.err("Invalid fd received err {} for fd {}", .{ err, fd });
                // If we can't find this fd in our clients list, close it
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
                    // Handle specific read errors
                    switch (err) {
                        error.WouldBlock => continue, // Non-blocking socket would block
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

                log.info("Received {} bytes from client {}: {s}", .{ bytes_read, fd, ClientsMAL.items(.buffer)[slot][0..bytes_read] });

                respondClient(slot, bytes_read);
            }
        }
    }
}
