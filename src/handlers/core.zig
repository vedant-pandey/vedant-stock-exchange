const std = @import("std");
const log = std.log.scoped(.@"handler/core");
const posix = std.posix;

const liburing = @cImport(@cInclude("liburing.h"));

const serverUtils = @import("../utils/server.zig");
const clientUtils = @import("../utils/client.zig");
const socketUtils = @import("../utils/socket.zig");
const serverTypes = @import("../types.zig");
const serverConsts = @import("../constants.zig");

inline fn cycleOfAcceptance(clientsMAL: *serverTypes.ClientsMAL, listenSocket: posix.socket_t) !u32 {
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
            posix.AcceptError.WouldBlock => {
                break;
            },
            else => {
                log.err("Error while accept syscall, err {}", .{err});
                break;
            },
        };

        const slot = serverUtils.findFreeSlot(clientsMAL) catch |err| {
            log.err("Error no free slot available for the new connection, err {}", .{err});
            posix.close(connectionFd);
            break;
        };

        log.debug("Found a slot at ind {}", .{slot});

        // Set new socket to non-blocking
        socketUtils.setNonBlocking(connectionFd) catch |err| {
            log.err("Failed to set client socket non-blocking: {}", .{err});
            posix.close(connectionFd);
            continue;
        };

        clientUtils.registerClient(clientsMAL, slot, connectionFd, clientAddrIn);

        connectionsHandled += 1;
    }
    return connectionsHandled;
}

pub inline fn cycleOfServing(clientsMAL: *serverTypes.ClientsMAL, listenSocket: posix.socket_t) !void {
    var connectionsHandled: u32 = 0;
    var requestsHandled: u64 = 0;
    var lastStatsTime = std.time.milliTimestamp();

    clientsMAL.items(.pollFd)[0].fd = listenSocket;
    clientsMAL.items(.pollFd)[0].events = posix.POLL.IN;
    clientsMAL.items(.last_activity)[0] = std.math.maxInt(i64);

    while (true) {
        const readyCount = posix.poll(clientsMAL.items(.pollFd), serverConsts.POLL_TIMEOUT_MS) catch |err| {
            log.err("Error while calling poll, err {}\n", .{err});
            unreachable;
        };

        const currentTime = std.time.milliTimestamp();
        if (currentTime - lastStatsTime > serverConsts.STATS_TIMEOUT_MS) {
            log.info("Stats - Connections: {}, Requests: {}", .{ connectionsHandled, requestsHandled });
            const current_time = std.time.milliTimestamp();
            connectionsHandled = 0;
            requestsHandled = 0;

            for (clientsMAL.items(.pollFd), clientsMAL.items(.last_activity), 0..) |pollFd, last_activity, i| {
                if (pollFd.fd > 0 and (current_time - last_activity) > serverConsts.IDLE_TIMEOUT_MS) {
                    log.debug("Closing idle connection on fd {}", .{pollFd.fd});
                    clientUtils.disconnectClient(clientsMAL, i);
                }
            }

            lastStatsTime = currentTime;
        }

        if (readyCount <= 0) {
            continue;
        }

        if (clientsMAL.items(.pollFd)[0].revents & posix.POLL.IN != 0) {
            connectionsHandled += cycleOfAcceptance(clientsMAL, listenSocket) catch {
                continue;
            };
        }

        for (clientsMAL.items(.pollFd)[1..], 1..) |pollFd, i| {
            const fd = pollFd.fd;
            if (fd < 0 or pollFd.revents == 0) {
                continue;
            }

            if (pollFd.revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL) != 0) {
                log.debug("Error or hangup on fd {}, closing connection", .{fd});
                clientUtils.disconnectClient(clientsMAL, i);
                continue;
            }

            // Read data if available
            if (pollFd.revents & posix.POLL.IN != 0) {
                log.debug("received some data somewhere", .{});

                const bytes_read = posix.read(fd, &clientsMAL.items(.buffer)[i]) catch |err| switch (err) {
                    posix.ReadError.WouldBlock => {
                        log.debug("would block received during posix read for client {}", .{i});
                        continue;
                    },
                    else => {
                        log.err("Error while reading client data, err {}\n", .{err});
                        clientUtils.disconnectClient(clientsMAL, i);
                        continue;
                    },
                };

                if (bytes_read == 0) {
                    log.debug("Client disconnected, closing fd {}", .{fd});
                    clientUtils.disconnectClient(clientsMAL, i);
                    continue;
                }

                // Update activity timestamp
                clientsMAL.items(.last_activity)[i] = std.time.milliTimestamp();

                // Only log at debug level to reduce logging overhead
                log.debug("Received {} bytes from client {}", .{ bytes_read, fd });

                clientUtils.respondClient(clientsMAL, i, bytes_read) catch |err| {
                    log.err("Error while responding to client, err {}", .{err});
                };
                requestsHandled += 1;
            }
        }
    }
}
