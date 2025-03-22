const std = @import("std");
const log = std.log.scoped(.@"client-utils");
const posix = std.posix;

const serverUtils = @import("server.zig");
const serverTypes = @import("../types.zig");
const serverConsts = @import("../constants.zig");

pub fn initClientsMAL(clientsMAL: *serverTypes.ClientsMAL, memoryBuffer: []u8) serverTypes.VSEError!void {
    var fba = std.heap.FixedBufferAllocator.init(memoryBuffer);

    log.debug(
        \\Initialized clients multi array list with size 
        \\{} bytes client state * {} Max connections = {} bytes, 
        \\storing in buffer of size {} bytes
    ,
        .{
            @sizeOf(serverTypes.SocketState),
            serverConsts.MAX_SOCKETS,
            (@sizeOf(serverTypes.SocketState) * serverConsts.MAX_SOCKETS),
            memoryBuffer.len,
        },
    );
    clientsMAL.setCapacity(fba.allocator(), serverConsts.MAX_SOCKETS) catch |err| {
        log.err("Error while initializing client multi array list, err {}", .{err});
        return serverTypes.VSEError.ClientMultiArrayInitFailed;
    };

    // Initialize all slots with default ClientState
    for (0..(serverConsts.MAX_SOCKETS)) |i| {
        clientsMAL.insert(fba.allocator(), i, serverTypes.SocketState{}) catch |err| {
            log.err(
                \\error while initializing clients multi array list for index {} with len {}, err {}
            ,
                .{ i, clientsMAL.len, err },
            );
            return serverTypes.VSEError.ClientMultiArrayInitFailed;
        };
    }
}

pub fn disconnectClient(clientsMAL: *const serverTypes.ClientsMAL, slot: usize) void {
    serverUtils.logIpAddr(clientsMAL, "Disconnecting client ", slot);
    posix.close(clientsMAL.items(.pollFd)[slot].fd);
    clientsMAL.items(.pollFd)[slot].fd = ~clientsMAL.items(.pollFd)[slot].fd;
    clientsMAL.items(.pollFd)[slot].revents = 0;
    clientsMAL.items(.state)[slot] = serverTypes.ConnectionState.DISCONNECTED;
}

pub fn registerClient(
    clientsMAL: *serverTypes.ClientsMAL,
    slot: usize,
    connectionFd: posix.socket_t,
    clientAddrIn: posix.sockaddr.in,
) void {
    // Store the new connection
    clientsMAL.items(.pollFd)[slot].fd = connectionFd;
    clientsMAL.items(.pollFd)[slot].events = posix.POLL.IN;
    clientsMAL.items(.state)[slot] = serverTypes.ConnectionState.CONNECTED;
    clientsMAL.items(.last_activity)[slot] = std.time.milliTimestamp();
    clientsMAL.items(.clientAddr)[slot] = clientAddrIn.addr;
    clientsMAL.items(.clientPort)[slot] = clientAddrIn.port;

    serverUtils.logIpAddr(clientsMAL, "New connection established from", slot);
}

// Optimized to reduce string formatting overhead
pub fn respondClient(clientsMAL: *serverTypes.ClientsMAL, slot: usize, bytes_read: usize) void {
    const fd = clientsMAL.items(.pollFd)[slot].fd;

    // Pre-allocate a single buffer for headers and content
    var responseBuffer: [serverConsts.READ_BUFFER_SIZE + 256]u8 = undefined;

    // Format the Content-Length part
    var lenBuf: [16]u8 = undefined;
    const lenStr = std.fmt.bufPrint(&lenBuf, "{d}", .{bytes_read}) catch return;

    // Copy prefix
    var pos: usize = 0;
    @memcpy(responseBuffer[pos .. pos + serverConsts.HTTP_RESPONSE_PREFIX.len], serverConsts.HTTP_RESPONSE_PREFIX);
    pos += serverConsts.HTTP_RESPONSE_PREFIX.len;

    // Copy content length
    @memcpy(responseBuffer[pos .. pos + lenStr.len], lenStr);
    pos += lenStr.len;

    // Copy suffix
    @memcpy(responseBuffer[pos .. pos + serverConsts.HTTP_RESPONSE_SUFFIX.len], serverConsts.HTTP_RESPONSE_SUFFIX);
    pos += serverConsts.HTTP_RESPONSE_SUFFIX.len;

    // Copy message body
    @memcpy(responseBuffer[pos .. pos + bytes_read], clientsMAL.items(.buffer)[slot][0..bytes_read]);
    pos += bytes_read;

    // Use writev to send in one syscall (would be ideal)
    // But we'll use a single write instead for this implementation
    _ = posix.write(fd, responseBuffer[0..pos]) catch |err| {
        log.err("Error writing response to client, err {}", .{err});
    };

    // Update last activity time
    clientsMAL.items(.last_activity)[slot] = std.time.milliTimestamp();
}
