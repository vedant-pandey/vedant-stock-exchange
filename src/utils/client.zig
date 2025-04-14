const std = @import("std");
const log = std.log.scoped(.@"utils/clients");
const posix = std.posix;

const serverUtils = @import("server.zig");
const serverTypes = @import("../types.zig");
const serverConsts = @import("../constants.zig");

const Request = @import("../types.zig").Request;
const VSE = @import("../types.zig").VSE;

pub inline fn initClientsMAL(clientsMAL: *serverTypes.ClientsMAL, memoryBuffer: []u8) VSE.Error!void {
    var fba = std.heap.FixedBufferAllocator.init(memoryBuffer);
    clientsMAL.setCapacity(fba.allocator(), serverConsts.MAX_SOCKETS) catch |err| {
        log.err("Error while initializing client multi array list, err {}", .{err});
        return VSE.Error.ClientMultiArrayInitFailed;
    };

    // Initialize all slots with default ClientState
    for (0..(serverConsts.MAX_SOCKETS)) |i| {
        clientsMAL.insert(fba.allocator(), i, serverTypes.SocketState{}) catch |err| {
            log.err(
                \\error while initializing clients multi array list for index {} with len {}, err {}
            ,
                .{ i, clientsMAL.len, err },
            );
            return VSE.Error.ClientMultiArrayInitFailed;
        };
    }
}

pub inline fn disconnectClient(clientsMAL: *const serverTypes.ClientsMAL, slot: usize) void {
    serverUtils.logIpAddr(clientsMAL, "Disconnecting client ", slot);
    posix.close(clientsMAL.items(.pollFd)[slot].fd);
    clientsMAL.items(.pollFd)[slot].fd = ~clientsMAL.items(.pollFd)[slot].fd;
    clientsMAL.items(.pollFd)[slot].revents = 0;
    clientsMAL.items(.state)[slot] = serverTypes.ConnectionState.DISCONNECTED;
}

pub inline fn registerClient(
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

pub inline fn respond400(clientsMAL: *serverTypes.ClientsMAL, slot: usize, bytes_read: usize) void {
    // TODO: respond with 400?
    _ = clientsMAL;
    _ = slot;
    _ = bytes_read;
}

inline fn respondEcho(clientsMAL: *serverTypes.ClientsMAL, slot: usize, bytes_read: usize) void {
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
    log.debug("DATA FROM CLIENT {}/{} bytes", .{
        bytes_read,
        clientsMAL.items(.buffer)[slot].len,
    });
    pos += bytes_read;

    // Use writev to send in one syscall (would be ideal)
    // But we'll use a single write instead for this implementation
    _ = posix.write(clientsMAL.items(.pollFd)[slot].fd, responseBuffer[0..pos]) catch |err| switch (err) {
        posix.WriteError.WouldBlock => {
            log.debug("This client is blocking us!!", .{});
        },
        else => log.err("Error writing response to client, err {}", .{err}),
    };
}

// Optimized to reduce string formatting overhead
pub fn respondClient(clientsMAL: *serverTypes.ClientsMAL, slot: usize, bytes_read: usize) !void {
    // TODO: parse first line `method path http/version`
    var lineIter = std.mem.splitSequence(u8, clientsMAL.items(.buffer)[slot][0..], "\r\n");

    const firstLine = lineIter.next() orelse return VSE.Error.InvalidRequest;
    var wordIter = std.mem.splitSequence(u8, firstLine, " ");

    const httpMethod = wordIter.next() orelse return VSE.Error.InvalidRequest;
    const pathWithParams = wordIter.next() orelse return VSE.Error.InvalidRequest;
    const httpVersion = wordIter.next() orelse return VSE.Error.InvalidRequest;
    // TODO: log ip address correctly
    log.debug(
        \\ Client {} with addr {}:{} created request with 
        \\ method {s}
        \\ path {s}
        \\ http/version {s}
    , .{
        clientsMAL.items(.pollFd)[slot].fd,
        clientsMAL.items(.clientAddr)[slot],
        clientsMAL.items(.clientPort)[slot],
        httpMethod,
        pathWithParams,
        httpVersion,
    });

    const methodEnum = Request.Method.getReqMethod(httpMethod) orelse Request.Method.null;
    switch (methodEnum.performValidation(pathWithParams)) {
        .SUCCESS => {
            log.debug("hurray validation passed", .{});
        },
        .FAILED => {
            log.debug("Some error seems to have happened with validation", .{});
            respond400(clientsMAL, slot, bytes_read);
        },
    }
    // TODO: create handlers
    const file =  try std.fs.cwd().openFile("./index.html", .{});
    defer file.close();
    const fileSize = (try file.stat()).size;

    var responseBuffer: [serverConsts.READ_BUFFER_SIZE + 256]u8 = undefined;

    // Format the Content-Length part
    var lenBuf: [16]u8 = undefined;
    const lenStr = std.fmt.bufPrint(&lenBuf, "{d}", .{fileSize}) catch return;

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

    _ = try posix.send(clientsMAL.items(.pollFd)[slot].fd, responseBuffer[0..pos], 0);
    _ = std.os.linux.sendfile(clientsMAL.items(.pollFd)[slot].fd, file.handle, null, fileSize);


    // Place holder
    // respondEcho(clientsMAL, slot, bytes_read);

    // Update last activity time
    clientsMAL.items(.last_activity)[slot] = std.time.milliTimestamp();
}
