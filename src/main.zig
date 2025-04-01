const std = @import("std");
const log = std.log.scoped(.root);
const posix = std.posix;

const clientUtils = @import("utils/client.zig");
const socketUtils = @import("utils/socket.zig");
const serverHandler = @import("handlers/core.zig");
const serverTypes = @import("types.zig");
const serverConsts = @import("constants.zig");

pub fn main() serverTypes.VSE.Error!void {
    var clientsMAL = serverTypes.ClientsMAL{};
    var memoryBuffer: [serverConsts.MAX_SOCKETS * @sizeOf(serverTypes.SocketState)]u8 = undefined;
    try clientUtils.initClientsMAL(&clientsMAL, &memoryBuffer);
    log.debug(
        "Initialized clients multi array list with size {} MB",
        .{(@sizeOf(serverTypes.SocketState) * serverConsts.MAX_SOCKETS / (1024*1024))},
    );

    const listenSocket: posix.socket_t = socketUtils.initSocket() catch |err| {
        log.err("Error while initializing socket, err {}", .{err});
        return serverTypes.VSE.Error.SocketInitializationError;
    };
    defer posix.close(listenSocket);

    try socketUtils.bindSocket(listenSocket);
    log.info("Server started on port {}\n", .{serverConsts.PORT});

    try serverHandler.cycleOfServing(&clientsMAL, listenSocket);
}
