const std = @import("std");
const log = std.log.scoped(.@"server-utils");
const serverTypes = @import("../types.zig");

pub inline fn logIpAddr(ClientsMAL: *const serverTypes.ClientsMAL, msg: []const u8, slot: usize) void {
    const bigEndianAddr = ClientsMAL.items(.clientAddr)[slot];
    const port = ClientsMAL.items(.clientPort)[slot];
    const first: u8 = @truncate((bigEndianAddr >> 0) & 0xFF);
    const second: u8 = @truncate((bigEndianAddr >> 8) & 0xFF);
    const third: u8 = @truncate((bigEndianAddr >> 16) & 0xFF);
    const fourth: u8 = @truncate((bigEndianAddr >> 24) & 0xFF);
    log.debug("{s} {}.{}.{}.{}:{}", .{ msg, first, second, third, fourth, std.mem.bigToNative(u16, port) });
}

pub inline fn findFreeSlot(clientsMAL: *const serverTypes.ClientsMAL) serverTypes.VSE.Error!usize {
    // Use bitmap or free list for faster slot finding
    for (clientsMAL.items(.pollFd), 0..) |pollFd, i| {
        if (pollFd.fd < 0) return i;
    }
    return serverTypes.VSE.Error.NoSlotsAvailable;
}

pub inline fn findSlotByFd(clientsMAL: *serverTypes.SocketsMAL, fd: i32) serverTypes.VSE.Error{
    // Consider using a hashmap for O(1) lookup instead of O(n)
    for (clientsMAL.items(.pollFd), 0..) |pollFd, i| {
        if (pollFd.fd == fd) {
            return i;
        }
    }

    return serverTypes.VSE.Error.InvalidClientFd;
}
