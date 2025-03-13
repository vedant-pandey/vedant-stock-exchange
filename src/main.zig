const std = @import("std");
const posix = std.posix;
const log = std.log;

const QUEUE_SIZE = 10;
const READ_BUFFER_SIZE = 4 * 1024;
const MAX_CONNECTIONS = 256;

pub fn main() !void {
    const listen_socket = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    log.debug("Socket created {}\n", .{listen_socket});

    var read_buffer: [READ_BUFFER_SIZE]u8 = [_]u8{0} ** READ_BUFFER_SIZE;

    const opt: u32 = 1;
    try posix.setsockopt(listen_socket, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&opt));

    const server_addr_in: posix.sockaddr.in = posix.sockaddr.in{
        .port = std.mem.nativeTo(u16, 3000, std.builtin.Endian.big),
        .addr = 0,
    };

    var client_addr_in: posix.sockaddr.in = undefined;
    var client_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

    try posix.bind(listen_socket, @as(*const posix.sockaddr, @ptrCast(&server_addr_in)), @sizeOf(posix.sockaddr.in));
    try posix.listen(listen_socket, QUEUE_SIZE);
    while (true) {
        const client_fd = posix.accept(listen_socket, @as(*posix.sockaddr, @ptrCast(&client_addr_in)), &client_addr_len, 0) catch |err| {
            log.err("Error while attempting to accept connection from client, err {}", .{err});
            continue;
        };

        const bytes_read = posix.read(client_fd, &read_buffer) catch |err| {
            log.err("Error while reading buffer {}, err {}", .{ client_fd, err });
            continue;
        };

        log.debug("Bytes read {}, data {s}", .{ bytes_read, read_buffer });

        log.debug("Telling client {} that it is kewl", .{client_fd});
        _ = posix.write(client_fd, "kewl dude!") catch |err| {
            log.err("Error while responding to client {}, err {}", .{client_fd, err});
        };
        posix.close(client_fd);
    }
}
