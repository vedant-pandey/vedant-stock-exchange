const std = @import("std");
const posix = std.posix;
const serverTypes = @import("types.zig");

pub const QUEUE_SIZE = 128; // Increased from 10
pub const READ_BUFFER_SIZE = 16 * 1024; // Increased from 16K
pub const MAX_SOCKETS = 1000 + 1; // One extra for listen socket
pub const PORT = 3000;
pub const POLL_TIMEOUT_MS = 100; // Add timeout instead of infinite wait
pub const IDLE_TIMEOUT_MS = 30 * 1000; // 30 seconds
pub const STATS_TIMEOUT_MS = 10 * 1000; // 10 seconds

// Pre-computed HTTP response headers
pub const HTTP_RESPONSE_PREFIX = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ";
pub const HTTP_400_RESPONSE_PREFIX = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: ";
pub const HTTP_RESPONSE_SUFFIX = "\r\nConnection: keep-alive\r\n\r\n";

