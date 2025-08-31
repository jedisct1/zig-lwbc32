const std = @import("std");

pub inline fn rotateLeft(comptime T: type, x: T, n: anytype) T {
    return std.math.rotl(T, x, n);
}

pub inline fn rotateRight(comptime T: type, x: T, n: anytype) T {
    return std.math.rotr(T, x, n);
}
