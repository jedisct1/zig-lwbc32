const std = @import("std");

pub inline fn rotateLeft(comptime T: type, x: T, n: anytype) T {
    return std.math.rotl(T, x, n);
}

pub inline fn rotateRight(comptime T: type, x: T, n: anytype) T {
    return std.math.rotr(T, x, n);
}

pub const BlockCipher32 = struct {
    key: [4]u16,

    const Self = @This();

    pub fn encrypt(self: *const Self, plaintext: [2]u16) [2]u16 {
        _ = self;
        _ = plaintext;
        @panic("Not implemented");
    }

    pub fn decrypt(self: *const Self, ciphertext: [2]u16) [2]u16 {
        _ = self;
        _ = ciphertext;
        @panic("Not implemented");
    }
};
