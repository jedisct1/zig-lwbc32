const std = @import("std");

inline fn rotateLeft(comptime T: type, x: T, n: anytype) T {
    return std.math.rotl(T, x, n);
}

inline fn rotateRight(comptime T: type, x: T, n: anytype) T {
    return std.math.rotr(T, x, n);
}

pub const Speck32 = struct {
    round_keys: [22]u16,

    const Self = @This();
    const rounds = 22;
    const alpha = 7; // Right rotation amount for 16-bit words
    const beta = 2; // Left rotation amount for 16-bit words

    pub fn init(key: [4]u16) Self {
        var cipher = Self{ .round_keys = undefined };
        cipher.expandKey(key);
        return cipher;
    }

    fn expandKey(self: *Self, key: [4]u16) void {
        var k = key[0];
        var l: [3]u16 = .{ key[1], key[2], key[3] };

        self.round_keys[0] = k;

        var i: u16 = 0;
        while (i < rounds - 1) : (i += 1) {
            const idx = i % 3;
            l[idx] = (k +% rotateRight(u16, l[idx], alpha)) ^ i;
            k = rotateLeft(u16, k, beta) ^ l[idx];
            self.round_keys[i + 1] = k;
        }
    }

    fn roundFunction(x: u16, y: u16, k: u16) struct { u16, u16 } {
        const new_x = (rotateRight(u16, x, alpha) +% y) ^ k;
        const new_y = rotateLeft(u16, y, beta) ^ new_x;
        return .{ new_x, new_y };
    }

    fn inverseRoundFunction(x: u16, y: u16, k: u16) struct { u16, u16 } {
        const new_y = rotateRight(u16, y ^ x, beta);
        const new_x = rotateLeft(u16, (x ^ k) -% new_y, alpha);
        return .{ new_x, new_y };
    }

    pub fn encrypt(self: *const Self, plaintext: [2]u16) [2]u16 {
        var x = plaintext[0];
        var y = plaintext[1];

        var i: usize = 0;
        while (i < rounds) : (i += 1) {
            const result = roundFunction(x, y, self.round_keys[i]);
            x = result[0];
            y = result[1];
        }

        return .{ x, y };
    }

    pub fn decrypt(self: *const Self, ciphertext: [2]u16) [2]u16 {
        var x = ciphertext[0];
        var y = ciphertext[1];

        var i: usize = rounds;
        while (i > 0) {
            i -= 1;
            const result = inverseRoundFunction(x, y, self.round_keys[i]);
            x = result[0];
            y = result[1];
        }

        return .{ x, y };
    }

    pub fn encryptBlock(self: *const Self, block: [4]u8) [4]u8 {
        const plaintext: [2]u16 = .{
            std.mem.readInt(u16, block[0..2], .little),
            std.mem.readInt(u16, block[2..4], .little),
        };

        const ciphertext = self.encrypt(plaintext);

        var result: [4]u8 = undefined;
        std.mem.writeInt(u16, result[0..2], ciphertext[0], .little);
        std.mem.writeInt(u16, result[2..4], ciphertext[1], .little);
        return result;
    }

    pub fn decryptBlock(self: *const Self, block: [4]u8) [4]u8 {
        const ciphertext: [2]u16 = .{
            std.mem.readInt(u16, block[0..2], .little),
            std.mem.readInt(u16, block[2..4], .little),
        };

        const plaintext = self.decrypt(ciphertext);

        var result: [4]u8 = undefined;
        std.mem.writeInt(u16, result[0..2], plaintext[0], .little);
        std.mem.writeInt(u16, result[2..4], plaintext[1], .little);
        return result;
    }
};

test "Speck32 basic roundtrip" {
    const key: [4]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918 };
    const plaintext: [2]u16 = .{ 0x6574, 0x694c };

    const cipher = Speck32.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}

test "Speck32 block roundtrip" {
    const key: [4]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918 };
    const plaintext_bytes: [4]u8 = .{ 0x74, 0x65, 0x4c, 0x69 };

    const cipher = Speck32.init(key);
    const ciphertext_bytes = cipher.encryptBlock(plaintext_bytes);
    const decrypted_bytes = cipher.decryptBlock(ciphertext_bytes);

    try std.testing.expectEqualSlices(u8, &plaintext_bytes, &decrypted_bytes);
}
