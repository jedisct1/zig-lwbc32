const std = @import("std");

pub const Simon48 = struct {
    round_keys: [36]u24,

    const Self = @This();
    const rounds = 36;
    const z1: u64 = 0b01011010000110010011111011100010101101000011001001111101110001;

    pub fn init(key: [4]u24) Self {
        var cipher = Self{ .round_keys = undefined };
        cipher.expandKey(key);
        return cipher;
    }

    pub fn fromBytes(key: [12]u8) Self {
        return init(.{
            std.mem.readInt(u24, key[0..3], .little),
            std.mem.readInt(u24, key[3..6], .little),
            std.mem.readInt(u24, key[6..9], .little),
            std.mem.readInt(u24, key[9..12], .little),
        });
    }

    inline fn expandKey(self: *Self, key: [4]u24) void {
        const round_constant: u24 = 0xFFFFFF ^ 3;

        self.round_keys[0] = key[0];
        self.round_keys[1] = key[1];
        self.round_keys[2] = key[2];
        self.round_keys[3] = key[3];

        const unroll_factor = 4;
        const unrolled_iterations = (rounds - 4) / unroll_factor;
        const remainder = (rounds - 4) % unroll_factor;

        var i: usize = 4;
        inline for (0..unrolled_iterations) |_| {
            inline for (0..unroll_factor) |j| {
                const idx = i + j;
                var tmp = std.math.rotr(u24, self.round_keys[idx - 1], 3);
                tmp = tmp ^ self.round_keys[idx - 3];
                tmp = tmp ^ std.math.rotr(u24, tmp, 1);
                const z_bit: u24 = @intCast((z1 >> @as(u6, @intCast((idx - 4) % 62))) & 1);
                self.round_keys[idx] = round_constant ^ z_bit ^ tmp ^ self.round_keys[idx - 4];
            }
            i += unroll_factor;
        }

        inline for (0..remainder) |j| {
            const idx = i + j;
            var tmp = std.math.rotr(u24, self.round_keys[idx - 1], 3);
            tmp = tmp ^ self.round_keys[idx - 3];
            tmp = tmp ^ std.math.rotr(u24, tmp, 1);
            const z_bit: u24 = @intCast((z1 >> @as(u6, @intCast((idx - 4) % 62))) & 1);
            self.round_keys[idx] = round_constant ^ z_bit ^ tmp ^ self.round_keys[idx - 4];
        }
    }

    pub inline fn encrypt(self: *const Self, plaintext: [2]u24) [2]u24 {
        var x = plaintext[0];
        var y = plaintext[1];

        const unroll_factor = 4;
        const unrolled_iterations = rounds / unroll_factor;
        const remainder = rounds % unroll_factor;

        var i: usize = 0;
        inline for (0..unrolled_iterations) |_| {
            inline for (0..unroll_factor) |j| {
                const tmp = x;
                const f = (std.math.rotl(u24, x, 1) & std.math.rotl(u24, x, 8)) ^ std.math.rotl(u24, x, 2);
                x = y ^ f ^ self.round_keys[i + j];
                y = tmp;
            }
            i += unroll_factor;
        }

        inline for (0..remainder) |j| {
            const tmp = x;
            const f = (std.math.rotl(u24, x, 1) & std.math.rotl(u24, x, 8)) ^ std.math.rotl(u24, x, 2);
            x = y ^ f ^ self.round_keys[i + j];
            y = tmp;
        }

        return .{ x, y };
    }

    pub inline fn decrypt(self: *const Self, ciphertext: [2]u24) [2]u24 {
        var x = ciphertext[0];
        var y = ciphertext[1];

        const unroll_factor = 4;
        const unrolled_iterations = rounds / unroll_factor;
        const remainder = rounds % unroll_factor;

        var i: usize = rounds;

        inline for (0..remainder) |j| {
            i -= 1;
            const tmp = y;
            const f = (std.math.rotl(u24, y, 1) & std.math.rotl(u24, y, 8)) ^ std.math.rotl(u24, y, 2);
            y = x ^ f ^ self.round_keys[i];
            x = tmp;
            _ = j;
        }

        inline for (0..unrolled_iterations) |_| {
            inline for (0..unroll_factor) |_| {
                i -= 1;
                const tmp = y;
                const f = (std.math.rotl(u24, y, 1) & std.math.rotl(u24, y, 8)) ^ std.math.rotl(u24, y, 2);
                y = x ^ f ^ self.round_keys[i];
                x = tmp;
            }
        }

        return .{ x, y };
    }

    pub inline fn encryptBlock(self: *const Self, block: [6]u8) [6]u8 {
        const plaintext: [2]u24 = .{
            std.mem.readInt(u24, block[0..3], .little),
            std.mem.readInt(u24, block[3..6], .little),
        };

        const ciphertext = self.encrypt(plaintext);

        var result: [6]u8 = undefined;
        std.mem.writeInt(u24, result[0..3], ciphertext[0], .little);
        std.mem.writeInt(u24, result[3..6], ciphertext[1], .little);
        return result;
    }

    pub inline fn decryptBlock(self: *const Self, block: [6]u8) [6]u8 {
        const ciphertext: [2]u24 = .{
            std.mem.readInt(u24, block[0..3], .little),
            std.mem.readInt(u24, block[3..6], .little),
        };

        const plaintext = self.decrypt(ciphertext);

        var result: [6]u8 = undefined;
        std.mem.writeInt(u24, result[0..3], plaintext[0], .little);
        std.mem.writeInt(u24, result[3..6], plaintext[1], .little);
        return result;
    }
};

test "Simon48 basic roundtrip" {
    const key: [4]u24 = .{ 0x020100, 0x0a0908, 0x121110, 0x1a1918 };
    const plaintext: [2]u24 = .{ 0x726963, 0x20646e };

    const cipher = Simon48.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}

test "Simon48 official test vector" {
    const key: [4]u24 = .{ 0x020100, 0x0a0908, 0x121110, 0x1a1918 };
    const plaintext: [2]u24 = .{ 0x726963, 0x20646e };
    const expected: [2]u24 = .{ 0x6e06a5, 0xacf156 };

    const cipher = Simon48.init(key);
    const ciphertext = cipher.encrypt(plaintext);

    try std.testing.expectEqual(expected[0], ciphertext[0]);
    try std.testing.expectEqual(expected[1], ciphertext[1]);

    const decrypted = cipher.decrypt(ciphertext);
    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}

test "Simon48 block roundtrip" {
    const key: [4]u24 = .{ 0x020100, 0x0a0908, 0x121110, 0x1a1918 };
    const plaintext_bytes: [6]u8 = .{ 0x63, 0x69, 0x72, 0x6e, 0x64, 0x20 };

    const cipher = Simon48.init(key);
    const ciphertext_bytes = cipher.encryptBlock(plaintext_bytes);
    const decrypted_bytes = cipher.decryptBlock(ciphertext_bytes);

    try std.testing.expectEqualSlices(u8, &plaintext_bytes, &decrypted_bytes);
}

test "Simon48 fromBytes" {
    const key_bytes: [12]u8 = .{ 0x00, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x10, 0x11, 0x12, 0x18, 0x19, 0x1a };
    const key_words: [4]u24 = .{ 0x020100, 0x0a0908, 0x121110, 0x1a1918 };
    const plaintext: [2]u24 = .{ 0x726963, 0x20646e };

    const cipher_bytes = Simon48.fromBytes(key_bytes);
    const cipher_words = Simon48.init(key_words);

    try std.testing.expectEqual(cipher_words.encrypt(plaintext), cipher_bytes.encrypt(plaintext));
}
