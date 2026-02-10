const std = @import("std");

pub const Speck48 = struct {
    round_keys: [23]u24,

    const Self = @This();
    const rounds = 23;
    const alpha = 8;
    const beta = 3;
    const word_bytes = 3;

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
        var k = key[0];
        var l0 = key[1];
        var l1 = key[2];
        var l2 = key[3];

        self.round_keys[0] = k;

        const unroll_factor = 3;
        const unrolled_iterations = (rounds - 1) / unroll_factor;
        const remainder = (rounds - 1) % unroll_factor;

        var i: u24 = 0;
        inline for (0..unrolled_iterations) |_| {
            l0 = (k +% std.math.rotr(u24, l0, alpha)) ^ i;
            k = std.math.rotl(u24, k, beta) ^ l0;
            self.round_keys[i + 1] = k;
            i += 1;

            l1 = (k +% std.math.rotr(u24, l1, alpha)) ^ i;
            k = std.math.rotl(u24, k, beta) ^ l1;
            self.round_keys[i + 1] = k;
            i += 1;

            l2 = (k +% std.math.rotr(u24, l2, alpha)) ^ i;
            k = std.math.rotl(u24, k, beta) ^ l2;
            self.round_keys[i + 1] = k;
            i += 1;
        }

        inline for (0..remainder) |j| {
            const idx = j % 3;
            const l_val = switch (idx) {
                0 => l0,
                1 => l1,
                2 => l2,
                else => unreachable,
            };
            const new_l = (k +% std.math.rotr(u24, l_val, alpha)) ^ i;
            k = std.math.rotl(u24, k, beta) ^ new_l;
            self.round_keys[i + 1] = k;
            switch (idx) {
                0 => l0 = new_l,
                1 => l1 = new_l,
                2 => l2 = new_l,
                else => unreachable,
            }
            i += 1;
        }
    }

    pub inline fn encrypt(self: *const Self, plaintext: [2]u24) [2]u24 {
        var x = plaintext[0];
        var y = plaintext[1];

        const unroll_factor = 3;
        const unrolled = rounds / unroll_factor;
        const remainder = rounds % unroll_factor;

        inline for (0..unrolled) |i| {
            const k0 = self.round_keys[i * 3];
            const k1 = self.round_keys[i * 3 + 1];
            const k2 = self.round_keys[i * 3 + 2];

            x = (std.math.rotr(u24, x, alpha) +% y) ^ k0;
            y = std.math.rotl(u24, y, beta) ^ x;

            x = (std.math.rotr(u24, x, alpha) +% y) ^ k1;
            y = std.math.rotl(u24, y, beta) ^ x;

            x = (std.math.rotr(u24, x, alpha) +% y) ^ k2;
            y = std.math.rotl(u24, y, beta) ^ x;
        }

        inline for (0..remainder) |i| {
            const idx = unrolled * unroll_factor + i;
            x = (std.math.rotr(u24, x, alpha) +% y) ^ self.round_keys[idx];
            y = std.math.rotl(u24, y, beta) ^ x;
        }

        return .{ x, y };
    }

    pub inline fn decrypt(self: *const Self, ciphertext: [2]u24) [2]u24 {
        var x = ciphertext[0];
        var y = ciphertext[1];

        const unroll_factor = 3;
        const unrolled = rounds / unroll_factor;
        const remainder = rounds % unroll_factor;

        inline for (0..remainder) |j| {
            const i = rounds - 1 - j;
            y = std.math.rotr(u24, y ^ x, beta);
            x = std.math.rotl(u24, (x ^ self.round_keys[i]) -% y, alpha);
        }

        inline for (0..unrolled) |j| {
            const base_idx = rounds - remainder - (j + 1) * unroll_factor;
            const k2 = self.round_keys[base_idx + 2];
            const k1 = self.round_keys[base_idx + 1];
            const k0 = self.round_keys[base_idx];

            y = std.math.rotr(u24, y ^ x, beta);
            x = std.math.rotl(u24, (x ^ k2) -% y, alpha);

            y = std.math.rotr(u24, y ^ x, beta);
            x = std.math.rotl(u24, (x ^ k1) -% y, alpha);

            y = std.math.rotr(u24, y ^ x, beta);
            x = std.math.rotl(u24, (x ^ k0) -% y, alpha);
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

test "Speck48 basic roundtrip" {
    const key: [4]u24 = .{ 0x020100, 0x0a0908, 0x121110, 0x1a1918 };
    const plaintext: [2]u24 = .{ 0x6d2073, 0x696874 };

    const cipher = Speck48.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}

test "Speck48 block roundtrip" {
    const key: [4]u24 = .{ 0x020100, 0x0a0908, 0x121110, 0x1a1918 };
    const plaintext_bytes: [6]u8 = .{ 0x73, 0x20, 0x6d, 0x74, 0x68, 0x69 };

    const cipher = Speck48.init(key);
    const ciphertext_bytes = cipher.encryptBlock(plaintext_bytes);
    const decrypted_bytes = cipher.decryptBlock(ciphertext_bytes);

    try std.testing.expectEqualSlices(u8, &plaintext_bytes, &decrypted_bytes);
}

test "Speck48 fromBytes" {
    const key_bytes: [12]u8 = .{ 0x00, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x10, 0x11, 0x12, 0x18, 0x19, 0x1a };
    const key_words: [4]u24 = .{ 0x020100, 0x0a0908, 0x121110, 0x1a1918 };
    const plaintext: [2]u24 = .{ 0x6d2073, 0x696874 };

    const cipher_bytes = Speck48.fromBytes(key_bytes);
    const cipher_words = Speck48.init(key_words);

    try std.testing.expectEqual(cipher_words.encrypt(plaintext), cipher_bytes.encrypt(plaintext));
}

test "Speck48 official test vector" {
    const key: [4]u24 = .{ 0x020100, 0x0a0908, 0x121110, 0x1a1918 };
    const plaintext: [2]u24 = .{ 0x6d2073, 0x696874 };
    const expected: [2]u24 = .{ 0x735e10, 0xb6445d };

    const cipher = Speck48.init(key);
    const ciphertext = cipher.encrypt(plaintext);

    try std.testing.expectEqual(expected[0], ciphertext[0]);
    try std.testing.expectEqual(expected[1], ciphertext[1]);

    const decrypted = cipher.decrypt(ciphertext);
    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}
