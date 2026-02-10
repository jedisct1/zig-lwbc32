const std = @import("std");

pub const Speck96 = struct {
    round_keys: [29]u48,

    const Self = @This();
    const rounds = 29;
    const alpha = 8;
    const beta = 3;
    const word_bytes = 6;

    pub fn init(key: [3]u48) Self {
        var cipher = Self{ .round_keys = undefined };
        cipher.expandKey(key);
        return cipher;
    }

    pub fn fromBytes(key: [18]u8) Self {
        return init(.{
            std.mem.readInt(u48, key[0..6], .little),
            std.mem.readInt(u48, key[6..12], .little),
            std.mem.readInt(u48, key[12..18], .little),
        });
    }

    inline fn expandKey(self: *Self, key: [3]u48) void {
        var k = key[0];
        var l0 = key[1];
        var l1 = key[2];

        self.round_keys[0] = k;

        const unroll_factor = 2;
        const unrolled_iterations = (rounds - 1) / unroll_factor;
        const remainder = (rounds - 1) % unroll_factor;

        var i: u48 = 0;
        inline for (0..unrolled_iterations) |_| {
            l0 = (k +% std.math.rotr(u48, l0, alpha)) ^ i;
            k = std.math.rotl(u48, k, beta) ^ l0;
            self.round_keys[i + 1] = k;
            i += 1;

            l1 = (k +% std.math.rotr(u48, l1, alpha)) ^ i;
            k = std.math.rotl(u48, k, beta) ^ l1;
            self.round_keys[i + 1] = k;
            i += 1;
        }

        inline for (0..remainder) |j| {
            const l_val = switch (j % 2) {
                0 => l0,
                1 => l1,
                else => unreachable,
            };
            const new_l = (k +% std.math.rotr(u48, l_val, alpha)) ^ i;
            k = std.math.rotl(u48, k, beta) ^ new_l;
            self.round_keys[i + 1] = k;
            switch (j % 2) {
                0 => l0 = new_l,
                1 => l1 = new_l,
                else => unreachable,
            }
            i += 1;
        }
    }

    pub inline fn encrypt(self: *const Self, plaintext: [2]u48) [2]u48 {
        var x = plaintext[0];
        var y = plaintext[1];

        const unroll_factor = 3;
        const unrolled = rounds / unroll_factor;
        const remainder = rounds % unroll_factor;

        inline for (0..unrolled) |i| {
            const k0 = self.round_keys[i * 3];
            const k1 = self.round_keys[i * 3 + 1];
            const k2 = self.round_keys[i * 3 + 2];

            x = (std.math.rotr(u48, x, alpha) +% y) ^ k0;
            y = std.math.rotl(u48, y, beta) ^ x;

            x = (std.math.rotr(u48, x, alpha) +% y) ^ k1;
            y = std.math.rotl(u48, y, beta) ^ x;

            x = (std.math.rotr(u48, x, alpha) +% y) ^ k2;
            y = std.math.rotl(u48, y, beta) ^ x;
        }

        inline for (0..remainder) |i| {
            const idx = unrolled * unroll_factor + i;
            x = (std.math.rotr(u48, x, alpha) +% y) ^ self.round_keys[idx];
            y = std.math.rotl(u48, y, beta) ^ x;
        }

        return .{ x, y };
    }

    pub inline fn decrypt(self: *const Self, ciphertext: [2]u48) [2]u48 {
        var x = ciphertext[0];
        var y = ciphertext[1];

        const unroll_factor = 3;
        const unrolled = rounds / unroll_factor;
        const remainder = rounds % unroll_factor;

        inline for (0..remainder) |j| {
            const i = rounds - 1 - j;
            y = std.math.rotr(u48, y ^ x, beta);
            x = std.math.rotl(u48, (x ^ self.round_keys[i]) -% y, alpha);
        }

        inline for (0..unrolled) |j| {
            const base_idx = rounds - remainder - (j + 1) * unroll_factor;
            const k2 = self.round_keys[base_idx + 2];
            const k1 = self.round_keys[base_idx + 1];
            const k0 = self.round_keys[base_idx];

            y = std.math.rotr(u48, y ^ x, beta);
            x = std.math.rotl(u48, (x ^ k2) -% y, alpha);

            y = std.math.rotr(u48, y ^ x, beta);
            x = std.math.rotl(u48, (x ^ k1) -% y, alpha);

            y = std.math.rotr(u48, y ^ x, beta);
            x = std.math.rotl(u48, (x ^ k0) -% y, alpha);
        }

        return .{ x, y };
    }

    pub inline fn encryptBlock(self: *const Self, block: [12]u8) [12]u8 {
        const plaintext: [2]u48 = .{
            std.mem.readInt(u48, block[0..6], .little),
            std.mem.readInt(u48, block[6..12], .little),
        };

        const ciphertext = self.encrypt(plaintext);

        var result: [12]u8 = undefined;
        std.mem.writeInt(u48, result[0..6], ciphertext[0], .little);
        std.mem.writeInt(u48, result[6..12], ciphertext[1], .little);
        return result;
    }

    pub inline fn decryptBlock(self: *const Self, block: [12]u8) [12]u8 {
        const ciphertext: [2]u48 = .{
            std.mem.readInt(u48, block[0..6], .little),
            std.mem.readInt(u48, block[6..12], .little),
        };

        const plaintext = self.decrypt(ciphertext);

        var result: [12]u8 = undefined;
        std.mem.writeInt(u48, result[0..6], plaintext[0], .little);
        std.mem.writeInt(u48, result[6..12], plaintext[1], .little);
        return result;
    }
};

test "Speck96 basic roundtrip" {
    const key: [3]u48 = .{ 0x050403020100, 0x0d0c0b0a0908, 0x151413121110 };
    const plaintext: [2]u48 = .{ 0x656d6974206e, 0x69202c726576 };

    const cipher = Speck96.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}

test "Speck96 block roundtrip" {
    const key: [3]u48 = .{ 0x050403020100, 0x0d0c0b0a0908, 0x151413121110 };
    const plaintext_bytes: [12]u8 = .{ 0x6e, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x76, 0x65, 0x72, 0x2c, 0x20, 0x69 };

    const cipher = Speck96.init(key);
    const ciphertext_bytes = cipher.encryptBlock(plaintext_bytes);
    const decrypted_bytes = cipher.decryptBlock(ciphertext_bytes);

    try std.testing.expectEqualSlices(u8, &plaintext_bytes, &decrypted_bytes);
}

test "Speck96 fromBytes" {
    const key_bytes: [18]u8 = .{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 };
    const key_words: [3]u48 = .{ 0x050403020100, 0x0d0c0b0a0908, 0x151413121110 };
    const plaintext: [2]u48 = .{ 0x656d6974206e, 0x69202c726576 };

    const cipher_bytes = Speck96.fromBytes(key_bytes);
    const cipher_words = Speck96.init(key_words);

    try std.testing.expectEqual(cipher_words.encrypt(plaintext), cipher_bytes.encrypt(plaintext));
}

test "Speck96 official test vector" {
    const key: [3]u48 = .{ 0x050403020100, 0x0d0c0b0a0908, 0x151413121110 };
    const plaintext: [2]u48 = .{ 0x656d6974206e, 0x69202c726576 };
    const expected: [2]u48 = .{ 0x2bf31072228a, 0x7ae440252ee6 };

    const cipher = Speck96.init(key);
    const ciphertext = cipher.encrypt(plaintext);

    try std.testing.expectEqual(expected[0], ciphertext[0]);
    try std.testing.expectEqual(expected[1], ciphertext[1]);

    const decrypted = cipher.decrypt(ciphertext);
    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}
