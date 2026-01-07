const std = @import("std");

pub const Speck64 = struct {
    round_keys: [27]u32,

    const Self = @This();
    const rounds = 27;
    const alpha = 8;
    const beta = 3;

    pub fn init(key: [4]u32) Self {
        var cipher = Self{ .round_keys = undefined };
        cipher.expandKey(key);
        return cipher;
    }

    inline fn expandKey(self: *Self, key: [4]u32) void {
        var k = key[0];
        var l0 = key[1];
        var l1 = key[2];
        var l2 = key[3];

        self.round_keys[0] = k;

        const unroll_factor = 3;
        const unrolled_iterations = (rounds - 1) / unroll_factor;
        const remainder = (rounds - 1) % unroll_factor;

        var i: u32 = 0;
        inline for (0..unrolled_iterations) |_| {
            l0 = (k +% std.math.rotr(u32, l0, alpha)) ^ i;
            k = std.math.rotl(u32, k, beta) ^ l0;
            self.round_keys[i + 1] = k;
            i += 1;

            l1 = (k +% std.math.rotr(u32, l1, alpha)) ^ i;
            k = std.math.rotl(u32, k, beta) ^ l1;
            self.round_keys[i + 1] = k;
            i += 1;

            l2 = (k +% std.math.rotr(u32, l2, alpha)) ^ i;
            k = std.math.rotl(u32, k, beta) ^ l2;
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
            const new_l = (k +% std.math.rotr(u32, l_val, alpha)) ^ i;
            k = std.math.rotl(u32, k, beta) ^ new_l;
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

    pub inline fn encrypt(self: *const Self, plaintext: [2]u32) [2]u32 {
        var x = plaintext[0];
        var y = plaintext[1];

        const unroll_factor = 3;
        const unrolled = rounds / unroll_factor;
        const remainder = rounds % unroll_factor;

        inline for (0..unrolled) |i| {
            const k0 = self.round_keys[i * 3];
            const k1 = self.round_keys[i * 3 + 1];
            const k2 = self.round_keys[i * 3 + 2];

            x = (std.math.rotr(u32, x, alpha) +% y) ^ k0;
            y = std.math.rotl(u32, y, beta) ^ x;

            x = (std.math.rotr(u32, x, alpha) +% y) ^ k1;
            y = std.math.rotl(u32, y, beta) ^ x;

            x = (std.math.rotr(u32, x, alpha) +% y) ^ k2;
            y = std.math.rotl(u32, y, beta) ^ x;
        }

        inline for (0..remainder) |i| {
            const idx = unrolled * unroll_factor + i;
            x = (std.math.rotr(u32, x, alpha) +% y) ^ self.round_keys[idx];
            y = std.math.rotl(u32, y, beta) ^ x;
        }

        return .{ x, y };
    }

    pub inline fn decrypt(self: *const Self, ciphertext: [2]u32) [2]u32 {
        var x = ciphertext[0];
        var y = ciphertext[1];

        const unroll_factor = 3;
        const unrolled = rounds / unroll_factor;
        const remainder = rounds % unroll_factor;

        inline for (0..remainder) |j| {
            const i = rounds - 1 - j;
            y = std.math.rotr(u32, y ^ x, beta);
            x = std.math.rotl(u32, (x ^ self.round_keys[i]) -% y, alpha);
        }

        inline for (0..unrolled) |j| {
            const base_idx = rounds - remainder - (j + 1) * unroll_factor;
            const k2 = self.round_keys[base_idx + 2];
            const k1 = self.round_keys[base_idx + 1];
            const k0 = self.round_keys[base_idx];

            y = std.math.rotr(u32, y ^ x, beta);
            x = std.math.rotl(u32, (x ^ k2) -% y, alpha);

            y = std.math.rotr(u32, y ^ x, beta);
            x = std.math.rotl(u32, (x ^ k1) -% y, alpha);

            y = std.math.rotr(u32, y ^ x, beta);
            x = std.math.rotl(u32, (x ^ k0) -% y, alpha);
        }

        return .{ x, y };
    }

    pub inline fn encryptBlock(self: *const Self, block: [8]u8) [8]u8 {
        const plaintext: [2]u32 = .{
            @bitCast(block[0..4].*),
            @bitCast(block[4..8].*),
        };

        const ciphertext = self.encrypt(plaintext);

        return @bitCast([_]u32{ ciphertext[0], ciphertext[1] });
    }

    pub inline fn decryptBlock(self: *const Self, block: [8]u8) [8]u8 {
        const ciphertext: [2]u32 = .{
            @bitCast(block[0..4].*),
            @bitCast(block[4..8].*),
        };

        const plaintext = self.decrypt(ciphertext);

        return @bitCast([_]u32{ plaintext[0], plaintext[1] });
    }
};

test "Speck64 basic roundtrip" {
    const key: [4]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
    const plaintext: [2]u32 = .{ 0x3b726574, 0x7475432d };

    const cipher = Speck64.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}

test "Speck64 block roundtrip" {
    const key: [4]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
    const plaintext_bytes: [8]u8 = .{ 0x74, 0x65, 0x72, 0x3b, 0x2d, 0x43, 0x75, 0x74 };

    const cipher = Speck64.init(key);
    const ciphertext_bytes = cipher.encryptBlock(plaintext_bytes);
    const decrypted_bytes = cipher.decryptBlock(ciphertext_bytes);

    try std.testing.expectEqualSlices(u8, &plaintext_bytes, &decrypted_bytes);
}
