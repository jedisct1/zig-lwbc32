const std = @import("std");

pub const Simon64 = struct {
    round_keys: [44]u32,

    const Self = @This();
    const rounds = 44;
    const z3: u64 = 0b11110000101100111001010001001000000111101001100011010111011011;

    pub fn init(key: [4]u32) Self {
        var cipher = Self{ .round_keys = undefined };
        cipher.expandKey(key);
        return cipher;
    }

    pub fn fromBytes(key: [16]u8) Self {
        return init(.{
            std.mem.readInt(u32, key[0..4], .little),
            std.mem.readInt(u32, key[4..8], .little),
            std.mem.readInt(u32, key[8..12], .little),
            std.mem.readInt(u32, key[12..16], .little),
        });
    }

    inline fn expandKey(self: *Self, key: [4]u32) void {
        const mod_mask: u32 = 0xFFFFFFFF;
        const round_constant: u32 = mod_mask ^ 3;

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
                var tmp = std.math.rotr(u32, self.round_keys[idx - 1], 3);
                tmp = tmp ^ self.round_keys[idx - 3];
                tmp = tmp ^ std.math.rotr(u32, tmp, 1);
                const z_bit: u32 = @intCast((z3 >> @as(u6, @intCast((idx - 4) % 62))) & 1);
                self.round_keys[idx] = round_constant ^ z_bit ^ tmp ^ self.round_keys[idx - 4];
            }
            i += unroll_factor;
        }

        inline for (0..remainder) |j| {
            const idx = i + j;
            var tmp = std.math.rotr(u32, self.round_keys[idx - 1], 3);
            tmp = tmp ^ self.round_keys[idx - 3];
            tmp = tmp ^ std.math.rotr(u32, tmp, 1);
            const z_bit: u32 = @intCast((z3 >> @as(u6, @intCast((idx - 4) % 62))) & 1);
            self.round_keys[idx] = round_constant ^ z_bit ^ tmp ^ self.round_keys[idx - 4];
        }
    }

    pub inline fn encrypt(self: *const Self, plaintext: [2]u32) [2]u32 {
        var x = plaintext[0];
        var y = plaintext[1];

        const unroll_factor = 4;
        const unrolled_iterations = rounds / unroll_factor;
        const remainder = rounds % unroll_factor;

        var i: usize = 0;
        inline for (0..unrolled_iterations) |_| {
            inline for (0..unroll_factor) |j| {
                const tmp = x;
                const f = (std.math.rotl(u32, x, 1) & std.math.rotl(u32, x, 8)) ^ std.math.rotl(u32, x, 2);
                x = y ^ f ^ self.round_keys[i + j];
                y = tmp;
            }
            i += unroll_factor;
        }

        inline for (0..remainder) |j| {
            const tmp = x;
            const f = (std.math.rotl(u32, x, 1) & std.math.rotl(u32, x, 8)) ^ std.math.rotl(u32, x, 2);
            x = y ^ f ^ self.round_keys[i + j];
            y = tmp;
        }

        return .{ x, y };
    }

    pub inline fn decrypt(self: *const Self, ciphertext: [2]u32) [2]u32 {
        var x = ciphertext[0];
        var y = ciphertext[1];

        const unroll_factor = 4;
        const unrolled_iterations = rounds / unroll_factor;
        const remainder = rounds % unroll_factor;

        var i: usize = rounds;

        inline for (0..remainder) |j| {
            i -= 1;
            const tmp = y;
            const f = (std.math.rotl(u32, y, 1) & std.math.rotl(u32, y, 8)) ^ std.math.rotl(u32, y, 2);
            y = x ^ f ^ self.round_keys[i];
            x = tmp;
            _ = j;
        }

        inline for (0..unrolled_iterations) |_| {
            inline for (0..unroll_factor) |_| {
                i -= 1;
                const tmp = y;
                const f = (std.math.rotl(u32, y, 1) & std.math.rotl(u32, y, 8)) ^ std.math.rotl(u32, y, 2);
                y = x ^ f ^ self.round_keys[i];
                x = tmp;
            }
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

test "Simon64 basic roundtrip" {
    const key: [4]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
    const plaintext: [2]u32 = .{ 0x20646e75, 0x656b696c };

    const cipher = Simon64.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}

test "Simon64 NSA test vector" {
    const key: [4]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
    const plaintext: [2]u32 = .{ 0x656b696c, 0x20646e75 };
    const expected_ciphertext: [2]u32 = .{ 0x44c8fc20, 0xb9dfa07a };

    const cipher = Simon64.init(key);
    const ciphertext = cipher.encrypt(plaintext);

    try std.testing.expectEqual(expected_ciphertext[0], ciphertext[0]);
    try std.testing.expectEqual(expected_ciphertext[1], ciphertext[1]);
}

test "Simon64 block roundtrip" {
    const key: [4]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
    const plaintext_bytes: [8]u8 = .{ 0x75, 0x6e, 0x64, 0x20, 0x6c, 0x69, 0x6b, 0x65 };

    const cipher = Simon64.init(key);
    const ciphertext_bytes = cipher.encryptBlock(plaintext_bytes);
    const decrypted_bytes = cipher.decryptBlock(ciphertext_bytes);

    try std.testing.expectEqualSlices(u8, &plaintext_bytes, &decrypted_bytes);
}
