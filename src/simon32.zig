const std = @import("std");

pub const Simon32 = struct {
    round_keys: [32]u16,

    const Self = @This();
    const rounds = 32;
    const z0: u64 = 0b01100111000011010100100010111110110011100001101010010001011111;

    pub fn init(key: [4]u16) Self {
        var cipher = Self{ .round_keys = undefined };
        cipher.expandKey(key);
        return cipher;
    }

    pub fn fromBytes(key: [8]u8) Self {
        return init(.{
            std.mem.readInt(u16, key[0..2], .little),
            std.mem.readInt(u16, key[2..4], .little),
            std.mem.readInt(u16, key[4..6], .little),
            std.mem.readInt(u16, key[6..8], .little),
        });
    }

    inline fn expandKey(self: *Self, key: [4]u16) void {
        const mod_mask: u16 = 0xFFFF;
        const round_constant: u16 = mod_mask ^ 3;

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
                var tmp = std.math.rotr(u16, self.round_keys[idx - 1], 3);
                tmp = tmp ^ self.round_keys[idx - 3];
                tmp = tmp ^ std.math.rotr(u16, tmp, 1);
                const z_bit: u16 = @intCast((z0 >> @as(u6, @intCast((idx - 4) % 62))) & 1);
                self.round_keys[idx] = round_constant ^ z_bit ^ tmp ^ self.round_keys[idx - 4];
            }
            i += unroll_factor;
        }

        inline for (0..remainder) |j| {
            const idx = i + j;
            var tmp = std.math.rotr(u16, self.round_keys[idx - 1], 3);
            tmp = tmp ^ self.round_keys[idx - 3];
            tmp = tmp ^ std.math.rotr(u16, tmp, 1);
            const z_bit: u16 = @intCast((z0 >> @as(u6, @intCast((idx - 4) % 62))) & 1);
            self.round_keys[idx] = round_constant ^ z_bit ^ tmp ^ self.round_keys[idx - 4];
        }
    }

    pub inline fn encrypt(self: *const Self, plaintext: [2]u16) [2]u16 {
        var x = plaintext[0];
        var y = plaintext[1];

        const unroll_factor = 4;
        const unrolled_iterations = rounds / unroll_factor;
        const remainder = rounds % unroll_factor;

        var i: usize = 0;
        inline for (0..unrolled_iterations) |_| {
            inline for (0..unroll_factor) |j| {
                const tmp = x;
                const f = (std.math.rotl(u16, x, 1) & std.math.rotl(u16, x, 8)) ^ std.math.rotl(u16, x, 2);
                x = y ^ f ^ self.round_keys[i + j];
                y = tmp;
            }
            i += unroll_factor;
        }

        inline for (0..remainder) |j| {
            const tmp = x;
            const f = (std.math.rotl(u16, x, 1) & std.math.rotl(u16, x, 8)) ^ std.math.rotl(u16, x, 2);
            x = y ^ f ^ self.round_keys[i + j];
            y = tmp;
        }

        return .{ x, y };
    }

    pub inline fn decrypt(self: *const Self, ciphertext: [2]u16) [2]u16 {
        var x = ciphertext[0];
        var y = ciphertext[1];

        const unroll_factor = 4;
        const unrolled_iterations = rounds / unroll_factor;
        const remainder = rounds % unroll_factor;

        var i: usize = rounds;

        inline for (0..remainder) |j| {
            i -= 1;
            const tmp = y;
            const f = (std.math.rotl(u16, y, 1) & std.math.rotl(u16, y, 8)) ^ std.math.rotl(u16, y, 2);
            y = x ^ f ^ self.round_keys[i];
            x = tmp;
            _ = j;
        }

        inline for (0..unrolled_iterations) |_| {
            inline for (0..unroll_factor) |_| {
                i -= 1;
                const tmp = y;
                const f = (std.math.rotl(u16, y, 1) & std.math.rotl(u16, y, 8)) ^ std.math.rotl(u16, y, 2);
                y = x ^ f ^ self.round_keys[i];
                x = tmp;
            }
        }

        return .{ x, y };
    }

    pub inline fn encryptBlock(self: *const Self, block: [4]u8) [4]u8 {
        const plaintext: [2]u16 = .{
            @bitCast(block[0..2].*),
            @bitCast(block[2..4].*),
        };

        const ciphertext = self.encrypt(plaintext);

        return @bitCast([_]u16{ ciphertext[0], ciphertext[1] });
    }

    pub inline fn decryptBlock(self: *const Self, block: [4]u8) [4]u8 {
        const ciphertext: [2]u16 = .{
            @bitCast(block[0..2].*),
            @bitCast(block[2..4].*),
        };

        const plaintext = self.decrypt(ciphertext);

        return @bitCast([_]u16{ plaintext[0], plaintext[1] });
    }
};

test "Simon32 basic roundtrip" {
    const key: [4]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918 };
    const plaintext: [2]u16 = .{ 0x6574, 0x694c };

    const cipher = Simon32.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}

test "Simon32 block roundtrip" {
    const key: [4]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918 };
    const plaintext_bytes: [4]u8 = .{ 0x74, 0x65, 0x4c, 0x69 };

    const cipher = Simon32.init(key);
    const ciphertext_bytes = cipher.encryptBlock(plaintext_bytes);
    const decrypted_bytes = cipher.decryptBlock(ciphertext_bytes);

    try std.testing.expectEqualSlices(u8, &plaintext_bytes, &decrypted_bytes);
}
