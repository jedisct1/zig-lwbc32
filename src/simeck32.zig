const std = @import("std");

pub const Simeck32 = struct {
    round_keys: [32]u16,

    const Self = @This();
    const rounds = 32;
    const constant: u32 = 0x9A42BB1F;

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
        self.round_keys[0] = key[0];
        self.round_keys[1] = key[1];
        self.round_keys[2] = key[2];
        self.round_keys[3] = key[3];

        const unroll_factor = 4;
        const unrolled = (rounds - 4) / unroll_factor;
        const remainder = (rounds - 4) % unroll_factor;

        var i: usize = 4;
        inline for (0..unrolled) |_| {
            inline for (0..unroll_factor) |_| {
                const shift_amount: u5 = @intCast((i - 4) % 31);
                const c: u16 = @intCast((constant >> shift_amount) & 1);
                const t = (c ^ @as(u16, 0xfffc)) ^ self.round_keys[i - 4];
                const tmp = std.math.rotl(u16, self.round_keys[i - 1], 5);
                self.round_keys[i] = t ^ tmp ^ self.round_keys[i - 3];
                i += 1;
            }
        }

        inline for (0..remainder) |_| {
            const shift_amount: u5 = @intCast((i - 4) % 31);
            const c: u16 = @intCast((constant >> shift_amount) & 1);
            const t = (c ^ @as(u16, 0xfffc)) ^ self.round_keys[i - 4];
            const tmp = std.math.rotl(u16, self.round_keys[i - 1], 5);
            self.round_keys[i] = t ^ tmp ^ self.round_keys[i - 3];
            i += 1;
        }
    }

    pub inline fn encrypt(self: *const Self, plaintext: [2]u16) [2]u16 {
        @setEvalBranchQuota(10000);
        var l = plaintext[0];
        var r = plaintext[1];

        const unroll_factor = 4;
        const unrolled = rounds / unroll_factor;

        inline for (0..unrolled) |i| {
            const base = i * unroll_factor;

            inline for (0..unroll_factor) |j| {
                const tmp = l;
                l = r ^ ((l & std.math.rotl(u16, l, 5)) ^ std.math.rotl(u16, l, 1)) ^ self.round_keys[base + j];
                r = tmp;
            }
        }

        return .{ l, r };
    }

    pub inline fn decrypt(self: *const Self, ciphertext: [2]u16) [2]u16 {
        var l = ciphertext[0];
        var r = ciphertext[1];

        const unroll_factor = 4;
        const unrolled = rounds / unroll_factor;

        inline for (0..unrolled) |j| {
            const base = rounds - (j + 1) * unroll_factor;

            inline for (0..unroll_factor) |k| {
                const idx = base + (unroll_factor - 1 - k);
                const tmp = r;
                r = l ^ ((r & std.math.rotl(u16, r, 5)) ^ std.math.rotl(u16, r, 1)) ^ self.round_keys[idx];
                l = tmp;
            }
        }

        return .{ l, r };
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

test "Simeck32 basic roundtrip" {
    const key: [4]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918 };
    const plaintext: [2]u16 = .{ 0x6574, 0x694c };

    const cipher = Simeck32.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}

test "Simeck32 block roundtrip" {
    const key: [4]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918 };
    const plaintext_bytes: [4]u8 = .{ 0x74, 0x65, 0x4c, 0x69 };

    const cipher = Simeck32.init(key);
    const ciphertext_bytes = cipher.encryptBlock(plaintext_bytes);
    const decrypted_bytes = cipher.decryptBlock(ciphertext_bytes);

    try std.testing.expectEqualSlices(u8, &plaintext_bytes, &decrypted_bytes);
}
