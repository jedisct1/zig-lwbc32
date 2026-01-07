const std = @import("std");

pub const Simeck64 = struct {
    round_keys: [44]u32,

    const Self = @This();
    const rounds = 44;
    const constant: u64 = 0x9A42BB1F9A42BB1F;

    pub fn init(key: [4]u32) Self {
        var cipher = Self{ .round_keys = undefined };
        cipher.expandKey(key);
        return cipher;
    }

    inline fn expandKey(self: *Self, key: [4]u32) void {
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
                const shift_amount: u6 = @intCast((i - 4) % 62);
                const c: u32 = @intCast((constant >> shift_amount) & 1);
                const t = (c ^ @as(u32, 0xfffffffc)) ^ self.round_keys[i - 4];
                const tmp = std.math.rotl(u32, self.round_keys[i - 1], 5);
                self.round_keys[i] = t ^ tmp ^ self.round_keys[i - 3];
                i += 1;
            }
        }

        inline for (0..remainder) |_| {
            const shift_amount: u6 = @intCast((i - 4) % 62);
            const c: u32 = @intCast((constant >> shift_amount) & 1);
            const t = (c ^ @as(u32, 0xfffffffc)) ^ self.round_keys[i - 4];
            const tmp = std.math.rotl(u32, self.round_keys[i - 1], 5);
            self.round_keys[i] = t ^ tmp ^ self.round_keys[i - 3];
            i += 1;
        }
    }

    pub inline fn encrypt(self: *const Self, plaintext: [2]u32) [2]u32 {
        @setEvalBranchQuota(10000);
        var l = plaintext[0];
        var r = plaintext[1];

        const unroll_factor = 4;
        const unrolled = rounds / unroll_factor;

        inline for (0..unrolled) |i| {
            const base = i * unroll_factor;

            inline for (0..unroll_factor) |j| {
                const tmp = l;
                l = r ^ ((l & std.math.rotl(u32, l, 5)) ^ std.math.rotl(u32, l, 1)) ^ self.round_keys[base + j];
                r = tmp;
            }
        }

        return .{ l, r };
    }

    pub inline fn decrypt(self: *const Self, ciphertext: [2]u32) [2]u32 {
        var l = ciphertext[0];
        var r = ciphertext[1];

        const unroll_factor = 4;
        const unrolled = rounds / unroll_factor;

        inline for (0..unrolled) |j| {
            const base = rounds - (j + 1) * unroll_factor;

            inline for (0..unroll_factor) |k| {
                const idx = base + (unroll_factor - 1 - k);
                const tmp = r;
                r = l ^ ((r & std.math.rotl(u32, r, 5)) ^ std.math.rotl(u32, r, 1)) ^ self.round_keys[idx];
                l = tmp;
            }
        }

        return .{ l, r };
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

test "Simeck64 basic roundtrip" {
    const key: [4]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
    const plaintext: [2]u32 = .{ 0x656b696c, 0x20646e75 };

    const cipher = Simeck64.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}

test "Simeck64 block roundtrip" {
    const key: [4]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
    const plaintext_bytes: [8]u8 = .{ 0x75, 0x6e, 0x64, 0x20, 0x6c, 0x69, 0x6b, 0x65 };

    const cipher = Simeck64.init(key);
    const ciphertext_bytes = cipher.encryptBlock(plaintext_bytes);
    const decrypted_bytes = cipher.decryptBlock(ciphertext_bytes);

    try std.testing.expectEqualSlices(u8, &plaintext_bytes, &decrypted_bytes);
}
