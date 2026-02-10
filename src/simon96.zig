const std = @import("std");

pub const Simon96 = struct {
    round_keys: [54]u48,

    const Self = @This();
    const rounds = 54;
    const z3: u64 = 0b11110000101100111001010001001000000111101001100011010111011011;

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
        const round_constant: u48 = 0xFFFFFFFFFFFF ^ 3;

        self.round_keys[0] = key[0];
        self.round_keys[1] = key[1];
        self.round_keys[2] = key[2];

        const unroll_factor = 3;
        const unrolled_iterations = (rounds - 3) / unroll_factor;
        const remainder = (rounds - 3) % unroll_factor;

        var i: usize = 3;
        inline for (0..unrolled_iterations) |_| {
            inline for (0..unroll_factor) |j| {
                const idx = i + j;
                var tmp = std.math.rotr(u48, self.round_keys[idx - 1], 3);
                tmp = tmp ^ std.math.rotr(u48, tmp, 1);
                const z_bit: u48 = @intCast((z3 >> @as(u6, @intCast((idx - 3) % 62))) & 1);
                self.round_keys[idx] = round_constant ^ z_bit ^ tmp ^ self.round_keys[idx - 3];
            }
            i += unroll_factor;
        }

        inline for (0..remainder) |j| {
            const idx = i + j;
            var tmp = std.math.rotr(u48, self.round_keys[idx - 1], 3);
            tmp = tmp ^ std.math.rotr(u48, tmp, 1);
            const z_bit: u48 = @intCast((z3 >> @as(u6, @intCast((idx - 3) % 62))) & 1);
            self.round_keys[idx] = round_constant ^ z_bit ^ tmp ^ self.round_keys[idx - 3];
        }
    }

    pub inline fn encrypt(self: *const Self, plaintext: [2]u48) [2]u48 {
        var x = plaintext[0];
        var y = plaintext[1];

        const unroll_factor = 3;
        const unrolled_iterations = rounds / unroll_factor;
        const remainder = rounds % unroll_factor;

        var i: usize = 0;
        inline for (0..unrolled_iterations) |_| {
            inline for (0..unroll_factor) |j| {
                const tmp = x;
                const f = (std.math.rotl(u48, x, 1) & std.math.rotl(u48, x, 8)) ^ std.math.rotl(u48, x, 2);
                x = y ^ f ^ self.round_keys[i + j];
                y = tmp;
            }
            i += unroll_factor;
        }

        inline for (0..remainder) |j| {
            const tmp = x;
            const f = (std.math.rotl(u48, x, 1) & std.math.rotl(u48, x, 8)) ^ std.math.rotl(u48, x, 2);
            x = y ^ f ^ self.round_keys[i + j];
            y = tmp;
        }

        return .{ x, y };
    }

    pub inline fn decrypt(self: *const Self, ciphertext: [2]u48) [2]u48 {
        var x = ciphertext[0];
        var y = ciphertext[1];

        const unroll_factor = 3;
        const unrolled_iterations = rounds / unroll_factor;
        const remainder = rounds % unroll_factor;

        var i: usize = rounds;

        inline for (0..remainder) |j| {
            i -= 1;
            const tmp = y;
            const f = (std.math.rotl(u48, y, 1) & std.math.rotl(u48, y, 8)) ^ std.math.rotl(u48, y, 2);
            y = x ^ f ^ self.round_keys[i];
            x = tmp;
            _ = j;
        }

        inline for (0..unrolled_iterations) |_| {
            inline for (0..unroll_factor) |_| {
                i -= 1;
                const tmp = y;
                const f = (std.math.rotl(u48, y, 1) & std.math.rotl(u48, y, 8)) ^ std.math.rotl(u48, y, 2);
                y = x ^ f ^ self.round_keys[i];
                x = tmp;
            }
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

test "Simon96 basic roundtrip" {
    const key: [3]u48 = .{ 0x050403020100, 0x0d0c0b0a0908, 0x151413121110 };
    const plaintext: [2]u48 = .{ 0x746168742074, 0x73756420666f };

    const cipher = Simon96.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}

test "Simon96 block roundtrip" {
    const key: [3]u48 = .{ 0x050403020100, 0x0d0c0b0a0908, 0x151413121110 };
    const plaintext_bytes: [12]u8 = .{ 0x74, 0x20, 0x74, 0x68, 0x61, 0x74, 0x6f, 0x66, 0x20, 0x64, 0x75, 0x73 };

    const cipher = Simon96.init(key);
    const ciphertext_bytes = cipher.encryptBlock(plaintext_bytes);
    const decrypted_bytes = cipher.decryptBlock(ciphertext_bytes);

    try std.testing.expectEqualSlices(u8, &plaintext_bytes, &decrypted_bytes);
}

test "Simon96 fromBytes" {
    const key_bytes: [18]u8 = .{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 };
    const key_words: [3]u48 = .{ 0x050403020100, 0x0d0c0b0a0908, 0x151413121110 };
    const plaintext: [2]u48 = .{ 0x746168742074, 0x73756420666f };

    const cipher_bytes = Simon96.fromBytes(key_bytes);
    const cipher_words = Simon96.init(key_words);

    try std.testing.expectEqual(cipher_words.encrypt(plaintext), cipher_bytes.encrypt(plaintext));
}

test "Simon96 official test vector" {
    const key: [3]u48 = .{ 0x050403020100, 0x0d0c0b0a0908, 0x151413121110 };
    const plaintext: [2]u48 = .{ 0x746168742074, 0x73756420666f };
    const expected: [2]u48 = .{ 0xecad1c6c451e, 0x3f59c5db1ae9 };

    const cipher = Simon96.init(key);
    const ciphertext = cipher.encrypt(plaintext);

    try std.testing.expectEqual(expected[0], ciphertext[0]);
    try std.testing.expectEqual(expected[1], ciphertext[1]);

    const decrypted = cipher.decrypt(ciphertext);
    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}
