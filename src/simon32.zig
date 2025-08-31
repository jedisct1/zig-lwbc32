const std = @import("std");

inline fn rotateLeft(comptime T: type, x: T, n: anytype) T {
    return std.math.rotl(T, x, n);
}

inline fn rotateRight(comptime T: type, x: T, n: anytype) T {
    return std.math.rotr(T, x, n);
}

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

    fn expandKey(self: *Self, key: [4]u16) void {
        const mod_mask: u16 = 0xFFFF; // 2^16 - 1
        const round_constant: u16 = mod_mask ^ 3; // 0xFFFC

        // Initialize key register like reference implementation
        // Key 0x1918111009080100 -> k_reg = [0x1918, 0x1110, 0x0908, 0x0100]
        var k_reg: [4]u16 = .{ key[3], key[2], key[1], key[0] };

        // Generate all 32 round keys
        var x: usize = 0;
        while (x < rounds) : (x += 1) {
            // Right rotate k_reg[0] by 3
            var rs_3 = rotateRight(u16, k_reg[0], 3);

            // For m=4, XOR with k_reg[2]
            rs_3 = rs_3 ^ k_reg[2];

            // Right rotate rs_3 by 1
            const rs_1 = rotateRight(u16, rs_3, 1);

            // Get z bit and calculate c_z
            const z_bit: u16 = @intCast((z0 >> @as(u6, @intCast(x % 62))) & 1);
            const c_z = z_bit ^ round_constant;

            // Calculate new key
            const new_k = c_z ^ rs_1 ^ rs_3 ^ k_reg[3];

            // Store the key being shifted out (k_reg[3]) as the round key
            self.round_keys[x] = k_reg[3];

            // Shift keys right and insert new key at position 0
            k_reg[3] = k_reg[2];
            k_reg[2] = k_reg[1];
            k_reg[1] = k_reg[0];
            k_reg[0] = new_k;
        }
    }

    fn f(x: u16) u16 {
        return (rotateLeft(u16, x, 1) & rotateLeft(u16, x, 8)) ^ rotateLeft(u16, x, 2);
    }

    pub fn encrypt(self: *const Self, plaintext: [2]u16) [2]u16 {
        var x = plaintext[0]; // Upper word (MSB)
        var y = plaintext[1]; // Lower word (LSB)

        var i: usize = 0;
        while (i < rounds) : (i += 1) {
            // Generate all circular shifts
            const ls_1_x = rotateLeft(u16, x, 1);
            const ls_8_x = rotateLeft(u16, x, 8);
            const ls_2_x = rotateLeft(u16, x, 2);

            // XOR Chain
            const xor_1 = (ls_1_x & ls_8_x) ^ y;
            const xor_2 = xor_1 ^ ls_2_x;
            const new_x = self.round_keys[i] ^ xor_2;

            y = x;
            x = new_x;
        }

        return .{ x, y }; // Return as [MSB, LSB]
    }

    pub fn decrypt(self: *const Self, ciphertext: [2]u16) [2]u16 {
        // Start with swapped words like reference implementation
        var x = ciphertext[1]; // Lower word becomes x
        var y = ciphertext[0]; // Upper word becomes y

        var i: usize = rounds;
        while (i > 0) {
            i -= 1;
            // Generate all circular shifts
            const ls_1_x = rotateLeft(u16, x, 1);
            const ls_8_x = rotateLeft(u16, x, 8);
            const ls_2_x = rotateLeft(u16, x, 2);

            // XOR Chain (same as encryption)
            const xor_1 = (ls_1_x & ls_8_x) ^ y;
            const xor_2 = xor_1 ^ ls_2_x;
            const new_x = self.round_keys[i] ^ xor_2;

            y = x;
            x = new_x;
        }

        return .{ y, x }; // Return swapped back
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
