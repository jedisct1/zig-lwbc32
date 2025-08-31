const std = @import("std");

inline fn rotateLeft(comptime T: type, x: T, n: anytype) T {
    return std.math.rotl(T, x, n);
}

inline fn rotateRight(comptime T: type, x: T, n: anytype) T {
    return std.math.rotr(T, x, n);
}

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

    fn expandKey(self: *Self, key: [4]u16) void {
        self.round_keys[0] = key[0];
        self.round_keys[1] = key[1];
        self.round_keys[2] = key[2];
        self.round_keys[3] = key[3];

        var i: usize = 4;
        while (i < rounds) : (i += 1) {
            const shift_amount: u5 = @intCast((i - 4) % 31);
            const c: u16 = @intCast((constant >> shift_amount) & 1);
            const t = (c ^ @as(u16, 0xfffc)) ^ self.round_keys[i - 4];
            const tmp = rotateLeft(u16, self.round_keys[i - 1], 5);
            self.round_keys[i] = t ^ tmp ^ self.round_keys[i - 3];
        }
    }

    fn f(x: u16) u16 {
        return (x & rotateLeft(u16, x, 5)) ^ rotateLeft(u16, x, 1);
    }

    pub fn encrypt(self: *const Self, plaintext: [2]u16) [2]u16 {
        var l = plaintext[0]; // Left half
        var r = plaintext[1]; // Right half

        var i: usize = 0;
        while (i < rounds) : (i += 1) {
            const tmp = l;
            l = r ^ f(l) ^ self.round_keys[i];
            r = tmp;
        }

        return .{ l, r };
    }

    pub fn decrypt(self: *const Self, ciphertext: [2]u16) [2]u16 {
        var l = ciphertext[0]; // Left half
        var r = ciphertext[1]; // Right half

        var i: usize = rounds;
        while (i > 0) {
            i -= 1;
            const tmp = r;
            r = l ^ f(r) ^ self.round_keys[i];
            l = tmp;
        }

        return .{ l, r };
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
