const std = @import("std");

pub const Crax = struct {
    key: [4]u32,

    const Self = @This();
    const steps = 10;
    const rcon: [5]u32 = .{ 0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, 0xBB1185EB };

    pub fn init(key: [4]u32) Self {
        return .{ .key = key };
    }

    pub fn fromBytes(key: [16]u8) Self {
        return init(.{
            std.mem.readInt(u32, key[0..4], .little),
            std.mem.readInt(u32, key[4..8], .little),
            std.mem.readInt(u32, key[8..12], .little),
            std.mem.readInt(u32, key[12..16], .little),
        });
    }

    inline fn alzette(x: u32, y: u32, c: u32) [2]u32 {
        var xv = x;
        var yv = y;
        xv = xv +% std.math.rotr(u32, yv, 31);
        yv ^= std.math.rotr(u32, xv, 24);
        xv ^= c;
        xv = xv +% std.math.rotr(u32, yv, 17);
        yv ^= std.math.rotr(u32, xv, 17);
        xv ^= c;
        xv = xv +% yv;
        yv ^= std.math.rotr(u32, xv, 31);
        xv ^= c;
        xv = xv +% std.math.rotr(u32, yv, 24);
        yv ^= std.math.rotr(u32, xv, 16);
        xv ^= c;
        return .{ xv, yv };
    }

    inline fn alzetteInv(x: u32, y: u32, c: u32) [2]u32 {
        var xv = x;
        var yv = y;
        xv ^= c;
        yv ^= std.math.rotr(u32, xv, 16);
        xv = xv -% std.math.rotr(u32, yv, 24);
        xv ^= c;
        yv ^= std.math.rotr(u32, xv, 31);
        xv = xv -% yv;
        xv ^= c;
        yv ^= std.math.rotr(u32, xv, 17);
        xv = xv -% std.math.rotr(u32, yv, 17);
        xv ^= c;
        yv ^= std.math.rotr(u32, xv, 24);
        xv = xv -% std.math.rotr(u32, yv, 31);
        return .{ xv, yv };
    }

    pub inline fn encrypt(self: *const Self, plaintext: [2]u32) [2]u32 {
        var x = plaintext[0];
        var y = plaintext[1];
        const k = [2][2]u32{ .{ self.key[0], self.key[1] }, .{ self.key[2], self.key[3] } };

        inline for (0..steps) |s| {
            x ^= @as(u32, s);
            x ^= k[s % 2][0];
            y ^= k[s % 2][1];
            const r = alzette(x, y, rcon[s % 5]);
            x = r[0];
            y = r[1];
        }

        x ^= k[0][0];
        y ^= k[0][1];

        return .{ x, y };
    }

    pub inline fn decrypt(self: *const Self, ciphertext: [2]u32) [2]u32 {
        var x = ciphertext[0];
        var y = ciphertext[1];
        const k = [2][2]u32{ .{ self.key[0], self.key[1] }, .{ self.key[2], self.key[3] } };

        x ^= k[0][0];
        y ^= k[0][1];

        inline for (0..steps) |j| {
            const s = steps - 1 - j;
            const r = alzetteInv(x, y, rcon[s % 5]);
            x = r[0];
            y = r[1];
            x ^= k[s % 2][0];
            y ^= k[s % 2][1];
            x ^= @as(u32, s);
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

test "CRAX basic roundtrip" {
    const key: [4]u32 = .{ 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c };
    const plaintext: [2]u32 = .{ 0x33221100, 0x77665544 };

    const cipher = Crax.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext, decrypted);
}

test "CRAX test vector" {
    const key: [4]u32 = .{ 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c };
    const plaintext: [2]u32 = .{ 0x33221100, 0x77665544 };
    const expected: [2]u32 = .{ 0x6203c5be, 0x7ae77255 };

    const cipher = Crax.init(key);
    const ciphertext = cipher.encrypt(plaintext);

    try std.testing.expectEqual(expected, ciphertext);
}

test "CRAX zero key test vector" {
    const key: [4]u32 = .{ 0, 0, 0, 0 };
    const plaintext: [2]u32 = .{ 0, 0 };
    const expected: [2]u32 = .{ 0x72edfac9, 0x453f5f4c };

    const cipher = Crax.init(key);
    const ciphertext = cipher.encrypt(plaintext);

    try std.testing.expectEqual(expected, ciphertext);
}

test "CRAX block roundtrip" {
    const key: [4]u32 = .{ 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c };
    const plaintext_bytes: [8]u8 = .{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

    const cipher = Crax.init(key);
    const ciphertext_bytes = cipher.encryptBlock(plaintext_bytes);
    const decrypted_bytes = cipher.decryptBlock(ciphertext_bytes);

    try std.testing.expectEqualSlices(u8, &plaintext_bytes, &decrypted_bytes);
}

test "CRAX fromBytes" {
    const key_bytes: [16]u8 = .{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const key_words: [4]u32 = .{ 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c };
    const plaintext: [2]u32 = .{ 0x33221100, 0x77665544 };

    const cipher_bytes = Crax.fromBytes(key_bytes);
    const cipher_words = Crax.init(key_words);

    try std.testing.expectEqual(cipher_words.encrypt(plaintext), cipher_bytes.encrypt(plaintext));
}
