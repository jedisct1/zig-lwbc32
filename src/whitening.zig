const std = @import("std");
const Speck32 = @import("speck32.zig").Speck32;
const Speck48 = @import("speck48.zig").Speck48;
const Speck64 = @import("speck64.zig").Speck64;
const Simon32 = @import("simon32.zig").Simon32;
const Simon48 = @import("simon48.zig").Simon48;
const Simon64 = @import("simon64.zig").Simon64;
const Simeck32 = @import("simeck32.zig").Simeck32;
const Simeck64 = @import("simeck64.zig").Simeck64;

fn Whitened(comptime BaseCipher: type, comptime Word: type, comptime block_bytes: usize) type {
    return struct {
        cipher: BaseCipher,
        pre_key: [2]Word,
        post_key: [2]Word,

        const Self = @This();
        const word_bytes = @divExact(@bitSizeOf(Word), 8);
        const key_bytes = 8 * word_bytes;

        pub fn init(key: [8]Word) Self {
            return .{
                .cipher = BaseCipher.init(key[0..4].*),
                .pre_key = key[4..6].*,
                .post_key = key[6..8].*,
            };
        }

        pub fn fromBytes(key: [key_bytes]u8) Self {
            var words: [8]Word = undefined;
            inline for (0..8) |i| {
                const start = i * word_bytes;
                words[i] = std.mem.readInt(Word, key[start..][0..word_bytes], .little);
            }
            return init(words);
        }

        pub inline fn encrypt(self: *const Self, plaintext: [2]Word) [2]Word {
            const whitened: [2]Word = .{
                plaintext[0] ^ self.pre_key[0],
                plaintext[1] ^ self.pre_key[1],
            };
            const encrypted = self.cipher.encrypt(whitened);
            return .{
                encrypted[0] ^ self.post_key[0],
                encrypted[1] ^ self.post_key[1],
            };
        }

        pub inline fn decrypt(self: *const Self, ciphertext: [2]Word) [2]Word {
            const unwhitened: [2]Word = .{
                ciphertext[0] ^ self.post_key[0],
                ciphertext[1] ^ self.post_key[1],
            };
            const decrypted = self.cipher.decrypt(unwhitened);
            return .{
                decrypted[0] ^ self.pre_key[0],
                decrypted[1] ^ self.pre_key[1],
            };
        }

        pub inline fn encryptBlock(self: *const Self, block: [block_bytes]u8) [block_bytes]u8 {
            const plaintext: [2]Word = .{
                std.mem.readInt(Word, block[0..word_bytes], .little),
                std.mem.readInt(Word, block[word_bytes..block_bytes], .little),
            };
            const ciphertext = self.encrypt(plaintext);
            var result: [block_bytes]u8 = undefined;
            std.mem.writeInt(Word, result[0..word_bytes], ciphertext[0], .little);
            std.mem.writeInt(Word, result[word_bytes..block_bytes], ciphertext[1], .little);
            return result;
        }

        pub inline fn decryptBlock(self: *const Self, block: [block_bytes]u8) [block_bytes]u8 {
            const ciphertext: [2]Word = .{
                std.mem.readInt(Word, block[0..word_bytes], .little),
                std.mem.readInt(Word, block[word_bytes..block_bytes], .little),
            };
            const plaintext = self.decrypt(ciphertext);
            var result: [block_bytes]u8 = undefined;
            std.mem.writeInt(Word, result[0..word_bytes], plaintext[0], .little);
            std.mem.writeInt(Word, result[word_bytes..block_bytes], plaintext[1], .little);
            return result;
        }
    };
}

pub const Speck32Whitened = Whitened(Speck32, u16, 4);
pub const Speck48Whitened = Whitened(Speck48, u24, 6);
pub const Speck64Whitened = Whitened(Speck64, u32, 8);
pub const Simon32Whitened = Whitened(Simon32, u16, 4);
pub const Simon48Whitened = Whitened(Simon48, u24, 6);
pub const Simon64Whitened = Whitened(Simon64, u32, 8);
pub const Simeck32Whitened = Whitened(Simeck32, u16, 4);
pub const Simeck64Whitened = Whitened(Simeck64, u32, 8);

test "Speck32Whitened roundtrip" {
    const key: [8]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918, 0xdead, 0xbeef, 0xcafe, 0xbabe };
    const plaintext: [2]u16 = .{ 0x6574, 0x694c };

    const cipher = Speck32Whitened.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext, decrypted);
}

test "Speck48Whitened roundtrip" {
    const key: [8]u24 = .{ 0x020100, 0x0a0908, 0x121110, 0x1a1918, 0xdeadbe, 0xcafeba, 0x123456, 0x9abcde };
    const plaintext: [2]u24 = .{ 0x6d2073, 0x696874 };

    const cipher = Speck48Whitened.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext, decrypted);
}

test "Speck64Whitened roundtrip" {
    const key: [8]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918, 0xdeadbeef, 0xcafebabe, 0x12345678, 0x9abcdef0 };
    const plaintext: [2]u32 = .{ 0x3b726574, 0x7475432d };

    const cipher = Speck64Whitened.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext, decrypted);
}

test "Simon32Whitened roundtrip" {
    const key: [8]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918, 0x1234, 0x5678, 0xabcd, 0xef01 };
    const plaintext: [2]u16 = .{ 0x6565, 0x6877 };

    const cipher = Simon32Whitened.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext, decrypted);
}

test "Simon48Whitened roundtrip" {
    const key: [8]u24 = .{ 0x020100, 0x0a0908, 0x121110, 0x1a1918, 0xdeadbe, 0xcafeba, 0x123456, 0x9abcde };
    const plaintext: [2]u24 = .{ 0x726963, 0x20646e };

    const cipher = Simon48Whitened.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext, decrypted);
}

test "Simon64Whitened roundtrip" {
    const key: [8]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918, 0xaaaabbbb, 0xccccdddd, 0xeeee1111, 0x22223333 };
    const plaintext: [2]u32 = .{ 0x656b696c, 0x20646e75 };

    const cipher = Simon64Whitened.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext, decrypted);
}

test "Simeck32Whitened roundtrip" {
    const key: [8]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918, 0xfeed, 0xface, 0xdead, 0xc0de };
    const plaintext: [2]u16 = .{ 0x6877, 0x6565 };

    const cipher = Simeck32Whitened.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext, decrypted);
}

test "Simeck64Whitened roundtrip" {
    const key: [8]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918, 0x11111111, 0x22222222, 0x33333333, 0x44444444 };
    const plaintext: [2]u32 = .{ 0x656b696c, 0x20646e75 };

    const cipher = Simeck64Whitened.init(key);
    const ciphertext = cipher.encrypt(plaintext);
    const decrypted = cipher.decrypt(ciphertext);

    try std.testing.expectEqual(plaintext, decrypted);
}

test "Speck32Whitened block roundtrip" {
    const key: [8]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918, 0xdead, 0xbeef, 0xcafe, 0xbabe };
    const plaintext_bytes: [4]u8 = .{ 0x74, 0x65, 0x4c, 0x69 };

    const cipher = Speck32Whitened.init(key);
    const ciphertext_bytes = cipher.encryptBlock(plaintext_bytes);
    const decrypted_bytes = cipher.decryptBlock(ciphertext_bytes);

    try std.testing.expectEqualSlices(u8, &plaintext_bytes, &decrypted_bytes);
}

test "Speck64Whitened block roundtrip" {
    const key: [8]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918, 0xdeadbeef, 0xcafebabe, 0x12345678, 0x9abcdef0 };
    const plaintext_bytes: [8]u8 = .{ 0x74, 0x65, 0x72, 0x3b, 0x2d, 0x43, 0x75, 0x74 };

    const cipher = Speck64Whitened.init(key);
    const ciphertext_bytes = cipher.encryptBlock(plaintext_bytes);
    const decrypted_bytes = cipher.decryptBlock(ciphertext_bytes);

    try std.testing.expectEqualSlices(u8, &plaintext_bytes, &decrypted_bytes);
}

test "Speck48Whitened block roundtrip" {
    const key: [8]u24 = .{ 0x020100, 0x0a0908, 0x121110, 0x1a1918, 0xdeadbe, 0xcafeba, 0x123456, 0x9abcde };
    const plaintext_bytes: [6]u8 = .{ 0x73, 0x20, 0x6d, 0x74, 0x68, 0x69 };

    const cipher = Speck48Whitened.init(key);
    const ciphertext_bytes = cipher.encryptBlock(plaintext_bytes);
    const decrypted_bytes = cipher.decryptBlock(ciphertext_bytes);

    try std.testing.expectEqualSlices(u8, &plaintext_bytes, &decrypted_bytes);
}

test "whitening changes ciphertext" {
    const base_key: [4]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918 };
    const whitening_key: [8]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918, 0xdead, 0xbeef, 0xcafe, 0xbabe };
    const plaintext: [2]u16 = .{ 0x6574, 0x694c };

    const base_cipher = Speck32.init(base_key);
    const whitened_cipher = Speck32Whitened.init(whitening_key);

    const base_ciphertext = base_cipher.encrypt(plaintext);
    const whitened_ciphertext = whitened_cipher.encrypt(plaintext);

    try std.testing.expect(base_ciphertext[0] != whitened_ciphertext[0] or base_ciphertext[1] != whitened_ciphertext[1]);
}

test "Speck32Whitened fromBytes" {
    const key_bytes: [16]u8 = .{ 0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19, 0xad, 0xde, 0xef, 0xbe, 0xfe, 0xca, 0xbe, 0xba };
    const key_words: [8]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918, 0xdead, 0xbeef, 0xcafe, 0xbabe };
    const plaintext: [2]u16 = .{ 0x6574, 0x694c };

    const cipher_bytes = Speck32Whitened.fromBytes(key_bytes);
    const cipher_words = Speck32Whitened.init(key_words);

    try std.testing.expectEqual(cipher_words.encrypt(plaintext), cipher_bytes.encrypt(plaintext));
}

test "Speck48Whitened fromBytes" {
    const key_bytes: [24]u8 = .{
        0x00, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x10, 0x11, 0x12, 0x18, 0x19, 0x1a,
        0xbe, 0xad, 0xde, 0xba, 0xfe, 0xca, 0x56, 0x34, 0x12, 0xde, 0xbc, 0x9a,
    };
    const key_words: [8]u24 = .{ 0x020100, 0x0a0908, 0x121110, 0x1a1918, 0xdeadbe, 0xcafeba, 0x123456, 0x9abcde };
    const plaintext: [2]u24 = .{ 0x6d2073, 0x696874 };

    const cipher_bytes = Speck48Whitened.fromBytes(key_bytes);
    const cipher_words = Speck48Whitened.init(key_words);

    try std.testing.expectEqual(cipher_words.encrypt(plaintext), cipher_bytes.encrypt(plaintext));
}

test "Speck64Whitened fromBytes" {
    const key_bytes: [32]u8 = .{
        0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b,
        0xef, 0xbe, 0xad, 0xde, 0xbe, 0xba, 0xfe, 0xca, 0x78, 0x56, 0x34, 0x12, 0xf0, 0xde, 0xbc, 0x9a,
    };
    const key_words: [8]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918, 0xdeadbeef, 0xcafebabe, 0x12345678, 0x9abcdef0 };
    const plaintext: [2]u32 = .{ 0x3b726574, 0x7475432d };

    const cipher_bytes = Speck64Whitened.fromBytes(key_bytes);
    const cipher_words = Speck64Whitened.init(key_words);

    try std.testing.expectEqual(cipher_words.encrypt(plaintext), cipher_bytes.encrypt(plaintext));
}
