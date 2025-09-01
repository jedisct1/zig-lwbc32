const std = @import("std");

const speck32 = @import("speck32.zig");
const simon32 = @import("simon32.zig");
const simeck32 = @import("simeck32.zig");

const Speck32 = speck32.Speck32;
const Simon32 = simon32.Simon32;
const Simeck32 = simeck32.Simeck32;

test "SPECK32/64 official test vector" {
    // Official test vector from NSA paper
    // Key: 0x1918111009080100 (little-endian: 0x0100, 0x0908, 0x1110, 0x1918)
    // Plaintext: ASCII "Lite" = 0x4c69 7465 (little-endian: 0x6574, 0x694c)
    // Expected ciphertext: 0xa86842f2 (little-endian: 0xa868, 0x42f2)
    const key: [4]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918 };
    const plaintext: [2]u16 = .{ 0x6574, 0x694c };
    const expected: [2]u16 = .{ 0xa868, 0x42f2 };

    const cipher = Speck32.init(key);
    const ciphertext = cipher.encrypt(plaintext);

    try std.testing.expectEqual(expected[0], ciphertext[0]);
    try std.testing.expectEqual(expected[1], ciphertext[1]);

    const decrypted = cipher.decrypt(ciphertext);
    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}

test "SIMON32/64 official test vector" {
    // Official test vector from NSA paper and reference implementations
    // Key: 0x1918111009080100 (little-endian: 0x0100, 0x0908, 0x1110, 0x1918)
    // Plaintext: 0x65656877 (little-endian: 0x6565, 0x6877)
    // Expected ciphertext: 0xc69be9bb (little-endian: 0xc69b, 0xe9bb)
    const key: [4]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918 };
    const plaintext: [2]u16 = .{ 0x6565, 0x6877 };
    const expected: [2]u16 = .{ 0xc69b, 0xe9bb };

    const cipher = Simon32.init(key);
    const ciphertext = cipher.encrypt(plaintext);

    try std.testing.expectEqual(expected[0], ciphertext[0]);
    try std.testing.expectEqual(expected[1], ciphertext[1]);

    const decrypted = cipher.decrypt(ciphertext);
    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}

test "SIMECK32/64 official test vector" {
    // Official test vector verified against reference implementation
    // Key: 0x1918111009080100 (little-endian: 0x0100, 0x0908, 0x1110, 0x1918)
    // Plaintext: 0x65656877 (little-endian: 0x6565, 0x6877)
    // Expected ciphertext: 0x677937a7 (little-endian: 0x6779, 0x37a7)
    const key: [4]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918 };
    const plaintext: [2]u16 = .{ 0x6565, 0x6877 };
    const expected: [2]u16 = .{ 0x6779, 0x37a7 };

    const cipher = Simeck32.init(key);
    const ciphertext = cipher.encrypt(plaintext);

    try std.testing.expectEqual(expected[0], ciphertext[0]);
    try std.testing.expectEqual(expected[1], ciphertext[1]);

    const decrypted = cipher.decrypt(ciphertext);
    try std.testing.expectEqual(plaintext[0], decrypted[0]);
    try std.testing.expectEqual(plaintext[1], decrypted[1]);
}

test "All ciphers different outputs" {
    const key: [4]u16 = .{ 0x1234, 0x5678, 0x9abc, 0xdef0 };
    const plaintext: [2]u16 = .{ 0xabcd, 0xef01 };

    const speck = Speck32.init(key);
    const simon = Simon32.init(key);
    const simeck = Simeck32.init(key);

    const speck_ct = speck.encrypt(plaintext);
    const simon_ct = simon.encrypt(plaintext);
    const simeck_ct = simeck.encrypt(plaintext);

    // All three ciphers should produce different ciphertexts
    try std.testing.expect(speck_ct[0] != simon_ct[0] or speck_ct[1] != simon_ct[1]);
    try std.testing.expect(speck_ct[0] != simeck_ct[0] or speck_ct[1] != simeck_ct[1]);
    try std.testing.expect(simon_ct[0] != simeck_ct[0] or simon_ct[1] != simeck_ct[1]);

    // But all should decrypt correctly
    const speck_pt = speck.decrypt(speck_ct);
    const simon_pt = simon.decrypt(simon_ct);
    const simeck_pt = simeck.decrypt(simeck_ct);

    try std.testing.expectEqual(plaintext[0], speck_pt[0]);
    try std.testing.expectEqual(plaintext[1], speck_pt[1]);
    try std.testing.expectEqual(plaintext[0], simon_pt[0]);
    try std.testing.expectEqual(plaintext[1], simon_pt[1]);
    try std.testing.expectEqual(plaintext[0], simeck_pt[0]);
    try std.testing.expectEqual(plaintext[1], simeck_pt[1]);
}
