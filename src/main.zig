const std = @import("std");
const zig_speck = @import("zig_speck");

pub fn main() !void {
    const stdout = std.fs.File.stdout().deprecatedWriter();
    const allocator = std.heap.page_allocator;

    try stdout.print("SIMON32, SPECK32, and SIMECK32 Lightweight Block Ciphers\n", .{});
    try stdout.print("=========================================================\n\n", .{});

    // Demo key and plaintext
    const key: [4]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918 };
    const plaintext: [2]u16 = .{ 0x6574, 0x694c };

    try stdout.print("Key:       ", .{});
    for (key) |k| {
        try stdout.print("{x:04} ", .{k});
    }
    try stdout.print("\n", .{});

    try stdout.print("Plaintext: {x:04} {x:04}\n\n", .{ plaintext[0], plaintext[1] });

    // SPECK32 demo
    {
        const speck = zig_speck.Speck32.init(key);
        const ciphertext = speck.encrypt(plaintext);
        const decrypted = speck.decrypt(ciphertext);

        try stdout.print("SPECK32/64:\n", .{});
        try stdout.print("  Ciphertext: {x:04} {x:04}\n", .{ ciphertext[0], ciphertext[1] });
        try stdout.print("  Decrypted:  {x:04} {x:04}\n", .{ decrypted[0], decrypted[1] });
        try stdout.print("  Match: {}\n\n", .{std.meta.eql(plaintext, decrypted)});
    }

    // SIMON32 demo
    {
        const simon = zig_speck.Simon32.init(key);
        const plaintext2: [2]u16 = .{ 0x6565, 0x6877 };
        const ciphertext = simon.encrypt(plaintext2);
        const decrypted = simon.decrypt(ciphertext);

        try stdout.print("SIMON32/64:\n", .{});
        try stdout.print("  Plaintext:  {x:04} {x:04}\n", .{ plaintext2[0], plaintext2[1] });
        try stdout.print("  Ciphertext: {x:04} {x:04}\n", .{ ciphertext[0], ciphertext[1] });
        try stdout.print("  Decrypted:  {x:04} {x:04}\n", .{ decrypted[0], decrypted[1] });
        try stdout.print("  Match: {}\n\n", .{std.meta.eql(plaintext2, decrypted)});
    }

    // SIMECK32 demo
    {
        const simeck = zig_speck.Simeck32.init(key);
        const plaintext3: [2]u16 = .{ 0x6565, 0x6877 };
        const ciphertext = simeck.encrypt(plaintext3);
        const decrypted = simeck.decrypt(ciphertext);

        try stdout.print("SIMECK32/64:\n", .{});
        try stdout.print("  Plaintext:  {x:04} {x:04}\n", .{ plaintext3[0], plaintext3[1] });
        try stdout.print("  Ciphertext: {x:04} {x:04}\n", .{ ciphertext[0], ciphertext[1] });
        try stdout.print("  Decrypted:  {x:04} {x:04}\n", .{ decrypted[0], decrypted[1] });
        try stdout.print("  Match: {}\n\n", .{std.meta.eql(plaintext3, decrypted)});
    }

    // Benchmark
    try stdout.print("Benchmark (1 million encryptions each):\n", .{});
    try stdout.print("----------------------------------------\n", .{});

    const iterations = 1_000_000;
    var dummy: u32 = 0;

    // SPECK32 benchmark
    {
        const speck = zig_speck.Speck32.init(key);
        var timer = try std.time.Timer.start();
        var i: usize = 0;
        while (i < iterations) : (i += 1) {
            const ct = speck.encrypt(plaintext);
            dummy +%= ct[0] +% ct[1];
        }
        const speck_time = timer.read();
        const speck_ms = @as(f64, @floatFromInt(speck_time)) / 1_000_000.0;
        try stdout.print("SPECK32:  {d:.2} ms ({d:.0} ops/sec)\n", .{ speck_ms, @as(f64, iterations) / (speck_ms / 1000.0) });
    }

    // SIMON32 benchmark
    {
        const simon = zig_speck.Simon32.init(key);
        var timer = try std.time.Timer.start();
        var i: usize = 0;
        while (i < iterations) : (i += 1) {
            const ct = simon.encrypt(plaintext);
            dummy +%= ct[0] +% ct[1];
        }
        const simon_time = timer.read();
        const simon_ms = @as(f64, @floatFromInt(simon_time)) / 1_000_000.0;
        try stdout.print("SIMON32:  {d:.2} ms ({d:.0} ops/sec)\n", .{ simon_ms, @as(f64, iterations) / (simon_ms / 1000.0) });
    }

    // SIMECK32 benchmark
    {
        const simeck = zig_speck.Simeck32.init(key);
        var timer = try std.time.Timer.start();
        var i: usize = 0;
        while (i < iterations) : (i += 1) {
            const ct = simeck.encrypt(plaintext);
            dummy +%= ct[0] +% ct[1];
        }
        const simeck_time = timer.read();
        const simeck_ms = @as(f64, @floatFromInt(simeck_time)) / 1_000_000.0;
        try stdout.print("SIMECK32: {d:.2} ms ({d:.0} ops/sec)\n", .{ simeck_ms, @as(f64, iterations) / (simeck_ms / 1000.0) });
    }

    _ = allocator;
}
