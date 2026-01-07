const std = @import("std");
const lwbc32 = @import("lwbc32");
const Io = std.Io;

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: Io.Threaded = .init(gpa, .{ .environ = .empty });
    defer threaded.deinit();
    const io = threaded.io();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writerStreaming(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("Lightweight Block Ciphers: SPECK, SIMON, and SIMECK\n", .{});
    try stdout.print("===================================================\n\n", .{});

    const key: [4]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918 };
    const plaintext: [2]u16 = .{ 0x6574, 0x694c };

    try stdout.print("Key:       ", .{});
    inline for (key) |k| {
        try stdout.print("{x:04} ", .{k});
    }
    try stdout.print("\n", .{});

    try stdout.print("Plaintext: {x:04} {x:04}\n\n", .{ plaintext[0], plaintext[1] });

    {
        const speck = lwbc32.Speck32.init(key);
        const ciphertext = speck.encrypt(plaintext);
        const decrypted = speck.decrypt(ciphertext);

        try stdout.print("SPECK32/64:\n", .{});
        try stdout.print("  Ciphertext: {x:04} {x:04}\n", .{ ciphertext[0], ciphertext[1] });
        try stdout.print("  Decrypted:  {x:04} {x:04}\n", .{ decrypted[0], decrypted[1] });
        try stdout.print("  Match: {}\n\n", .{std.meta.eql(plaintext, decrypted)});
    }

    {
        const key64: [4]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
        const plaintext64: [2]u32 = .{ 0x3b726574, 0x7475432d };
        const speck = lwbc32.Speck64.init(key64);
        const ciphertext = speck.encrypt(plaintext64);
        const decrypted = speck.decrypt(ciphertext);

        try stdout.print("SPECK64/128:\n", .{});
        try stdout.print("  Key:        ", .{});
        inline for (key64) |k| {
            try stdout.print("{x:08} ", .{k});
        }
        try stdout.print("\n", .{});
        try stdout.print("  Plaintext:  {x:08} {x:08}\n", .{ plaintext64[0], plaintext64[1] });
        try stdout.print("  Ciphertext: {x:08} {x:08}\n", .{ ciphertext[0], ciphertext[1] });
        try stdout.print("  Decrypted:  {x:08} {x:08}\n", .{ decrypted[0], decrypted[1] });
        try stdout.print("  Match: {}\n\n", .{std.meta.eql(plaintext64, decrypted)});
    }

    {
        const simon = lwbc32.Simon32.init(key);
        const plaintext2: [2]u16 = .{ 0x6565, 0x6877 };
        const ciphertext = simon.encrypt(plaintext2);
        const decrypted = simon.decrypt(ciphertext);

        try stdout.print("SIMON32/64:\n", .{});
        try stdout.print("  Plaintext:  {x:04} {x:04}\n", .{ plaintext2[0], plaintext2[1] });
        try stdout.print("  Ciphertext: {x:04} {x:04}\n", .{ ciphertext[0], ciphertext[1] });
        try stdout.print("  Decrypted:  {x:04} {x:04}\n", .{ decrypted[0], decrypted[1] });
        try stdout.print("  Match: {}\n\n", .{std.meta.eql(plaintext2, decrypted)});
    }

    {
        const key64: [4]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
        const plaintext64: [2]u32 = .{ 0x656b696c, 0x20646e75 };
        const simon = lwbc32.Simon64.init(key64);
        const ciphertext = simon.encrypt(plaintext64);
        const decrypted = simon.decrypt(ciphertext);

        try stdout.print("SIMON64/128:\n", .{});
        try stdout.print("  Key:        ", .{});
        inline for (key64) |k| {
            try stdout.print("{x:08} ", .{k});
        }
        try stdout.print("\n", .{});
        try stdout.print("  Plaintext:  {x:08} {x:08}\n", .{ plaintext64[0], plaintext64[1] });
        try stdout.print("  Ciphertext: {x:08} {x:08}\n", .{ ciphertext[0], ciphertext[1] });
        try stdout.print("  Decrypted:  {x:08} {x:08}\n", .{ decrypted[0], decrypted[1] });
        try stdout.print("  Match: {}\n\n", .{std.meta.eql(plaintext64, decrypted)});
    }

    {
        const simeck = lwbc32.Simeck32.init(key);
        const plaintext3: [2]u16 = .{ 0x6565, 0x6877 };
        const ciphertext = simeck.encrypt(plaintext3);
        const decrypted = simeck.decrypt(ciphertext);

        try stdout.print("SIMECK32/64:\n", .{});
        try stdout.print("  Plaintext:  {x:04} {x:04}\n", .{ plaintext3[0], plaintext3[1] });
        try stdout.print("  Ciphertext: {x:04} {x:04}\n", .{ ciphertext[0], ciphertext[1] });
        try stdout.print("  Decrypted:  {x:04} {x:04}\n", .{ decrypted[0], decrypted[1] });
        try stdout.print("  Match: {}\n\n", .{std.meta.eql(plaintext3, decrypted)});
    }

    {
        const key64: [4]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
        const plaintext64: [2]u32 = .{ 0x656b696c, 0x20646e75 };
        const simeck = lwbc32.Simeck64.init(key64);
        const ciphertext = simeck.encrypt(plaintext64);
        const decrypted = simeck.decrypt(ciphertext);

        try stdout.print("SIMECK64/128:\n", .{});
        try stdout.print("  Key:        ", .{});
        inline for (key64) |k| {
            try stdout.print("{x:08} ", .{k});
        }
        try stdout.print("\n", .{});
        try stdout.print("  Plaintext:  {x:08} {x:08}\n", .{ plaintext64[0], plaintext64[1] });
        try stdout.print("  Ciphertext: {x:08} {x:08}\n", .{ ciphertext[0], ciphertext[1] });
        try stdout.print("  Decrypted:  {x:08} {x:08}\n", .{ decrypted[0], decrypted[1] });
        try stdout.print("  Match: {}\n\n", .{std.meta.eql(plaintext64, decrypted)});
    }

    try stdout.print("Whitened Variants (with key whitening)\n", .{});
    try stdout.print("---------------------------------------\n\n", .{});

    {
        const whitened_key: [8]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918, 0xdead, 0xbeef, 0xcafe, 0xbabe };
        const speck = lwbc32.Speck32Whitened.init(whitened_key);
        const ciphertext = speck.encrypt(plaintext);
        const decrypted = speck.decrypt(ciphertext);

        try stdout.print("SPECK32/64 Whitened (128-bit key):\n", .{});
        try stdout.print("  Ciphertext: {x:04} {x:04}\n", .{ ciphertext[0], ciphertext[1] });
        try stdout.print("  Decrypted:  {x:04} {x:04}\n", .{ decrypted[0], decrypted[1] });
        try stdout.print("  Match: {}\n\n", .{std.meta.eql(plaintext, decrypted)});
    }

    {
        const whitened_key: [8]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918, 0xdeadbeef, 0xcafebabe, 0x12345678, 0x9abcdef0 };
        const plaintext64: [2]u32 = .{ 0x3b726574, 0x7475432d };
        const speck = lwbc32.Speck64Whitened.init(whitened_key);
        const ciphertext = speck.encrypt(plaintext64);
        const decrypted = speck.decrypt(ciphertext);

        try stdout.print("SPECK64/128 Whitened (256-bit key):\n", .{});
        try stdout.print("  Ciphertext: {x:08} {x:08}\n", .{ ciphertext[0], ciphertext[1] });
        try stdout.print("  Decrypted:  {x:08} {x:08}\n", .{ decrypted[0], decrypted[1] });
        try stdout.print("  Match: {}\n\n", .{std.meta.eql(plaintext64, decrypted)});
    }

    try stdout.print("Benchmark (10 million encryptions each):\n", .{});
    try stdout.print("----------------------------------------\n", .{});

    const iterations = 10_000_000;
    var dummy: u32 = 0;

    {
        const speck = lwbc32.Speck32.init(key);
        var timer = try std.time.Timer.start();

        var i: usize = 0;
        while (i < iterations) : (i += 4) {
            const ct1 = speck.encrypt(plaintext);
            const ct2 = speck.encrypt(.{ ct1[0], ct1[1] });
            const ct3 = speck.encrypt(.{ ct2[0], ct2[1] });
            const ct4 = speck.encrypt(.{ ct3[0], ct3[1] });
            dummy +%= ct1[0] +% ct1[1] +% ct2[0] +% ct2[1] +% ct3[0] +% ct3[1] +% ct4[0] +% ct4[1];
            std.mem.doNotOptimizeAway(dummy);
        }

        const speck_time = timer.read();
        const speck_ms = @as(f64, @floatFromInt(speck_time)) / 1_000_000.0;
        const speck_ops_sec = @as(f64, iterations) / (speck_ms / 1000.0);
        try stdout.print("SPECK32:   {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ speck_ms, speck_ops_sec, (speck_ops_sec * 32.0) / 1_000_000_000.0 });
    }

    {
        const key64: [4]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
        const plaintext64: [2]u32 = .{ 0x3b726574, 0x7475432d };
        const speck = lwbc32.Speck64.init(key64);
        var timer = try std.time.Timer.start();

        var i: usize = 0;
        while (i < iterations) : (i += 4) {
            const ct1 = speck.encrypt(plaintext64);
            const ct2 = speck.encrypt(.{ ct1[0], ct1[1] });
            const ct3 = speck.encrypt(.{ ct2[0], ct2[1] });
            const ct4 = speck.encrypt(.{ ct3[0], ct3[1] });
            dummy +%= ct1[0] +% ct1[1] +% ct2[0] +% ct2[1] +% ct3[0] +% ct3[1] +% ct4[0] +% ct4[1];
            std.mem.doNotOptimizeAway(dummy);
        }

        const speck_time = timer.read();
        const speck_ms = @as(f64, @floatFromInt(speck_time)) / 1_000_000.0;
        const speck_ops_sec = @as(f64, iterations) / (speck_ms / 1000.0);
        try stdout.print("SPECK64:   {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ speck_ms, speck_ops_sec, (speck_ops_sec * 64.0) / 1_000_000_000.0 });
    }

    {
        const simon = lwbc32.Simon32.init(key);
        var timer = try std.time.Timer.start();

        var i: usize = 0;
        while (i < iterations) : (i += 4) {
            const ct1 = simon.encrypt(plaintext);
            const ct2 = simon.encrypt(.{ ct1[0], ct1[1] });
            const ct3 = simon.encrypt(.{ ct2[0], ct2[1] });
            const ct4 = simon.encrypt(.{ ct3[0], ct3[1] });
            dummy +%= ct1[0] +% ct1[1] +% ct2[0] +% ct2[1] +% ct3[0] +% ct3[1] +% ct4[0] +% ct4[1];
            std.mem.doNotOptimizeAway(dummy);
        }

        const simon_time = timer.read();
        const simon_ms = @as(f64, @floatFromInt(simon_time)) / 1_000_000.0;
        const simon_ops_sec = @as(f64, iterations) / (simon_ms / 1000.0);
        try stdout.print("SIMON32:   {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ simon_ms, simon_ops_sec, (simon_ops_sec * 32.0) / 1_000_000_000.0 });
    }

    {
        const key64: [4]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
        const plaintext64: [2]u32 = .{ 0x656b696c, 0x20646e75 };
        const simon = lwbc32.Simon64.init(key64);
        var timer = try std.time.Timer.start();

        var i: usize = 0;
        while (i < iterations) : (i += 4) {
            const ct1 = simon.encrypt(plaintext64);
            const ct2 = simon.encrypt(.{ ct1[0], ct1[1] });
            const ct3 = simon.encrypt(.{ ct2[0], ct2[1] });
            const ct4 = simon.encrypt(.{ ct3[0], ct3[1] });
            dummy +%= ct1[0] +% ct1[1] +% ct2[0] +% ct2[1] +% ct3[0] +% ct3[1] +% ct4[0] +% ct4[1];
            std.mem.doNotOptimizeAway(dummy);
        }

        const simon_time = timer.read();
        const simon_ms = @as(f64, @floatFromInt(simon_time)) / 1_000_000.0;
        const simon_ops_sec = @as(f64, iterations) / (simon_ms / 1000.0);
        try stdout.print("SIMON64:   {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ simon_ms, simon_ops_sec, (simon_ops_sec * 64.0) / 1_000_000_000.0 });
    }

    {
        const simeck = lwbc32.Simeck32.init(key);
        var timer = try std.time.Timer.start();

        var i: usize = 0;
        while (i < iterations) : (i += 4) {
            const ct1 = simeck.encrypt(plaintext);
            const ct2 = simeck.encrypt(.{ ct1[0], ct1[1] });
            const ct3 = simeck.encrypt(.{ ct2[0], ct2[1] });
            const ct4 = simeck.encrypt(.{ ct3[0], ct3[1] });
            dummy +%= ct1[0] +% ct1[1] +% ct2[0] +% ct2[1] +% ct3[0] +% ct3[1] +% ct4[0] +% ct4[1];
            std.mem.doNotOptimizeAway(dummy);
        }

        const simeck_time = timer.read();
        const simeck_ms = @as(f64, @floatFromInt(simeck_time)) / 1_000_000.0;
        const simeck_ops_sec = @as(f64, iterations) / (simeck_ms / 1000.0);
        try stdout.print("SIMECK32:  {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ simeck_ms, simeck_ops_sec, (simeck_ops_sec * 32.0) / 1_000_000_000.0 });
    }

    {
        const key64: [4]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 };
        const plaintext64: [2]u32 = .{ 0x656b696c, 0x20646e75 };
        const simeck = lwbc32.Simeck64.init(key64);
        var timer = try std.time.Timer.start();

        var i: usize = 0;
        while (i < iterations) : (i += 4) {
            const ct1 = simeck.encrypt(plaintext64);
            const ct2 = simeck.encrypt(.{ ct1[0], ct1[1] });
            const ct3 = simeck.encrypt(.{ ct2[0], ct2[1] });
            const ct4 = simeck.encrypt(.{ ct3[0], ct3[1] });
            dummy +%= ct1[0] +% ct1[1] +% ct2[0] +% ct2[1] +% ct3[0] +% ct3[1] +% ct4[0] +% ct4[1];
            std.mem.doNotOptimizeAway(dummy);
        }

        const simeck_time = timer.read();
        const simeck_ms = @as(f64, @floatFromInt(simeck_time)) / 1_000_000.0;
        const simeck_ops_sec = @as(f64, iterations) / (simeck_ms / 1000.0);
        try stdout.print("SIMECK64:  {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ simeck_ms, simeck_ops_sec, (simeck_ops_sec * 64.0) / 1_000_000_000.0 });
    }

    try stdout.print("\nWhitened variants:\n", .{});

    {
        const whitened_key: [8]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918, 0xdead, 0xbeef, 0xcafe, 0xbabe };
        const speck = lwbc32.Speck32Whitened.init(whitened_key);
        var timer = try std.time.Timer.start();

        var i: usize = 0;
        while (i < iterations) : (i += 4) {
            const ct1 = speck.encrypt(plaintext);
            const ct2 = speck.encrypt(.{ ct1[0], ct1[1] });
            const ct3 = speck.encrypt(.{ ct2[0], ct2[1] });
            const ct4 = speck.encrypt(.{ ct3[0], ct3[1] });
            dummy +%= ct1[0] +% ct1[1] +% ct2[0] +% ct2[1] +% ct3[0] +% ct3[1] +% ct4[0] +% ct4[1];
            std.mem.doNotOptimizeAway(dummy);
        }

        const time = timer.read();
        const ms = @as(f64, @floatFromInt(time)) / 1_000_000.0;
        const ops_sec = @as(f64, iterations) / (ms / 1000.0);
        try stdout.print("SPECK32W:  {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ ms, ops_sec, (ops_sec * 32.0) / 1_000_000_000.0 });
    }

    {
        const whitened_key: [8]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918, 0xdeadbeef, 0xcafebabe, 0x12345678, 0x9abcdef0 };
        const plaintext64: [2]u32 = .{ 0x3b726574, 0x7475432d };
        const speck = lwbc32.Speck64Whitened.init(whitened_key);
        var timer = try std.time.Timer.start();

        var i: usize = 0;
        while (i < iterations) : (i += 4) {
            const ct1 = speck.encrypt(plaintext64);
            const ct2 = speck.encrypt(.{ ct1[0], ct1[1] });
            const ct3 = speck.encrypt(.{ ct2[0], ct2[1] });
            const ct4 = speck.encrypt(.{ ct3[0], ct3[1] });
            dummy +%= ct1[0] +% ct1[1] +% ct2[0] +% ct2[1] +% ct3[0] +% ct3[1] +% ct4[0] +% ct4[1];
            std.mem.doNotOptimizeAway(dummy);
        }

        const time = timer.read();
        const ms = @as(f64, @floatFromInt(time)) / 1_000_000.0;
        const ops_sec = @as(f64, iterations) / (ms / 1000.0);
        try stdout.print("SPECK64W:  {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ ms, ops_sec, (ops_sec * 64.0) / 1_000_000_000.0 });
    }

    {
        const whitened_key: [8]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918, 0x1234, 0x5678, 0xabcd, 0xef01 };
        const simon = lwbc32.Simon32Whitened.init(whitened_key);
        var timer = try std.time.Timer.start();

        var i: usize = 0;
        while (i < iterations) : (i += 4) {
            const ct1 = simon.encrypt(plaintext);
            const ct2 = simon.encrypt(.{ ct1[0], ct1[1] });
            const ct3 = simon.encrypt(.{ ct2[0], ct2[1] });
            const ct4 = simon.encrypt(.{ ct3[0], ct3[1] });
            dummy +%= ct1[0] +% ct1[1] +% ct2[0] +% ct2[1] +% ct3[0] +% ct3[1] +% ct4[0] +% ct4[1];
            std.mem.doNotOptimizeAway(dummy);
        }

        const time = timer.read();
        const ms = @as(f64, @floatFromInt(time)) / 1_000_000.0;
        const ops_sec = @as(f64, iterations) / (ms / 1000.0);
        try stdout.print("SIMON32W:  {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ ms, ops_sec, (ops_sec * 32.0) / 1_000_000_000.0 });
    }

    {
        const whitened_key: [8]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918, 0xaaaabbbb, 0xccccdddd, 0xeeee1111, 0x22223333 };
        const plaintext64: [2]u32 = .{ 0x656b696c, 0x20646e75 };
        const simon = lwbc32.Simon64Whitened.init(whitened_key);
        var timer = try std.time.Timer.start();

        var i: usize = 0;
        while (i < iterations) : (i += 4) {
            const ct1 = simon.encrypt(plaintext64);
            const ct2 = simon.encrypt(.{ ct1[0], ct1[1] });
            const ct3 = simon.encrypt(.{ ct2[0], ct2[1] });
            const ct4 = simon.encrypt(.{ ct3[0], ct3[1] });
            dummy +%= ct1[0] +% ct1[1] +% ct2[0] +% ct2[1] +% ct3[0] +% ct3[1] +% ct4[0] +% ct4[1];
            std.mem.doNotOptimizeAway(dummy);
        }

        const time = timer.read();
        const ms = @as(f64, @floatFromInt(time)) / 1_000_000.0;
        const ops_sec = @as(f64, iterations) / (ms / 1000.0);
        try stdout.print("SIMON64W:  {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ ms, ops_sec, (ops_sec * 64.0) / 1_000_000_000.0 });
    }

    {
        const whitened_key: [8]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918, 0xfeed, 0xface, 0xdead, 0xc0de };
        const simeck = lwbc32.Simeck32Whitened.init(whitened_key);
        var timer = try std.time.Timer.start();

        var i: usize = 0;
        while (i < iterations) : (i += 4) {
            const ct1 = simeck.encrypt(plaintext);
            const ct2 = simeck.encrypt(.{ ct1[0], ct1[1] });
            const ct3 = simeck.encrypt(.{ ct2[0], ct2[1] });
            const ct4 = simeck.encrypt(.{ ct3[0], ct3[1] });
            dummy +%= ct1[0] +% ct1[1] +% ct2[0] +% ct2[1] +% ct3[0] +% ct3[1] +% ct4[0] +% ct4[1];
            std.mem.doNotOptimizeAway(dummy);
        }

        const time = timer.read();
        const ms = @as(f64, @floatFromInt(time)) / 1_000_000.0;
        const ops_sec = @as(f64, iterations) / (ms / 1000.0);
        try stdout.print("SIMECK32W: {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ ms, ops_sec, (ops_sec * 32.0) / 1_000_000_000.0 });
    }

    {
        const whitened_key: [8]u32 = .{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918, 0x11111111, 0x22222222, 0x33333333, 0x44444444 };
        const plaintext64: [2]u32 = .{ 0x656b696c, 0x20646e75 };
        const simeck = lwbc32.Simeck64Whitened.init(whitened_key);
        var timer = try std.time.Timer.start();

        var i: usize = 0;
        while (i < iterations) : (i += 4) {
            const ct1 = simeck.encrypt(plaintext64);
            const ct2 = simeck.encrypt(.{ ct1[0], ct1[1] });
            const ct3 = simeck.encrypt(.{ ct2[0], ct2[1] });
            const ct4 = simeck.encrypt(.{ ct3[0], ct3[1] });
            dummy +%= ct1[0] +% ct1[1] +% ct2[0] +% ct2[1] +% ct3[0] +% ct3[1] +% ct4[0] +% ct4[1];
            std.mem.doNotOptimizeAway(dummy);
        }

        const time = timer.read();
        const ms = @as(f64, @floatFromInt(time)) / 1_000_000.0;
        const ops_sec = @as(f64, iterations) / (ms / 1000.0);
        try stdout.print("SIMECK64W: {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ ms, ops_sec, (ops_sec * 64.0) / 1_000_000_000.0 });
    }

    try stdout_writer.interface.flush();
    std.mem.doNotOptimizeAway(dummy);
}
