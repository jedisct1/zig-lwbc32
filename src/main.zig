const std = @import("std");
const lwbc32 = @import("lwbc32");
const Io = std.Io;

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();
    const gpa = debug_allocator.allocator();

    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = Io.File.stdout().writerStreaming(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.print("SIMON32, SPECK32, and SIMECK32 Lightweight Block Ciphers\n", .{});
    try stdout.print("=========================================================\n\n", .{});

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
        try stdout.print("SPECK32:  {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ speck_ms, speck_ops_sec, (speck_ops_sec * 32.0) / 1_000_000_000.0 });
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
        try stdout.print("SIMON32:  {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ simon_ms, simon_ops_sec, (simon_ops_sec * 32.0) / 1_000_000_000.0 });
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
        try stdout.print("SIMECK32: {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ simeck_ms, simeck_ops_sec, (simeck_ops_sec * 32.0) / 1_000_000_000.0 });
    }

    try stdout_writer.interface.flush();
    std.mem.doNotOptimizeAway(dummy);
}
