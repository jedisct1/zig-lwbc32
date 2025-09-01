const std = @import("std");
const lwbc32 = @import("lwbc32");

pub fn main() !void {
    const stdout_file = std.fs.File.stdout();

    _ = try stdout_file.write("SIMON32, SPECK32, and SIMECK32 Lightweight Block Ciphers\n");
    _ = try stdout_file.write("=========================================================\n\n");

    const key: [4]u16 = .{ 0x0100, 0x0908, 0x1110, 0x1918 };
    const plaintext: [2]u16 = .{ 0x6574, 0x694c };

    _ = try stdout_file.write("Key:       ");
    var buf: [128]u8 = undefined;
    inline for (key) |k| {
        const str = try std.fmt.bufPrint(&buf, "{x:04} ", .{k});
        _ = try stdout_file.write(str);
    }
    _ = try stdout_file.write("\n");

    const plaintext_str = try std.fmt.bufPrint(&buf, "Plaintext: {x:04} {x:04}\n\n", .{ plaintext[0], plaintext[1] });
    _ = try stdout_file.write(plaintext_str);

    {
        const speck = lwbc32.Speck32.init(key);
        const ciphertext = speck.encrypt(plaintext);
        const decrypted = speck.decrypt(ciphertext);

        _ = try stdout_file.write("SPECK32/64:\n");
        const ct_str = try std.fmt.bufPrint(&buf, "  Ciphertext: {x:04} {x:04}\n", .{ ciphertext[0], ciphertext[1] });
        _ = try stdout_file.write(ct_str);
        const dec_str = try std.fmt.bufPrint(&buf, "  Decrypted:  {x:04} {x:04}\n", .{ decrypted[0], decrypted[1] });
        _ = try stdout_file.write(dec_str);
        const match_str = try std.fmt.bufPrint(&buf, "  Match: {}\n\n", .{std.meta.eql(plaintext, decrypted)});
        _ = try stdout_file.write(match_str);
    }

    {
        const simon = lwbc32.Simon32.init(key);
        const plaintext2: [2]u16 = .{ 0x6565, 0x6877 };
        const ciphertext = simon.encrypt(plaintext2);
        const decrypted = simon.decrypt(ciphertext);

        _ = try stdout_file.write("SIMON32/64:\n");
        const pt_str = try std.fmt.bufPrint(&buf, "  Plaintext:  {x:04} {x:04}\n", .{ plaintext2[0], plaintext2[1] });
        _ = try stdout_file.write(pt_str);
        const ct_str = try std.fmt.bufPrint(&buf, "  Ciphertext: {x:04} {x:04}\n", .{ ciphertext[0], ciphertext[1] });
        _ = try stdout_file.write(ct_str);
        const dec_str = try std.fmt.bufPrint(&buf, "  Decrypted:  {x:04} {x:04}\n", .{ decrypted[0], decrypted[1] });
        _ = try stdout_file.write(dec_str);
        const match_str = try std.fmt.bufPrint(&buf, "  Match: {}\n\n", .{std.meta.eql(plaintext2, decrypted)});
        _ = try stdout_file.write(match_str);
    }

    {
        const simeck = lwbc32.Simeck32.init(key);
        const plaintext3: [2]u16 = .{ 0x6565, 0x6877 };
        const ciphertext = simeck.encrypt(plaintext3);
        const decrypted = simeck.decrypt(ciphertext);

        _ = try stdout_file.write("SIMECK32/64:\n");
        const pt_str = try std.fmt.bufPrint(&buf, "  Plaintext:  {x:04} {x:04}\n", .{ plaintext3[0], plaintext3[1] });
        _ = try stdout_file.write(pt_str);
        const ct_str = try std.fmt.bufPrint(&buf, "  Ciphertext: {x:04} {x:04}\n", .{ ciphertext[0], ciphertext[1] });
        _ = try stdout_file.write(ct_str);
        const dec_str = try std.fmt.bufPrint(&buf, "  Decrypted:  {x:04} {x:04}\n", .{ decrypted[0], decrypted[1] });
        _ = try stdout_file.write(dec_str);
        const match_str = try std.fmt.bufPrint(&buf, "  Match: {}\n\n", .{std.meta.eql(plaintext3, decrypted)});
        _ = try stdout_file.write(match_str);
    }

    _ = try stdout_file.write("Benchmark (10 million encryptions each):\n");
    _ = try stdout_file.write("----------------------------------------\n");

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
        const res_str = try std.fmt.bufPrint(&buf, "SPECK32:  {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ speck_ms, speck_ops_sec, (speck_ops_sec * 32.0) / 1_000_000_000.0 });
        _ = try stdout_file.write(res_str);
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
        const res_str = try std.fmt.bufPrint(&buf, "SIMON32:  {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ simon_ms, simon_ops_sec, (simon_ops_sec * 32.0) / 1_000_000_000.0 });
        _ = try stdout_file.write(res_str);
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
        const res_str = try std.fmt.bufPrint(&buf, "SIMECK32: {d:.2} ms ({d:.0} ops/sec, {d:.2} Gbps)\n", .{ simeck_ms, simeck_ops_sec, (simeck_ops_sec * 32.0) / 1_000_000_000.0 });
        _ = try stdout_file.write(res_str);
    }

    std.mem.doNotOptimizeAway(dummy);
}
