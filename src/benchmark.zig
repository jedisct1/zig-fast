const std = @import("std");
const fast = @import("root.zig");

const BenchmarkResult = struct {
    name: []const u8,
    iterations: u64,
    total_ns: u64,
    ns_per_op: u64,
    ops_per_sec: f64,
};

fn printResult(result: BenchmarkResult) void {
    std.debug.print(
        "{s:40} {d:>10} iterations  {d:>8} ns/op  {d:>12.2} ops/sec\n",
        .{ result.name, result.iterations, result.ns_per_op, result.ops_per_sec },
    );
}

fn benchmarkInit(comptime radix: u32, allocator: std.mem.Allocator, word_length: u32, iterations: u64) !BenchmarkResult {
    const sbox_count = 256;
    const params = try fast.calculateRecommendedParams(radix, word_length, 128);
    const key = [_]u8{
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    };

    var timer = try std.time.Timer.start();
    const start = timer.read();

    var i: u64 = 0;
    while (i < iterations) : (i += 1) {
        var ctx = try fast.init(radix, sbox_count, allocator, &params, &key);
        ctx.deinit();
        allocator.destroy(ctx);
    }

    const elapsed = timer.read() - start;
    const ns_per_op = elapsed / iterations;
    const ops_per_sec = @as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0);

    return BenchmarkResult{
        .name = try std.fmt.allocPrint(allocator, "init (radix={d}, len={d})", .{ radix, word_length }),
        .iterations = iterations,
        .total_ns = elapsed,
        .ns_per_op = ns_per_op,
        .ops_per_sec = ops_per_sec,
    };
}

fn benchmarkEncrypt(comptime radix: u32, allocator: std.mem.Allocator, word_length: u32, iterations: u64) !BenchmarkResult {
    const sbox_count = 256;
    const params = try fast.calculateRecommendedParams(radix, word_length, 128);
    const key = [_]u8{
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    };

    var ctx = try fast.init(radix, sbox_count, allocator, &params, &key);
    defer {
        ctx.deinit();
        allocator.destroy(ctx);
    }

    const tweak = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
    const plaintext = try allocator.alloc(u8, word_length);
    defer allocator.free(plaintext);
    const ciphertext = try allocator.alloc(u8, word_length);
    defer allocator.free(ciphertext);

    // Initialize plaintext
    for (plaintext, 0..) |*p, idx| {
        p.* = @intCast(idx % radix);
    }

    var timer = try std.time.Timer.start();
    const start = timer.read();

    var i: u64 = 0;
    while (i < iterations) : (i += 1) {
        try fast.encrypt(radix, sbox_count, ctx, &tweak, plaintext, ciphertext);
    }

    const elapsed = timer.read() - start;
    const ns_per_op = elapsed / iterations;
    const ops_per_sec = @as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0);

    return BenchmarkResult{
        .name = try std.fmt.allocPrint(allocator, "encrypt (radix={d}, len={d})", .{ radix, word_length }),
        .iterations = iterations,
        .total_ns = elapsed,
        .ns_per_op = ns_per_op,
        .ops_per_sec = ops_per_sec,
    };
}

fn benchmarkDecrypt(comptime radix: u32, allocator: std.mem.Allocator, word_length: u32, iterations: u64) !BenchmarkResult {
    const sbox_count = 256;
    const params = try fast.calculateRecommendedParams(radix, word_length, 128);
    const key = [_]u8{
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    };

    var ctx = try fast.init(radix, sbox_count, allocator, &params, &key);
    defer {
        ctx.deinit();
        allocator.destroy(ctx);
    }

    const tweak = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
    const plaintext = try allocator.alloc(u8, word_length);
    defer allocator.free(plaintext);
    const ciphertext = try allocator.alloc(u8, word_length);
    defer allocator.free(ciphertext);

    // Initialize and encrypt once to get ciphertext
    for (plaintext, 0..) |*p, idx| {
        p.* = @intCast(idx % radix);
    }
    try fast.encrypt(radix, sbox_count, ctx, &tweak, plaintext, ciphertext);

    var timer = try std.time.Timer.start();
    const start = timer.read();

    var i: u64 = 0;
    while (i < iterations) : (i += 1) {
        try fast.decrypt(radix, sbox_count, ctx, &tweak, ciphertext, plaintext);
    }

    const elapsed = timer.read() - start;
    const ns_per_op = elapsed / iterations;
    const ops_per_sec = @as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0);

    return BenchmarkResult{
        .name = try std.fmt.allocPrint(allocator, "decrypt (radix={d}, len={d})", .{ radix, word_length }),
        .iterations = iterations,
        .total_ns = elapsed,
        .ns_per_op = ns_per_op,
        .ops_per_sec = ops_per_sec,
    };
}

fn benchmarkThroughput(comptime radix: u32, allocator: std.mem.Allocator, word_length: u32, duration_ms: u64) !void {
    const sbox_count = 256;
    const params = try fast.calculateRecommendedParams(radix, word_length, 128);
    const key = [_]u8{
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    };

    var ctx = try fast.init(radix, sbox_count, allocator, &params, &key);
    defer {
        ctx.deinit();
        allocator.destroy(ctx);
    }

    const tweak = [_]u8{ 0x00, 0x11, 0x22, 0x33 };
    const plaintext = try allocator.alloc(u8, word_length);
    defer allocator.free(plaintext);
    const ciphertext = try allocator.alloc(u8, word_length);
    defer allocator.free(ciphertext);

    for (plaintext, 0..) |*p, idx| {
        p.* = @intCast(idx % radix);
    }

    var timer = try std.time.Timer.start();
    const start = timer.read();
    const target_ns = duration_ms * 1_000_000;

    var iterations: u64 = 0;
    while ((timer.read() - start) < target_ns) {
        try fast.encrypt(radix, sbox_count, ctx, &tweak, plaintext, ciphertext);
        iterations += 1;
    }

    const elapsed = timer.read() - start;
    const bytes_processed = iterations * word_length;
    const mb_processed = @as(f64, @floatFromInt(bytes_processed)) / (1024.0 * 1024.0);
    const seconds = @as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0;
    const throughput = mb_processed / seconds;

    std.debug.print(
        "Throughput (radix={d}, len={d:>3}): {d:>8} ops in {d:>6.2}s = {d:>10.2} MB/s\n",
        .{ radix, word_length, iterations, seconds, throughput },
    );
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n=== FAST Cipher Benchmarks ===\n\n", .{});

    std.debug.print("--- Context Initialization ---\n", .{});
    {
        const result = try benchmarkInit(10, allocator, 16, 1000);
        printResult(result);
        allocator.free(result.name);
    }
    {
        const result = try benchmarkInit(16, allocator, 16, 1000);
        printResult(result);
        allocator.free(result.name);
    }
    {
        const result = try benchmarkInit(256, allocator, 16, 1000);
        printResult(result);
        allocator.free(result.name);
    }
    {
        const result = try benchmarkInit(10, allocator, 32, 500);
        printResult(result);
        allocator.free(result.name);
    }
    {
        const result = try benchmarkInit(256, allocator, 32, 500);
        printResult(result);
        allocator.free(result.name);
    }

    std.debug.print("\n--- Encryption ---\n", .{});
    {
        const result = try benchmarkEncrypt(10, allocator, 16, 10000);
        printResult(result);
        allocator.free(result.name);
    }
    {
        const result = try benchmarkEncrypt(16, allocator, 16, 10000);
        printResult(result);
        allocator.free(result.name);
    }
    {
        const result = try benchmarkEncrypt(256, allocator, 16, 10000);
        printResult(result);
        allocator.free(result.name);
    }
    {
        const result = try benchmarkEncrypt(10, allocator, 32, 5000);
        printResult(result);
        allocator.free(result.name);
    }
    {
        const result = try benchmarkEncrypt(256, allocator, 32, 5000);
        printResult(result);
        allocator.free(result.name);
    }

    std.debug.print("\n--- Decryption ---\n", .{});
    {
        const result = try benchmarkDecrypt(10, allocator, 16, 10000);
        printResult(result);
        allocator.free(result.name);
    }
    {
        const result = try benchmarkDecrypt(16, allocator, 16, 10000);
        printResult(result);
        allocator.free(result.name);
    }
    {
        const result = try benchmarkDecrypt(256, allocator, 16, 10000);
        printResult(result);
        allocator.free(result.name);
    }
    {
        const result = try benchmarkDecrypt(10, allocator, 32, 5000);
        printResult(result);
        allocator.free(result.name);
    }
    {
        const result = try benchmarkDecrypt(256, allocator, 32, 5000);
        printResult(result);
        allocator.free(result.name);
    }

    std.debug.print("\n--- Throughput (1 second tests) ---\n", .{});
    try benchmarkThroughput(10, allocator, 16, 1000);
    try benchmarkThroughput(16, allocator, 32, 1000);
    try benchmarkThroughput(256, allocator, 64, 1000);
    try benchmarkThroughput(256, allocator, 128, 1000);

    std.debug.print("\n=== Benchmarks Complete ===\n\n", .{});
}
