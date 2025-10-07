const std = @import("std");
const fast_lib = @import("zig");

const DEFAULT_TWEAK = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

fn printArray(label: []const u8, data: []const u8) void {
    std.debug.print("{s}: ", .{label});
    for (data) |byte| {
        std.debug.print("{d:3} ", .{byte});
    }
    std.debug.print("\n", .{});
}

fn testEncryptDecrypt() !void {
    std.debug.print("\n=== Testing Encryption and Decryption ===\n", .{});

    const key = [_]u8{
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    };

    const radix = 10;
    const sbox_count = fast_lib.SBOX_POOL_SIZE;
    const word_length: u32 = 16;
    const security_level: u32 = 128;

    const params = try fast_lib.calculateRecommendedParams(radix, word_length, security_level);

    std.debug.print("Parameters:\n", .{});
    std.debug.print("  Radix: {d}\n", .{radix});
    std.debug.print("  Word length: {d}\n", .{params.word_length});
    std.debug.print("  Number of layers: {d}\n", .{params.num_layers});
    std.debug.print("  Branch distance w: {d}\n", .{params.branch_dist1});
    std.debug.print("  Branch distance w': {d}\n", .{params.branch_dist2});
    std.debug.print("  S-box pool size: {d}\n", .{params.sbox_count});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var ctx = try fast_lib.init(radix, sbox_count, allocator, &params, &key);
    defer {
        ctx.deinit();
        allocator.destroy(ctx);
    }

    const plaintext = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
    var ciphertext: [16]u8 = undefined;
    var recovered: [16]u8 = undefined;

    printArray("Plaintext ", &plaintext);

    try fast_lib.encrypt(radix, sbox_count, ctx, &DEFAULT_TWEAK, &plaintext, &ciphertext);
    printArray("Ciphertext", &ciphertext);

    try fast_lib.decrypt(radix, sbox_count, ctx, &DEFAULT_TWEAK, &ciphertext, &recovered);
    printArray("Recovered ", &recovered);

    if (std.mem.eql(u8, &plaintext, &recovered)) {
        std.debug.print("✓ Decryption correctly recovered the plaintext\n", .{});
    } else {
        std.debug.print("✗ Decryption failed to recover the plaintext\n", .{});
        return error.DecryptionFailed;
    }
}

fn testRadix(comptime radix: u32, comptime word_length: u32, allocator: std.mem.Allocator) !void {
    const key = [_]u8{
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    };

    const sbox_count = fast_lib.SBOX_POOL_SIZE;
    std.debug.print("\nTesting radix={d}, word_length={d}\n", .{ radix, word_length });

    const params = try fast_lib.calculateRecommendedParams(radix, word_length, 128);

    var ctx = try fast_lib.init(radix, sbox_count, allocator, &params, &key);
    defer {
        ctx.deinit();
        allocator.destroy(ctx);
    }

    const plaintext = try allocator.alloc(u8, word_length);
    defer allocator.free(plaintext);
    const ciphertext = try allocator.alloc(u8, word_length);
    defer allocator.free(ciphertext);
    const recovered = try allocator.alloc(u8, word_length);
    defer allocator.free(recovered);

    // Initialize plaintext with values in range [0, radix)
    for (plaintext, 0..) |*p, i| {
        p.* = @intCast(i % radix);
    }

    try fast_lib.encrypt(radix, sbox_count, ctx, &DEFAULT_TWEAK, plaintext, ciphertext);
    try fast_lib.decrypt(radix, sbox_count, ctx, &DEFAULT_TWEAK, ciphertext, recovered);

    if (std.mem.eql(u8, plaintext, recovered)) {
        std.debug.print("  ✓ Passed\n", .{});
    } else {
        std.debug.print("  ✗ Failed\n", .{});
        return error.TestFailed;
    }
}

fn testDifferentRadices() !void {
    std.debug.print("\n=== Testing Different Radices ===\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try testRadix(10, 10, allocator);
    try testRadix(16, 8, allocator);
    try testRadix(256, 16, allocator);
}

pub fn main() !void {
    std.debug.print("FAST Zig Implementation Test Suite\n", .{});
    std.debug.print("==================================\n", .{});

    try testEncryptDecrypt();
    try testDifferentRadices();

    std.debug.print("\n=== All Tests Passed ===\n", .{});
}

test "simple test" {
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(std.testing.allocator);
    try list.append(std.testing.allocator, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
