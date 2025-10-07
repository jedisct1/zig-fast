const std = @import("std");
const layers = @import("layers.zig");
const sbox = @import("sbox.zig");

/// Component encryption - applies all ES layers in forward order
pub fn cenc(
    comptime radix: u32,
    comptime sbox_count: u32,
    params: *const layers.Params(radix),
    pool: *const sbox.SBoxPool(radix, sbox_count),
    seq: []const u32,
    input: []const u8,
    output: []u8,
) void {
    if (input.len != params.word_length or output.len != params.word_length) {
        return;
    }

    // Copy input to output if different
    if (input.ptr != output.ptr) {
        @memcpy(output, input);
    }

    // Apply all layers
    for (0..params.num_layers) |i| {
        const sbox_index = if (seq.len > 0) seq[i] else @as(u32, @intCast(i % sbox_count));
        layers.esLayer(radix, sbox_count, params, pool, output, sbox_index);
    }
}

/// Component decryption - applies all DS layers in reverse order
pub fn cdec(
    comptime radix: u32,
    comptime sbox_count: u32,
    params: *const layers.Params(radix),
    pool: *const sbox.SBoxPool(radix, sbox_count),
    seq: []const u32,
    input: []const u8,
    output: []u8,
) void {
    if (input.len != params.word_length or output.len != params.word_length) {
        return;
    }

    // Copy input to output if different
    if (input.ptr != output.ptr) {
        @memcpy(output, input);
    }

    // Apply all layers in reverse
    var i = params.num_layers;
    while (i > 0) {
        i -= 1;
        const sbox_index = if (seq.len > 0) seq[i] else @as(u32, @intCast(i % sbox_count));
        layers.dsLayer(radix, sbox_count, params, pool, output, sbox_index);
    }
}

test "cenc_cdec roundtrip" {
    const radix = 16;
    const sbox_count = 10;

    const PoolType = sbox.SBoxPool(radix, sbox_count);
    var pool = PoolType.init();

    // Need to generate S-boxes
    const key_material: [32]u8 = @splat(0x01);
    pool.generateFromKeyMaterial(&key_material);

    const ParamsType = layers.Params(radix);
    const params = ParamsType{
        .word_length = 8,
        .sbox_count = sbox_count,
        .num_layers = 16,
        .branch_dist1 = 2,
        .branch_dist2 = 1,
        .security_level = 128,
    };

    // Generate sequence
    var seq: [16]u32 = undefined;
    for (&seq, 0..) |*s, i| {
        s.* = @intCast(i % sbox_count);
    }

    const plaintext = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var ciphertext: [8]u8 = undefined;
    var recovered: [8]u8 = undefined;

    cenc(radix, sbox_count, &params, &pool, &seq, &plaintext, &ciphertext);
    cdec(radix, sbox_count, &params, &pool, &seq, &ciphertext, &recovered);

    try std.testing.expectEqualSlices(u8, &plaintext, &recovered);
}
