const std = @import("std");
const assert = std.debug.assert;
const sbox = @import("sbox.zig");

/// Parameters for the FAST cipher.
///
/// These parameters define the structure and security level of the FAST cipher.
/// They are typically calculated automatically by calculateRecommendedParams()
/// based on desired radix, word length, and security level.
pub fn Params(comptime radix: u32) type {
    // Validate radix at comptime
    if (radix < 4 or radix > 256) {
        @compileError("Invalid radix: must be between 4 and 256");
    }

    return struct {
        /// Length of plaintext/ciphertext words in symbols
        word_length: u32,
        /// Number of S-boxes in the pool (typically 256)
        sbox_count: u32,
        /// Total number of SPN layers (must be divisible by word_length)
        num_layers: u32,
        /// First branch distance parameter (w)
        branch_dist1: u32,
        /// Second branch distance parameter (w')
        branch_dist2: u32,
        /// Target security level in bits (typically 128)
        security_level: u32,
    };
}

/// Modular addition in the given radix.
///
/// Returns (a + b) mod radix as a u8.
inline fn modAdd(comptime radix: u32, a: u32, b: u32) u8 {
    if (radix == 256) {
        return @as(u8, @truncate(a)) +% @as(u8, @truncate(b));
    }
    return @intCast((a + b) % radix);
}

/// Modular subtraction in the given radix.
///
/// Returns (a - b) mod radix as a u8, handling negative results correctly.
inline fn modSub(comptime radix: u32, a: u32, b: u32) u8 {
    if (radix == 256) {
        return @as(u8, @truncate(a)) -% @as(u8, @truncate(b));
    }
    return @intCast((a + radix - (b % radix)) % radix);
}

/// ES (Expansion-Substitution) layer - forward cipher operation for encryption.
///
/// The ES layer is the core building block of the FAST cipher's SPN structure.
/// It performs expansion, modular addition, S-box substitution, and shifting.
///
/// Parameters:
///   - params: Cipher parameters
///   - pool: S-box pool
///   - data: Input/output buffer (modified in-place)
///   - sbox_index: Index of S-box to use from the pool
pub fn esLayer(
    comptime radix: u32,
    comptime sbox_count: u32,
    params: *const Params(radix),
    pool: *const sbox.SBoxPool(radix, sbox_count),
    data: []u8,
    sbox_index: u32,
) void {
    assert(data.len == params.word_length);
    assert(sbox_index < sbox_count);

    if (data.len != params.word_length) return;
    if (sbox_index >= sbox_count) return;

    const w = params.branch_dist1;
    const wp = params.branch_dist2;
    const ell = params.word_length;

    const box = &pool.sboxes[sbox_index];

    var sum1 = modAdd(radix, data[0], data[ell - wp]);
    box.apply(&sum1);

    const new_last = if (w > 0) blk: {
        var intermediate = modSub(radix, sum1, data[w]);
        box.apply(&intermediate);
        break :blk intermediate;
    } else blk: {
        var double_image = sum1;
        box.apply(&double_image);
        break :blk double_image;
    };

    // Shift left by 1
    std.mem.copyForwards(u8, data[0 .. ell - 1], data[1..ell]);
    data[ell - 1] = new_last;
}

/// DS (De-Substitution) layer - inverse cipher operation for decryption.
///
/// The DS layer is the inverse of the ES layer, performing the same operations
/// in reverse order with inverse S-boxes and operations.
///
/// Parameters:
///   - params: Cipher parameters
///   - pool: S-box pool
///   - data: Input/output buffer (modified in-place)
///   - sbox_index: Index of S-box to use from the pool
pub fn dsLayer(
    comptime radix: u32,
    comptime sbox_count: u32,
    params: *const Params(radix),
    pool: *const sbox.SBoxPool(radix, sbox_count),
    data: []u8,
    sbox_index: u32,
) void {
    assert(data.len == params.word_length);
    assert(sbox_index < sbox_count);

    if (data.len != params.word_length) return;
    if (sbox_index >= sbox_count) return;

    const w = params.branch_dist1;
    const wp = params.branch_dist2;
    const ell = params.word_length;

    const box = &pool.sboxes[sbox_index];

    var x_last = data[ell - 1];
    box.applyInverse(&x_last);

    const intermediate = if (w > 0) blk: {
        var inter = modAdd(radix, x_last, data[w - 1]);
        box.applyInverse(&inter);
        break :blk inter;
    } else blk: {
        box.applyInverse(&x_last);
        break :blk x_last;
    };

    const new_first = modSub(radix, intermediate, data[ell - wp - 1]);

    // Shift right by 1
    std.mem.copyBackwards(u8, data[1..ell], data[0 .. ell - 1]);
    data[0] = new_first;
}

test "layer operations" {
    // Basic smoke test
    const radix = 10;
    const sbox_count = 1;

    const PoolType = sbox.SBoxPool(radix, sbox_count);
    var pool = PoolType.init();

    // Generate S-boxes with test key material
    const key_material: [32]u8 = @splat(0x01);
    pool.generateFromKeyMaterial(&key_material);

    const ParamsType = Params(radix);
    const params = ParamsType{
        .word_length = 4,
        .sbox_count = sbox_count,
        .num_layers = 4,
        .branch_dist1 = 1,
        .branch_dist2 = 1,
        .security_level = 128,
    };

    var data = [_]u8{ 1, 2, 3, 4 };
    const original = data;

    // Apply ES layer
    esLayer(radix, sbox_count, &params, &pool, &data, 0);

    // Should have modified the data
    try std.testing.expect(!std.mem.eql(u8, &data, &original));

    // Apply DS layer
    dsLayer(radix, sbox_count, &params, &pool, &data, 0);

    // Should recover original data (ES and DS are inverses)
    try std.testing.expectEqualSlices(u8, &original, &data);
}
