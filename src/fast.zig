const std = @import("std");
const assert = std.debug.assert;
const prf = @import("prf.zig");
const prng = @import("prng.zig");
const sbox = @import("sbox.zig");
const layers = @import("layers.zig");
const cenc_cdec = @import("cenc_cdec.zig");

pub const Params = layers.Params;

// Public constants
pub const MAX_RADIX: comptime_int = 256;
pub const SBOX_POOL_SIZE: comptime_int = 256;

// Internal cryptographic constants
const AES_BLOCK_SIZE: comptime_int = 16;
const AES_KEY_SIZE: comptime_int = 16;
const MASTER_KEY_SIZE: comptime_int = AES_KEY_SIZE;
const DERIVED_KEY_SIZE: comptime_int = 32;

// Labels for PRF
const LABEL_INSTANCE1 = "instance1";
const LABEL_INSTANCE2 = "instance2";
const LABEL_FPE_POOL = "FPE Pool";
const LABEL_FPE_SEQ = "FPE SEQ";
const LABEL_TWEAK = "tweak";

// Lookup tables for recommended rounds
const round_l_values = [_]u32{ 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 16, 32, 50, 64, 100 };
const round_radices = [_]u32{ 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 100, 128, 256, 1000, 1024, 10000, 65536 };

const round_table = [_][15]u16{
    .{ 165, 135, 117, 105, 96, 89, 83, 78, 74, 68, 59, 52, 52, 53, 57 }, // a = 4
    .{ 131, 107, 93, 83, 76, 70, 66, 62, 59, 54, 48, 46, 47, 48, 53 }, // a = 5
    .{ 113, 92, 80, 72, 65, 61, 57, 54, 51, 46, 44, 43, 44, 46, 52 }, // a = 6
    .{ 102, 83, 72, 64, 59, 55, 51, 48, 46, 43, 41, 41, 43, 45, 50 }, // a = 7
    .{ 94, 76, 66, 59, 54, 50, 47, 44, 42, 41, 39, 39, 42, 44, 50 }, // a = 8
    .{ 88, 72, 62, 56, 51, 47, 44, 42, 40, 39, 38, 38, 41, 43, 49 }, // a = 9
    .{ 83, 68, 59, 53, 48, 45, 42, 39, 39, 38, 37, 37, 40, 43, 49 }, // a = 10
    .{ 79, 65, 56, 50, 46, 43, 40, 38, 38, 37, 36, 37, 40, 42, 48 }, // a = 11
    .{ 76, 62, 54, 48, 44, 41, 38, 37, 37, 36, 35, 36, 39, 42, 48 }, // a = 12
    .{ 73, 60, 52, 47, 43, 39, 37, 36, 36, 35, 34, 36, 39, 41, 48 }, // a = 13
    .{ 71, 58, 50, 45, 41, 38, 36, 36, 35, 34, 34, 35, 39, 41, 47 }, // a = 14
    .{ 69, 57, 49, 44, 40, 37, 36, 35, 34, 34, 33, 35, 38, 41, 47 }, // a = 15
    .{ 67, 55, 48, 43, 39, 36, 35, 34, 34, 33, 33, 35, 38, 41, 47 }, // a = 16
    .{ 40, 33, 28, 27, 26, 26, 25, 25, 25, 26, 26, 30, 34, 37, 44 }, // a = 100
    .{ 38, 31, 27, 26, 25, 25, 25, 25, 25, 25, 26, 30, 34, 37, 44 }, // a = 128
    .{ 33, 27, 25, 24, 23, 23, 23, 23, 23, 24, 25, 29, 33, 37, 44 }, // a = 256
    .{ 32, 22, 21, 21, 21, 21, 21, 21, 21, 22, 23, 28, 32, 36, 43 }, // a = 1000
    .{ 32, 22, 21, 21, 21, 21, 21, 21, 21, 22, 23, 28, 32, 36, 43 }, // a = 1024
    .{ 32, 22, 18, 18, 18, 18, 19, 19, 19, 20, 21, 27, 32, 35, 42 }, // a = 10000
    .{ 32, 22, 17, 17, 17, 17, 17, 18, 18, 19, 21, 26, 31, 35, 42 }, // a = 65536
};

/// Errors that can occur during FAST cipher operations.
pub const FastError = error{
    /// Radix parameter is out of valid range [4, 256]
    InvalidRadix,
    /// Word length parameter is invalid
    InvalidWordLength,
    /// S-box count parameter is invalid
    InvalidSBoxCount,
    /// Branch distance parameters are invalid
    InvalidBranchDist1,
    InvalidBranchDist2,
    /// Input/output length doesn't match word length
    InvalidLength,
    /// Input value exceeds radix
    InvalidValue,
    /// Generic parameter validation failure
    InvalidParameters,
    /// Memory allocation failed
    OutOfMemory,
};

/// FAST cipher context.
///
/// This structure holds all state needed for FAST encryption and decryption:
/// - Cipher parameters (radix, word length, number of layers, etc.)
/// - S-box pool for substitutions
/// - Master key for key derivation
/// - Cached sequence and tweak for performance optimization
///
/// The context is initialized with init() and must be freed with deinit().
/// A single context can be reused for multiple encrypt/decrypt operations
/// with different tweaks.
pub fn Context(comptime radix: u32, comptime sbox_count: u32) type {
    const SBoxPoolType = sbox.SBoxPool(radix, sbox_count);
    const ParamsType = Params(radix);

    return struct {
        const Self = @This();

        params: ParamsType,
        sbox_pool: SBoxPoolType,
        master_key: [MASTER_KEY_SIZE]u8,
        seq_buffer: []u32,
        cached_tweak: ?[]u8,
        has_cached_seq: bool,
        allocator: std.mem.Allocator,

        /// Free all resources associated with this context.
        ///
        /// Zeroizes the master key to prevent key material from remaining in memory.
        /// After calling deinit(), the context should not be used.
        pub fn deinit(self: *Self) void {
            self.allocator.free(self.seq_buffer);
            if (self.cached_tweak) |tweak| {
                self.allocator.free(tweak);
            }
            @memset(&self.master_key, 0);
        }
    };
}

/// Linear interpolation
fn interpolate(x: f64, x0: f64, x1: f64, y0: f64, y1: f64) f64 {
    if (x1 == x0) return y0;
    const t = (x - x0) / (x1 - x0);
    if (t <= 0.0) return y0;
    if (t >= 1.0) return y1;
    return y0 + t * (y1 - y0);
}

/// Get recommended rounds for a specific row and word length
fn roundsForRow(row_index: usize, ell: f64) f64 {
    const row = round_table[row_index];
    const l_count = round_l_values.len;

    if (ell <= @as(f64, @floatFromInt(round_l_values[0]))) {
        return @floatFromInt(row[0]);
    }
    if (ell >= @as(f64, @floatFromInt(round_l_values[l_count - 1]))) {
        const last: f64 = @floatFromInt(row[l_count - 1]);
        const ratio = @sqrt(ell / @as(f64, @floatFromInt(round_l_values[l_count - 1])));
        const projected = last * ratio;
        return if (projected < last) last else projected;
    }

    for (1..l_count) |i| {
        const l_prev: f64 = @floatFromInt(round_l_values[i - 1]);
        const l_curr: f64 = @floatFromInt(round_l_values[i]);
        if (ell <= l_curr) {
            const r_prev: f64 = @floatFromInt(row[i - 1]);
            const r_curr: f64 = @floatFromInt(row[i]);
            return interpolate(ell, l_prev, l_curr, r_prev, r_curr);
        }
    }

    return @floatFromInt(row[l_count - 1]);
}

/// Lookup recommended rounds with radix interpolation
fn lookupRecommendedRounds(radix: u32, ell: f64) f64 {
    const radix_count = round_radices.len;

    if (radix <= round_radices[0]) {
        return roundsForRow(0, ell);
    }
    if (radix >= round_radices[radix_count - 1]) {
        return roundsForRow(radix_count - 1, ell);
    }

    for (1..radix_count) |i| {
        const r_prev = round_radices[i - 1];
        const r_curr = round_radices[i];
        if (radix <= r_curr) {
            const rounds_prev = roundsForRow(i - 1, ell);
            const rounds_curr = roundsForRow(i, ell);
            const log_prev = @log(@as(f64, @floatFromInt(r_prev)));
            const log_curr = @log(@as(f64, @floatFromInt(r_curr)));
            const log_radix = @log(@as(f64, @floatFromInt(radix)));
            return interpolate(log_radix, log_prev, log_curr, rounds_prev, rounds_curr);
        }
    }

    return roundsForRow(radix_count - 1, ell);
}

/// Calculate recommended cipher parameters for given radix, word length, and security level.
///
/// This function computes optimal FAST cipher parameters using lookup tables
/// and interpolation based on security analysis from the FAST paper. It determines:
/// - Number of SPN rounds needed for desired security
/// - Branch distances (w and w') for optimal diffusion
/// - Total number of layers
///
/// Parameters:
///   - radix: Base of the numeral system (must be >= 4)
///   - word_length: Length of plaintext/ciphertext (must be >= 2)
///   - security_level: Target security in bits (0 = default 128 bits)
///
/// Returns: Fully initialized Params struct with optimal security parameters
pub fn calculateRecommendedParams(
    comptime radix: u32,
    word_length: u32,
    security_level: u32,
) FastError!Params(radix) {
    if (radix < 4 or word_length < 2) {
        return FastError.InvalidParameters;
    }

    const sec_level = if (security_level == 0) 128 else security_level;

    // Branch distances per specification
    const w_candidate = @as(u32, @intFromFloat(@ceil(@sqrt(@as(f64, @floatFromInt(word_length))))));
    const branch_dist1 = if (word_length <= 2)
        0
    else
        @min(w_candidate, word_length - 2);

    const branch_dist2 = if (branch_dist1 > 1) branch_dist1 - 1 else 1;

    var rounds = lookupRecommendedRounds(radix, @floatFromInt(word_length));
    if (rounds < 1.0) {
        rounds = 1.0;
    }

    const rounds_u: u32 = @intFromFloat(@ceil(rounds));

    return Params(radix){
        .word_length = word_length,
        .sbox_count = SBOX_POOL_SIZE,
        .num_layers = rounds_u * word_length,
        .branch_dist1 = branch_dist1,
        .branch_dist2 = branch_dist2,
        .security_level = sec_level,
    };
}

/// Write u32 in big-endian format
fn writeU32Be(value: u32, out: *[4]u8) void {
    std.mem.writeInt(u32, out, value, .big);
}

/// Encode PRF parts (matching C implementation)
fn encodeParts(allocator: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    var total: usize = 4; // part count
    for (parts) |part| {
        total += 4 + part.len; // length + data
    }

    var buffer = try allocator.alloc(u8, total);
    var pos: usize = 0;

    // Write part count
    writeU32Be(@intCast(parts.len), buffer[pos..][0..4]);
    pos += 4;

    for (parts) |part| {
        writeU32Be(@intCast(part.len), buffer[pos..][0..4]);
        pos += 4;
        if (part.len > 0) {
            @memcpy(buffer[pos..][0..part.len], part);
            pos += part.len;
        }
    }

    return buffer;
}

/// Build setup1 input for S-box pool generation
fn buildSetup1Input(
    comptime radix: u32,
    allocator: std.mem.Allocator,
    params: *const Params(radix),
) ![]u8 {
    var a_be: [4]u8 = undefined;
    var m_be: [4]u8 = undefined;
    writeU32Be(radix, &a_be);
    writeU32Be(params.sbox_count, &m_be);

    const parts = [_][]const u8{
        LABEL_INSTANCE1,
        &a_be,
        &m_be,
        LABEL_FPE_POOL,
    };

    return encodeParts(allocator, &parts);
}

/// Build setup2 input for sequence generation
fn buildSetup2Input(
    comptime radix: u32,
    allocator: std.mem.Allocator,
    params: *const Params(radix),
    tweak: []const u8,
) ![]u8 {
    var a_be: [4]u8 = undefined;
    var m_be: [4]u8 = undefined;
    var ell_be: [4]u8 = undefined;
    var n_be: [4]u8 = undefined;
    var w_be: [4]u8 = undefined;
    var wp_be: [4]u8 = undefined;

    writeU32Be(radix, &a_be);
    writeU32Be(params.sbox_count, &m_be);
    writeU32Be(params.word_length, &ell_be);
    writeU32Be(params.num_layers, &n_be);
    writeU32Be(params.branch_dist1, &w_be);
    writeU32Be(params.branch_dist2, &wp_be);

    const parts = [_][]const u8{
        LABEL_INSTANCE1,
        &a_be,
        &m_be,
        LABEL_INSTANCE2,
        &ell_be,
        &n_be,
        &w_be,
        &wp_be,
        LABEL_FPE_SEQ,
        LABEL_TWEAK,
        tweak,
    };

    return encodeParts(allocator, &parts);
}

/// Ensure sequence is cached for the given tweak
fn ensureSequence(
    comptime radix: u32,
    comptime sbox_count: u32,
    ctx: *Context(radix, sbox_count),
    tweak: []const u8,
) !void {
    // Check if we can use cached sequence
    if (ctx.has_cached_seq) {
        if (ctx.cached_tweak) |cached| {
            if (std.mem.eql(u8, cached, tweak)) {
                return;
            }
        } else if (tweak.len == 0) {
            return;
        }
    }

    // Build input for PRF
    const input = try buildSetup2Input(radix, ctx.allocator, &ctx.params, tweak);
    defer ctx.allocator.free(input);

    // Derive key material
    var kseq_material: [DERIVED_KEY_SIZE]u8 = undefined;
    try prf.deriveKey(ctx.allocator, &ctx.master_key, input, &kseq_material);
    defer @memset(&kseq_material, 0);

    // Generate sequence
    prng.generateSequence(ctx.seq_buffer, ctx.params.sbox_count, &kseq_material);

    // Cache tweak
    if (ctx.cached_tweak) |old_tweak| {
        ctx.allocator.free(old_tweak);
        ctx.cached_tweak = null;
    }

    if (tweak.len > 0) {
        const new_cache = try ctx.allocator.alloc(u8, tweak.len);
        @memcpy(new_cache, tweak);
        ctx.cached_tweak = new_cache;
    }

    ctx.has_cached_seq = true;
}

/// Initialize a new FAST cipher context.
///
/// Creates and initializes a FAST cipher context with the given parameters and key.
/// This involves:
/// 1. Validating all parameters for correctness
/// 2. Deriving S-box pool key from master key using PRF
/// 3. Generating the S-box pool deterministically
/// 4. Allocating buffers for sequence caching
///
/// The returned context must be freed with context.deinit() and allocator.destroy().
///
/// Parameters:
///   - allocator: Memory allocator for context and internal structures
///   - params: Cipher parameters (from calculateRecommendedParams or custom)
///   - key: 16-byte master key for key derivation
///
/// Returns: Pointer to initialized context, or error if parameters are invalid
///
/// Example:
///   var ctx = try fast.init(10, 256, allocator, &params, &key);
///   defer {
///       ctx.deinit();
///       allocator.destroy(ctx);
///   }
pub fn init(
    comptime radix: u32,
    comptime sbox_count: u32,
    allocator: std.mem.Allocator,
    params: *const Params(radix),
    key: *const [MASTER_KEY_SIZE]u8,
) FastError!*Context(radix, sbox_count) {
    assert(key.len == MASTER_KEY_SIZE);

    // Validate parameters
    if (radix < 4 or radix > MAX_RADIX) {
        return FastError.InvalidRadix;
    }
    if (params.word_length < 2 or params.num_layers == 0 or
        params.num_layers % params.word_length != 0)
    {
        return FastError.InvalidWordLength;
    }
    if (sbox_count == 0) {
        return FastError.InvalidSBoxCount;
    }
    if (params.branch_dist1 > params.word_length - 2) {
        return FastError.InvalidBranchDist1;
    }
    if (params.branch_dist2 == 0 or params.branch_dist2 > params.word_length - 1 or
        params.branch_dist2 > params.word_length - params.branch_dist1 - 1)
    {
        return FastError.InvalidBranchDist2;
    }

    // Allocate context
    const ContextType = Context(radix, sbox_count);
    const ctx = try allocator.create(ContextType);
    errdefer allocator.destroy(ctx);

    // Allocate sequence buffer
    const seq_buffer = try allocator.alloc(u32, params.num_layers);
    errdefer allocator.free(seq_buffer);

    // Build setup1 input and derive S-box pool key
    const setup1_input = try buildSetup1Input(radix, allocator, params);
    defer allocator.free(setup1_input);

    var pool_key_material: [DERIVED_KEY_SIZE]u8 = undefined;
    try prf.deriveKey(allocator, key, setup1_input, &pool_key_material);
    defer @memset(&pool_key_material, 0);

    // Create and generate S-box pool
    const SBoxPoolType = sbox.SBoxPool(radix, sbox_count);
    var pool = SBoxPoolType.init();
    pool.generateFromKeyMaterial(&pool_key_material);

    ctx.* = .{
        .params = params.*,
        .sbox_pool = pool,
        .master_key = key.*,
        .seq_buffer = seq_buffer,
        .cached_tweak = null,
        .has_cached_seq = false,
        .allocator = allocator,
    };

    return ctx;
}

/// Encrypt plaintext using FAST cipher.
///
/// Performs format-preserving encryption on the input plaintext using the
/// given tweak for domain separation. The ciphertext will have the same format
/// (radix and length) as the plaintext.
///
/// Parameters:
///   - ctx: Initialized FAST context
///   - tweak: Tweak value for domain separation (can be empty)
///   - plaintext: Input data to encrypt (each value must be < radix)
///   - ciphertext: Output buffer for encrypted data (same length as plaintext)
///
/// Returns: FastError if input is invalid
///
/// The plaintext and ciphertext buffers must be exactly ctx.params.word_length bytes.
/// All values in plaintext must be in the range [0, radix).
pub fn encrypt(
    comptime radix: u32,
    comptime sbox_count: u32,
    ctx: *Context(radix, sbox_count),
    tweak: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
) FastError!void {
    if (plaintext.len != ctx.params.word_length or ciphertext.len != ctx.params.word_length) {
        return FastError.InvalidLength;
    }

    // Validate plaintext values
    for (plaintext) |p| {
        if (p >= radix) {
            return FastError.InvalidValue;
        }
    }

    try ensureSequence(radix, sbox_count, ctx, tweak);
    cenc_cdec.cenc(radix, sbox_count, &ctx.params, &ctx.sbox_pool, ctx.seq_buffer, plaintext, ciphertext);
}

/// Decrypt ciphertext using FAST cipher.
///
/// Performs format-preserving decryption on the input ciphertext using the
/// given tweak. The plaintext will be recovered exactly if the same tweak
/// is used as during encryption.
///
/// Parameters:
///   - ctx: Initialized FAST context
///   - tweak: Tweak value (must match the one used for encryption)
///   - ciphertext: Input data to decrypt (each value must be < radix)
///   - plaintext: Output buffer for decrypted data (same length as ciphertext)
///
/// Returns: FastError if input is invalid
///
/// The ciphertext and plaintext buffers must be exactly ctx.params.word_length bytes.
/// All values in ciphertext must be in the range [0, radix).
pub fn decrypt(
    comptime radix: u32,
    comptime sbox_count: u32,
    ctx: *Context(radix, sbox_count),
    tweak: []const u8,
    ciphertext: []const u8,
    plaintext: []u8,
) FastError!void {
    if (ciphertext.len != ctx.params.word_length or plaintext.len != ctx.params.word_length) {
        return FastError.InvalidLength;
    }

    // Validate ciphertext values
    for (ciphertext) |c| {
        if (c >= radix) {
            return FastError.InvalidValue;
        }
    }

    try ensureSequence(radix, sbox_count, ctx, tweak);
    cenc_cdec.cdec(radix, sbox_count, &ctx.params, &ctx.sbox_pool, ctx.seq_buffer, ciphertext, plaintext);
}

test "parameter calculation" {
    const radix = 10;
    const params = try calculateRecommendedParams(radix, 16, 0);

    try std.testing.expectEqual(@as(u32, 16), params.word_length);
    try std.testing.expectEqual(@as(u32, 128), params.security_level);
    try std.testing.expect(params.num_layers > 0);
    try std.testing.expect(params.num_layers % params.word_length == 0);
}

test "encrypt decrypt roundtrip" {
    const allocator = std.testing.allocator;
    const radix = 10;
    const sbox_count = SBOX_POOL_SIZE;

    const params = try calculateRecommendedParams(radix, 16, 128);

    const key = [_]u8{
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    };

    var ctx = try init(radix, sbox_count, allocator, &params, &key);
    defer {
        ctx.deinit();
        allocator.destroy(ctx);
    }

    const tweak = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
    const plaintext = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
    var ciphertext: [16]u8 = undefined;
    var recovered: [16]u8 = undefined;

    try encrypt(radix, sbox_count, ctx, &tweak, &plaintext, &ciphertext);
    try decrypt(radix, sbox_count, ctx, &tweak, &ciphertext, &recovered);

    try std.testing.expectEqualSlices(u8, &plaintext, &recovered);
}
