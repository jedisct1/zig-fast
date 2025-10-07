const std = @import("std");
const assert = std.debug.assert;
const prng = @import("prng.zig");
const prf = @import("prf.zig");

const PrngState = prng.PrngState;

// Constants
const MAX_RADIX: comptime_int = 256;
const AES_KEY_SIZE: comptime_int = 16;
const AES_BLOCK_SIZE: comptime_int = 16;
const DERIVED_KEY_SIZE: comptime_int = 32;

/// S-box (substitution box) structure containing a permutation and its inverse.
///
/// An S-box is a lookup table used in the FAST cipher to perform non-linear
/// substitution operations. Each S-box contains a permutation of values [0..radix)
/// and its inverse, allowing both forward (encryption) and reverse (decryption)
/// substitution operations.
///
/// Properties:
///   - The permutation is a bijection: each input maps to a unique output
///   - The inverse allows efficient decryption
///   - Generated using Fisher-Yates shuffle for uniform distribution
pub fn SBox(comptime radix: u32) type {
    if (radix == 0 or radix > MAX_RADIX) {
        @compileError("Invalid radix");
    }

    return struct {
        const Self = @This();

        perm: [radix]u8, // Permutation array
        inv: [radix]u8, // Inverse permutation

        /// Create a new S-box.
        ///
        /// Initializes arrays but does not populate them.
        /// Call generate() to populate with a permutation.
        pub fn init() Self {
            return Self{
                .perm = undefined,
                .inv = undefined,
            };
        }

        /// Generate S-box permutation using Fisher-Yates shuffle.
        ///
        /// Uses the Fisher-Yates (Knuth) shuffle algorithm with a cryptographic
        /// PRNG to generate a uniformly random permutation. The inverse permutation
        /// is computed automatically.
        ///
        /// Parameters:
        ///   - self: S-box to populate
        ///   - prng_state: PRNG state for random number generation
        pub fn generate(self: *Self, prng_state: *PrngState) void {
            // Initialize permutation to identity
            for (&self.perm, 0..) |*p, i| {
                p.* = @intCast(i);
            }

            // Fisher-Yates shuffle
            var i: u32 = radix;
            while (i > 1) {
                i -= 1;
                const j = prng_state.uniform(i + 1);
                const temp = self.perm[i];
                self.perm[i] = self.perm[j];
                self.perm[j] = temp;
            }

            // Compute inverse permutation
            for (self.perm, 0..) |p, idx| {
                self.inv[p] = @intCast(idx);
            }
        }

        /// Apply S-box forward substitution to a single value.
        ///
        /// Replaces the input value with its permutation.
        ///
        /// PRECONDITION: data.* < radix (checked with assert in debug builds)
        pub inline fn apply(self: *const Self, data: *u8) void {
            assert(data.* < radix);
            data.* = self.perm[data.*];
        }

        /// Apply S-box inverse substitution to a single value.
        ///
        /// Replaces the input value with its inverse permutation (for decryption).
        ///
        /// PRECONDITION: data.* < radix (checked with assert in debug builds)
        pub inline fn applyInverse(self: *const Self, data: *u8) void {
            assert(data.* < radix);
            data.* = self.inv[data.*];
        }
    };
}

/// Pool of S-boxes for the FAST cipher.
///
/// The FAST cipher uses a pool of S-boxes that are selected during encryption
/// and decryption operations based on a pseudorandom sequence. This structure
/// manages a collection of S-boxes, all with the same radix.
pub fn SBoxPool(comptime radix: u32, comptime count: u32) type {
    if (radix < 4 or radix > MAX_RADIX) {
        @compileError("Invalid radix");
    }
    if (count == 0) {
        @compileError("Invalid count");
    }

    const SBoxType = SBox(radix);

    return struct {
        const Self = @This();

        sboxes: [count]SBoxType,

        /// Create a new S-box pool.
        ///
        /// Initializes a pool of S-boxes. The S-boxes are initialized
        /// but not yet populated; call generateFromKeyMaterial() to generate them.
        pub fn init() Self {
            var result: Self = undefined;
            for (&result.sboxes) |*sbox| {
                sbox.* = SBoxType.init();
            }
            return result;
        }

        /// Generate all S-boxes in the pool using PRF-derived key material.
        ///
        /// Derives a PRNG key and IV from the key material and uses it to
        /// generate all S-boxes deterministically via Fisher-Yates shuffle.
        ///
        /// Parameters:
        ///   - self: S-box pool to populate
        ///   - key_material: 32 bytes of PRF-derived key material
        pub fn generateFromKeyMaterial(
            self: *Self,
            key_material: *const [DERIVED_KEY_SIZE]u8,
        ) void {
            assert(key_material.len == DERIVED_KEY_SIZE);
            var key: [AES_KEY_SIZE]u8 = undefined;
            var iv: [AES_BLOCK_SIZE]u8 = undefined;

            // Split key material (don't zeroize IV suffix for S-box generation)
            prng.splitKeyMaterial(key_material, &key, &iv, false);

            var prng_state = PrngState.init(&key, &iv);
            defer prng_state.cleanup();

            for (&self.sboxes) |*sbox| {
                sbox.generate(&prng_state);
            }

            @memset(&key, 0);
            @memset(&iv, 0);
        }
    };
}

test "sbox generation" {
    const SBoxType = SBox(10);
    var sbox = SBoxType.init();

    const key = [_]u8{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    const nonce: [AES_BLOCK_SIZE]u8 = @splat(0);

    var prng_state = PrngState.init(&key, &nonce);
    defer prng_state.cleanup();

    sbox.generate(&prng_state);

    // Verify permutation properties
    var seen: [10]bool = @splat(false);
    for (sbox.perm) |p| {
        try std.testing.expect(p < 10);
        try std.testing.expect(!seen[p]);
        seen[p] = true;
    }

    // Verify inverse
    for (0..10) |i| {
        const p = sbox.perm[i];
        const inv_p = sbox.inv[p];
        try std.testing.expectEqual(@as(u8, @intCast(i)), inv_p);
    }
}

test "sbox pool" {
    const PoolType = SBoxPool(16, 256);
    var pool = PoolType.init();

    try std.testing.expectEqual(@as(usize, 256), pool.sboxes.len);
}
