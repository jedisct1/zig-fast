//! FAST: Format-preserving, Additive, Symmetric Translation cipher
//!
//! ## Usage
//!
//! ```zig
//! const fast = @import("fast");
//!
//! // 1. Calculate recommended parameters
//! const params = try fast.calculateRecommendedParams(10, 16, 128);
//!
//! // 2. Initialize context with a 16-byte key
//! const key = [_]u8{0x2B, 0x7E, ...};
//! var ctx = try fast.init(allocator, &params, &key);
//! defer {
//!     ctx.deinit();
//!     allocator.destroy(ctx);
//! }
//!
//! // 3. Encrypt/decrypt data
//! const tweak = [_]u8{0x00, 0x11, 0x22, ...};
//! const plaintext = [_]u8{1, 2, 3, 4, ...};
//! var ciphertext: [16]u8 = undefined;
//!
//! try fast.encrypt(ctx, &tweak, &plaintext, &ciphertext);
//! try fast.decrypt(ctx, &tweak, &ciphertext, &plaintext);
//! ```

const std = @import("std");

// Import internal modules (not re-exported)
const fast = @import("fast.zig");
const prf = @import("prf.zig");
const prng = @import("prng.zig");
const sbox = @import("sbox.zig");
const layers = @import("layers.zig");
const cenc_cdec = @import("cenc_cdec.zig");

// Public API: Types
pub const Params = fast.Params;
pub const Context = fast.Context;
pub const FastError = fast.FastError;

// Public API: Constants
pub const MAX_RADIX = fast.MAX_RADIX;
pub const SBOX_POOL_SIZE = fast.SBOX_POOL_SIZE;

// Public API: Functions
pub const calculateRecommendedParams = fast.calculateRecommendedParams;
pub const init = fast.init;
pub const encrypt = fast.encrypt;
pub const decrypt = fast.decrypt;

test {
    // Run all tests from submodules
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(fast);
    std.testing.refAllDecls(prf);
    std.testing.refAllDecls(prng);
    std.testing.refAllDecls(sbox);
    std.testing.refAllDecls(layers);
    std.testing.refAllDecls(cenc_cdec);
}
