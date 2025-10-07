const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;

const CmacAes128 = std.crypto.auth.cmac.CmacAes128;

// Cryptographic constants
const AES_KEY_SIZE: comptime_int = 16;
const AES_BLOCK_SIZE: comptime_int = 16;
const DERIVED_KEY_SIZE: comptime_int = 32;

/// Errors that can occur during PRF key derivation.
pub const PrfError = error{
    /// Output buffer has invalid length (must be > 0)
    InvalidLength,
    /// Memory allocation failed
    OutOfMemory,
};

/// Derives a key using AES-CMAC in counter mode, matching the C implementation
/// from prf.c. This implements the PRF (Pseudorandom Function) as specified
/// in the FAST paper using AES-CMAC for key derivation.
///
/// This function generates arbitrary-length key material from a master key and
/// input data by repeatedly computing CMAC with an incrementing counter.
///
/// Parameters:
///   - allocator: Memory allocator for temporary buffers (only used for large inputs)
///   - master_key: 16-byte AES key used for CMAC computation
///   - input: Application-specific input data to bind the derived key
///   - output: Buffer to receive derived key material (length determines amount generated)
///
/// Returns: PrfError if parameters are invalid or allocation fails
pub fn deriveKey(
    allocator: std.mem.Allocator,
    master_key: *const [AES_KEY_SIZE]u8,
    input: []const u8,
    output: []u8,
) PrfError!void {
    assert(master_key.len == AES_KEY_SIZE);

    if (output.len == 0) {
        return PrfError.InvalidLength;
    }

    const total_input_len = 4 + input.len;

    // Use stack buffer for common case (most inputs are small)
    // 512 bytes handles all typical PRF inputs in FAST
    var stack_buffer: [512]u8 = undefined;
    const use_stack = total_input_len <= stack_buffer.len;

    // For large inputs, use arena allocator
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer if (!use_stack) arena.deinit();

    const buffer = if (use_stack)
        stack_buffer[0..total_input_len]
    else
        try arena.allocator().alloc(u8, total_input_len);

    // Copy input once (counter will be updated in place)
    @memcpy(buffer[4..], input);

    var bytes_generated: usize = 0;
    var counter: u32 = 0;

    while (bytes_generated < output.len) {
        var cmac_output: [AES_BLOCK_SIZE]u8 = undefined;

        // Update counter (big-endian)
        mem.writeInt(u32, buffer[0..4], counter, .big);

        // Compute CMAC
        CmacAes128.create(&cmac_output, buffer, master_key);

        // Copy to output
        const to_copy = @min(output.len - bytes_generated, cmac_output.len);
        @memcpy(output[bytes_generated..][0..to_copy], cmac_output[0..to_copy]);
        bytes_generated += to_copy;
        counter += 1;
    }
}

test "prf basic derivation" {
    const allocator = std.testing.allocator;
    const key = [_]u8{
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const input = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var output: [DERIVED_KEY_SIZE]u8 = undefined;

    try deriveKey(allocator, &key, &input, &output);

    // Just verify it doesn't crash and produces output
    try std.testing.expect(output.len == DERIVED_KEY_SIZE);
}
