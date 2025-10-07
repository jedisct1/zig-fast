# FAST Cipher (Zig Implementation)

A pure Zig implementation of the [FAST](https://eprint.iacr.org/2021/1171.pdf) (Format-preserving, Additive, Symmetric Translation) cipher. This library provides format-preserving encryption/decryption that maintains the same format (radix and length) between plaintext and ciphertext, making it ideal for encrypting sensitive data like credit card numbers, SSNs, or other structured data.

## Usage

```zig
const std = @import("std");
const fast = @import("fast");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Calculate recommended security parameters
    const radix = 10; // For decimal numbers (0-9)
    const word_length = 16; // For 16-digit numbers
    const params = try fast.calculateRecommendedParams(radix, word_length, 128);

    // Initialize cipher context with a 16-byte key
    const key = [_]u8{
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
    };

    var ctx = try fast.init(10, 256, allocator, &params, &key);
    defer {
        ctx.deinit();
        allocator.destroy(ctx);
    }

    // Encrypt data (using a tweak for domain separation)
    const tweak = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
    const plaintext = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
    var ciphertext: [16]u8 = undefined;

    try fast.encrypt(10, 256, ctx, &tweak, &plaintext, &ciphertext);

    // Decrypt data
    var recovered: [16]u8 = undefined;
    try fast.decrypt(10, 256, ctx, &tweak, &ciphertext, &recovered);

    // Verify roundtrip
    if (std.mem.eql(u8, &plaintext, &recovered)) {
        std.debug.print("Encryption/decryption successful!\n", .{});
    }
}
```
