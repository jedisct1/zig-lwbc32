# Lightweight Block Cipher Library

A Zig implementation of lightweight block ciphers from the SPECK/SIMON family. These ciphers are designed for use in resource-constrained environments and offer high performance in software implementations.

## Ciphers Overview

| Cipher       | Block Size | Key Size | Rounds | Word Size | Structure                     |
| ------------ | ---------- | -------- | ------ | --------- | ----------------------------- |
| SPECK32/64   | 32 bits    | 64 bits  | 22     | 16-bit    | ARX (Addition, Rotation, XOR) |
| SPECK64/128  | 64 bits    | 128 bits | 27     | 32-bit    | ARX (Addition, Rotation, XOR) |
| SIMON32/64   | 32 bits    | 64 bits  | 32     | 16-bit    | Balanced Feistel              |
| SIMON64/128  | 64 bits    | 128 bits | 44     | 32-bit    | Balanced Feistel              |
| SIMECK32/64  | 32 bits    | 64 bits  | 32     | 16-bit    | Feistel (hybrid)              |
| SIMECK64/128 | 64 bits    | 128 bits | 44     | 32-bit    | Feistel (hybrid)              |

### Whitened Variants

All ciphers have whitened variants with extended keys that add XOR whitening before and after encryption:

| Cipher           | Block Size | Key Size | Structure                        |
| ---------------- | ---------- | -------- | -------------------------------- |
| Speck32Whitened  | 32 bits    | 128 bits | 64-bit cipher + 32-bit pre/post  |
| Speck64Whitened  | 64 bits    | 256 bits | 128-bit cipher + 64-bit pre/post |
| Simon32Whitened  | 32 bits    | 128 bits | 64-bit cipher + 32-bit pre/post  |
| Simon64Whitened  | 64 bits    | 256 bits | 128-bit cipher + 64-bit pre/post |
| Simeck32Whitened | 32 bits    | 128 bits | 64-bit cipher + 32-bit pre/post  |
| Simeck64Whitened | 64 bits    | 256 bits | 128-bit cipher + 64-bit pre/post |

## Building and Running

To build and run the demo application:

```bash
zig build run -Doptimize=ReleaseFast
```

This will display encryption/decryption examples for all ciphers along with benchmark results.

## Running Tests

To run all tests:

```bash
zig build test
```

## Usage

Add `lwbc32` as a dependency in your `build.zig.zon`, then:

```zig
const lwbc32 = @import("lwbc32");

// Standard ciphers
const speck32 = lwbc32.Speck32.init(.{ 0x0100, 0x0908, 0x1110, 0x1918 });
const ciphertext = speck32.encrypt(.{ 0x6574, 0x694c });
const plaintext = speck32.decrypt(ciphertext);

// 64-bit block ciphers
const simon64 = lwbc32.Simon64.init(.{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 });

// Whitened variants (extended keys)
const speck32w = lwbc32.Speck32Whitened.init(.{
    0x0100, 0x0908, 0x1110, 0x1918,  // cipher key
    0xdead, 0xbeef,                  // pre-whitening key
    0xcafe, 0xbabe,                  // post-whitening key
});

// Byte-oriented interface
const ct_bytes = speck32.encryptBlock(.{ 0x74, 0x65, 0x4c, 0x69 });
const pt_bytes = speck32.decryptBlock(ct_bytes);
```

## Security Notes

**Important Security Considerations**:

1. **32-bit block size vulnerability**: The 32-bit variants use small blocks, making them vulnerable to birthday attacks with just 2^16 blocks. They should only be used in extremely constrained environments.

2. **64-bit block size**: SPECK64/128 and SIMON64/128 provide better security margins (birthday bound at 2^32 blocks) and 128-bit key security against brute force.

3. **Intended use**: These lightweight ciphers are intended for constrained environments where larger block sizes are not feasible.

For applications requiring strong security, consider using other authenticated encryption schemes.

## References

1. [NSA Lightweight Cryptography](https://www.nsa.gov/Research-and-Domain-Expertise/Research/Technical-Publications/Lightweight-Cryptography.cfm)
2. [The SIMON and SPECK Families of Lightweight Block Ciphers](https://eprint.iacr.org/2013/404.pdf)
3. [SIMECK: A Family of Lightweight Block Ciphers](https://eprint.iacr.org/2015/612.pdf)
