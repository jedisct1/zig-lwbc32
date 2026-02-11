# Lightweight Block Cipher Library

A Zig implementation of lightweight block ciphers from the SPECK/SIMON family and the SPARKLE suite. These ciphers are designed for use in resource-constrained environments and offer high performance in software implementations.

## Ciphers Overview

| Cipher       | Block Size | Key Size | Rounds | Word Size | Structure                     |
| ------------ | ---------- | -------- | ------ | --------- | ----------------------------- |
| SPECK32/64   | 32 bits    | 64 bits  | 22     | 16-bit    | ARX (Addition, Rotation, XOR) |
| SPECK48/96   | 48 bits    | 96 bits  | 23     | 24-bit    | ARX (Addition, Rotation, XOR) |
| SPECK64/128  | 64 bits    | 128 bits | 27     | 32-bit    | ARX (Addition, Rotation, XOR) |
| SPECK96/144  | 96 bits    | 144 bits | 29     | 48-bit    | ARX (Addition, Rotation, XOR) |
| SIMON32/64   | 32 bits    | 64 bits  | 32     | 16-bit    | Balanced Feistel              |
| SIMON48/96   | 48 bits    | 96 bits  | 36     | 24-bit    | Balanced Feistel              |
| SIMON64/128  | 64 bits    | 128 bits | 44     | 32-bit    | Balanced Feistel              |
| SIMON96/144  | 96 bits    | 144 bits | 54     | 48-bit    | Balanced Feistel              |
| SIMECK32/64  | 32 bits    | 64 bits  | 32     | 16-bit    | Feistel (hybrid)              |
| SIMECK64/128 | 64 bits    | 128 bits | 44     | 32-bit    | Feistel (hybrid)              |
| CRAX-S-10    | 64 bits    | 128 bits | 10     | 32-bit    | Alzette ARX-box               |

### Whitened Variants

All ciphers have whitened variants with extended keys that add XOR whitening before and after encryption:

| Cipher           | Block Size | Key Size | Structure                        |
| ---------------- | ---------- | -------- | -------------------------------- |
| Speck32Whitened  | 32 bits    | 128 bits | 64-bit cipher + 32-bit pre/post  |
| Speck48Whitened  | 48 bits    | 192 bits | 96-bit cipher + 48-bit pre/post  |
| Speck64Whitened  | 64 bits    | 256 bits | 128-bit cipher + 64-bit pre/post |
| Speck96Whitened  | 96 bits    | 336 bits | 144-bit cipher + 96-bit pre/post |
| Simon32Whitened  | 32 bits    | 128 bits | 64-bit cipher + 32-bit pre/post  |
| Simon48Whitened  | 48 bits    | 192 bits | 96-bit cipher + 48-bit pre/post  |
| Simon64Whitened  | 64 bits    | 256 bits | 128-bit cipher + 64-bit pre/post |
| Simon96Whitened  | 96 bits    | 336 bits | 144-bit cipher + 96-bit pre/post |
| Simeck32Whitened | 32 bits    | 128 bits | 64-bit cipher + 32-bit pre/post  |
| Simeck64Whitened | 64 bits    | 256 bits | 128-bit cipher + 64-bit pre/post |
| CraxWhitened     | 64 bits    | 256 bits | 128-bit cipher + 64-bit pre/post |

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

// 48-bit block cipher (24-bit words)
const speck48 = lwbc32.Speck48.init(.{ 0x020100, 0x0a0908, 0x121110, 0x1a1918 });
const ct48 = speck48.encrypt(.{ 0x6d2073, 0x696874 });

// 64-bit block ciphers
const simon64 = lwbc32.Simon64.init(.{ 0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918 });

// CRAX-S-10 (64-bit block, 128-bit key, no key schedule)
const crax = lwbc32.Crax.init(.{ 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c });
const ct_crax = crax.encrypt(.{ 0x33221100, 0x77665544 });

// 96-bit block ciphers (48-bit words, 3-word keys)
const speck96 = lwbc32.Speck96.init(.{ 0x050403020100, 0x0d0c0b0a0908, 0x151413121110 });
const ct96 = speck96.encrypt(.{ 0x656d6974206e, 0x69202c726576 });

// Whitened variants (extended keys)
const speck32w = lwbc32.Speck32Whitened.init(.{
    0x0100, 0x0908, 0x1110, 0x1918,  // cipher key
    0xdead, 0xbeef,                  // pre-whitening key
    0xcafe, 0xbabe,                  // post-whitening key
});

// Byte-oriented interface
const ct_bytes = speck32.encryptBlock(.{ 0x74, 0x65, 0x4c, 0x69 });
const pt_bytes = speck32.decryptBlock(ct_bytes);

// Key from byte array (all ciphers support this)
const speck48b = lwbc32.Speck48.fromBytes(.{
    0x00, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x10, 0x11, 0x12, 0x18, 0x19, 0x1a,
});
```

## Performance

Benchmark results on Apple M-series (10 million encryptions, ReleaseFast):

| Cipher   | Time     | Ops/sec | Throughput |
| -------- | -------- | ------- | ---------- |
| SPECK32  | 258 ms   | 38.7M   | 1.24 Gbps  |
| SPECK48  | 236 ms   | 42.5M   | 2.04 Gbps  |
| SPECK64  | 194 ms   | 51.5M   | 3.29 Gbps  |
| SPECK96  | 290 ms   | 34.5M   | 3.32 Gbps  |
| SIMON32  | 464 ms   | 21.6M   | 0.69 Gbps  |
| SIMON48  | 569 ms   | 17.6M   | 0.84 Gbps  |
| SIMON64  | 427 ms   | 23.4M   | 1.50 Gbps  |
| SIMON96  | 844 ms   | 11.9M   | 1.14 Gbps  |
| SIMECK32 | 443 ms   | 22.6M   | 0.72 Gbps  |
| SIMECK64 | 420 ms   | 23.7M   | 1.53 Gbps  |
| CRAX     | 427 ms   | 23.4M   | 1.50 Gbps  |

SPECK is faster due to fewer rounds and simpler ARX operations. CRAX has only 10 steps but each step (Alzette) involves more operations. Whitened variants have minimal overhead (~2-3%).

## Security Notes

**Important Security Considerations**:

1. **32-bit block size vulnerability**: The 32-bit variants use small blocks, making them vulnerable to birthday attacks with just 2^16 blocks. They should only be used in extremely constrained environments.

2. **48-bit block size**: SPECK48/96 and SIMON48/96 offer slightly better margins (birthday bound at 2^24 blocks) but are still limited for high-volume applications.

3. **64-bit block size**: SPECK64/128, SIMON64/128, and CRAX-S-10 provide better security margins (birthday bound at 2^32 blocks) and 128-bit key security against brute force.

4. **96-bit block size**: SPECK96/144 and SIMON96/144 push the birthday bound to 2^48 blocks with 144-bit keys, offering a middle ground between lightweight and conventional ciphers.

5. **Intended use**: These lightweight ciphers are intended for constrained environments where larger block sizes are not feasible.

For applications requiring strong security, consider using other authenticated encryption schemes.

## References

1. [NSA Lightweight Cryptography](https://www.nsa.gov/Research-and-Domain-Expertise/Research/Technical-Publications/Lightweight-Cryptography.cfm)
2. [The SIMON and SPECK Families of Lightweight Block Ciphers](https://eprint.iacr.org/2013/404.pdf)
3. [SIMECK: A Family of Lightweight Block Ciphers](https://eprint.iacr.org/2015/612.pdf)
4. [Alzette: A 64-Bit ARX-box (CRYPTO 2020)](https://eprint.iacr.org/2019/1378.pdf)
