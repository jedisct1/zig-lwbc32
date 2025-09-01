# LWBC32: Lightweight 32-bit Block Cipher Library

A Zig implementation of three lightweight block ciphers: SPECK32/64, SIMON32/64, and SIMECK32/64. These ciphers are designed for use in resource-constrained environments and offer high performance in software implementations.

## Ciphers Overview

All three ciphers in this library operate on 32-bit blocks (split into two 16-bit words) with 64-bit keys:

| Cipher      | Block Size | Key Size | Rounds | Structure                     |
| ----------- | ---------- | -------- | ------ | ----------------------------- |
| SPECK32/64  | 32 bits    | 64 bits  | 22     | ARX (Addition, Rotation, XOR) |
| SIMON32/64  | 32 bits    | 64 bits  | 32     | Balanced Feistel              |
| SIMECK32/64 | 32 bits    | 64 bits  | 32     | Feistel                       |

## Building and Running

To build and run the demo application:

```bash
zig build run -Doptimize=ReleaseFast
```

This will display encryption/decryption examples for all three ciphers along with benchmark results.

## Running Tests

To run all tests:

```bash
zig build test
```

## Security Notes

⚠️ **Important Security Considerations**:

1. **32-bit block size vulnerability**: These ciphers use 32-bit blocks, making them vulnerable to birthday attacks with just 2^16 ≈ 65,000 blocks. They should only be used in extremely constrained environments where this is an acceptable trade-off.

2. **64-bit key size limitation**: The 64-bit key size is vulnerable to brute-force attacks with modern computational power.

3. **Intended use**: These lightweight variants are intended for research, educational purposes, or extremely constrained environments where larger block sizes are not feasible.

For production applications requiring strong security, consider using other modern authenticated encryption schemes

## References

1. [NSA Lightweight Cryptography](https://www.nsa.gov/Research-and-Domain-Expertise/Research/Technical-Publications/Lightweight-Cryptography.cfm)
2. [The SIMON and SPECK Families of Lightweight Block Ciphers](https://eprint.iacr.org/2013/404.pdf)
3. [SIMECK: A Family of Lightweight Block Ciphers](https://eprint.iacr.org/2015/612.pdf)
