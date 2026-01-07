# Lightweight Block Cipher Library

A Zig implementation of lightweight block ciphers from the SPECK/SIMON family. These ciphers are designed for use in resource-constrained environments and offer high performance in software implementations.

## Ciphers Overview

| Cipher       | Block Size | Key Size  | Rounds | Word Size | Structure                     |
| ------------ | ---------- | --------- | ------ | --------- | ----------------------------- |
| SPECK32/64   | 32 bits    | 64 bits   | 22     | 16-bit    | ARX (Addition, Rotation, XOR) |
| SPECK64/128  | 64 bits    | 128 bits  | 27     | 32-bit    | ARX (Addition, Rotation, XOR) |
| SIMON32/64   | 32 bits    | 64 bits   | 32     | 16-bit    | Balanced Feistel              |
| SIMECK32/64  | 32 bits    | 64 bits   | 32     | 16-bit    | Feistel                       |

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

## Security Notes

**Important Security Considerations**:

1. **32-bit block size vulnerability**: The 32-bit variants use small blocks, making them vulnerable to birthday attacks with just 2^16 blocks. They should only be used in extremely constrained environments.

2. **64-bit block size**: SPECK64/128 provides better security margins (birthday bound at 2^32 blocks) and 128-bit key security against brute force.

3. **Intended use**: These lightweight ciphers are intended for constrained environments where larger block sizes are not feasible.

For applications requiring strong security, consider using other authenticated encryption schemes.

## References

1. [NSA Lightweight Cryptography](https://www.nsa.gov/Research-and-Domain-Expertise/Research/Technical-Publications/Lightweight-Cryptography.cfm)
2. [The SIMON and SPECK Families of Lightweight Block Ciphers](https://eprint.iacr.org/2013/404.pdf)
3. [SIMECK: A Family of Lightweight Block Ciphers](https://eprint.iacr.org/2015/612.pdf)
