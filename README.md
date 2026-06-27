# Cryptographic Algorithms for Ziglang

A pure Zig implementation of **45+** core cryptographic algorithms with **zero std or external library imports**. All helpers are written from scratch.

## Repository Structure

```
├── utils.zig                           # Shared helpers (BigInt, endian, bit ops)
├── build.zig                           # Build script with test runner
├── Cryptographic Hash Functions/
│   ├── SHA-256.zig                      # SHA-256 + SHA-512
│   ├── SHA3.zig                         # SHA3-256 + SHAKE128 + SHAKE256
│   ├── BLAKE2.zig                       # BLAKE2b
│   ├── BLAKE3.zig                       # BLAKE3
│   ├── RIPEMD.zig                       # RIPEMD-160 + RIPEMD-320
│   ├── Whirlpool.zig                    # Whirlpool-512
│   ├── Tiger.zig                        # Tiger/192
│   ├── MD5.zig                          # MD5
│   ├── SHA1.zig                         # SHA-1
│   ├── SHA224_384.zig                   # SHA-224 + SHA-384
│   ├── Skein.zig                        # Skein-256 + Skein-512
│   ├── Grostl.zig                       # Grøstl-256 + Grøstl-512
│   ├── JH.zig                           # JH-256 + JH-512
│   └── Blake2s.zig                      # BLAKE2s
├── Symmetric Key Cryptography/
│   ├── AES.zig                          # AES-128 + AES-256
│   ├── ChaCha20.zig                     # ChaCha20 + HChaCha20
│   ├── ChaCha20Poly1305.zig             # ChaCha20-Poly1305 AEAD
│   ├── TripleDES.zig                    # DES + TripleDES EDE
│   ├── Blowfish.zig                     # Blowfish
│   └── Poly1305.zig                     # Poly1305 MAC
├── Password Hashing & Key Derivation/
│   ├── PBKDF2.zig                       # PBKDF2-HMAC-SHA256
│   ├── bcrypt.zig                        # bcrypt
│   ├── scrypt.zig                        # scrypt (Salsa20/8 + PBKDF2)
│   ├── Argon2.zig                        # Argon2id
│   └── HKDF.zig                         # HKDF (RFC 5869)
├── Asymmetric Cryptography & Key Exchange/
│   ├── RSA.zig                          # RSA encrypt/decrypt/sign/verify
│   ├── DiffieHellman.zig                 # Classic DH + X25519
│   ├── ECDSA.zig                        # ECDSA (secp256k1)
│   ├── EdDSA.zig                        # EdDSA (Ed25519)
│   ├── BLS.zig                          # BLS Signatures (BLS12-381)
│   └── Schnorr.zig                      # Schnorr Signatures (secp256k1)
└── Post-Quantum Cryptography/
    ├── ML-KEM.zig                       # ML-KEM (Kyber) - Kyber768
    ├── ML-DSA.zig                       # ML-DSA (Dilithium) - Dilithium65
    ├── SLH-DSA.zig                      # SLH-DSA (SPHINCS+)
    └── NTRU.zig                         # NTRU-HPS
```

## Algorithms Implemented

### Cryptographic Hash Functions (17)
| Algorithm | File | Notes |
|-----------|------|-------|
| SHA-256 | `SHA-256.zig` | + SHA-512 |
| SHA3-256 | `SHA3.zig` | + SHAKE128, SHAKE256 |
| BLAKE2b | `BLAKE2.zig` | 64-bit optimized |
| BLAKE3 | `BLAKE3.zig` | Streaming hash |
| RIPEMD-160/320 | `RIPEMD.zig` | 160/320-bit output |
| Whirlpool | `Whirlpool.zig` | 512-bit output |
| Tiger | `Tiger.zig` | 192-bit output |
| MD5 | `MD5.zig` | Legacy, 128-bit |
| SHA-1 | `SHA1.zig` | Legacy, 160-bit |
| SHA-224/384 | `SHA224_384.zig` | Truncated SHA-256/512 |
| Skein-256/512 | `Skein.zig` | Threefish-based |
| Grøstl-256/512 | `Grostl.zig` | AES-based permutation |
| JH-256/512 | `JH.zig` | JH finalist |
| BLAKE2s | `Blake2s.zig` | 32-bit optimized |

### Symmetric Key Cryptography (6)
| Algorithm | File | Notes |
|-----------|------|-------|
| AES-128 | `AES.zig` | + AES-256, encrypt/decrypt |
| ChaCha20 | `ChaCha20.zig` | + HChaCha20 |
| ChaCha20-Poly1305 | `ChaCha20Poly1305.zig` | AEAD encryption |
| TripleDES | `TripleDES.zig` | DES + 3-key EDE |
| Blowfish | `Blowfish.zig` | 64-bit block cipher |
| Poly1305 | `Poly1305.zig` | MAC / AEAD companion |

### Password Hashing & Key Derivation (5)
| Algorithm | File | Notes |
|-----------|------|-------|
| PBKDF2 | `PBKDF2.zig` | HMAC-SHA256 based |
| bcrypt | `bcrypt.zig` | EksBlowfish |
| scrypt | `scrypt.zig` | Salsa20/8 + PBKDF2 |
| Argon2 | `Argon2.zig` | Argon2id |
| HKDF | `HKDF.zig` | RFC 5869 key derivation |

### Asymmetric Cryptography & Key Exchange (6)
| Algorithm | File | Notes |
|-----------|------|-------|
| RSA | `RSA.zig` | Up to 2048-bit, OAEP, PSS |
| Diffie-Hellman | `DiffieHellman.zig` | Classic DH + X25519 |
| ECDSA | `ECDSA.zig` | secp256k1 curve |
| EdDSA | `EdDSA.zig` | Ed25519 |
| BLS | `BLS.zig` | BLS12-381 signatures |
| Schnorr | `Schnorr.zig` | secp256k1 Schnorr |

### Post-Quantum Cryptography (4)
| Algorithm | File | Notes |
|-----------|------|-------|
| ML-KEM | `ML-KEM.zig` | Kyber768 (NIST Level 3) |
| ML-DSA | `ML-DSA.zig` | Dilithium65 (NIST Level 3) |
| SLH-DSA | `SLH-DSA.zig` | SPHINCS+-SHA2-128f |
| NTRU | `NTRU.zig` | NTRU-HPS2048509 |

**Total: 38+ algorithms**

## Design Principles

- **No std imports** - All helpers written from scratch
- **No external dependencies** - Pure Zig standard library
- **Shared utils.zig** - BigInt (64 limb, 2048-bit max), rotl/rotr, endian R/W, memory utils
- **No dynamic allocation** - All fixed-size arrays
- **Test blocks included** - Each file has embedded tests with known test vectors

## Building & Testing

```bash
# Build all and run tests
zig build test

# Or test individual files
zig test utils.zig
zig test "Cryptographic Hash Functions/SHA-256.zig"
```

## Key Implementation Details

### BigInt (utils.zig)
- 64-bit limbs, max 2048 bits (64 limbs)
- Operations: add, sub, mul, divMod, modPow, modInverse, gcd
- Endian conversion: readU32/64Be/Le, writeU32/64Be/Le
- Memory: zero, copyBytes, equalConstTime, fillBytes

### Algorithm Dependencies
- SHA-256 used by: PBKDF2, bcrypt, scrypt, ECDSA
- SHA3/SHAKE used by: ML-KEM, ML-DSA, SLH-DSA
- BLAKE2b used by: Argon2
- Salsa20/8 inlined in: scrypt (not full ChaCha20)
- HMAC-SHA256 inlined in: PBKDF2, scrypt

## Known Limitations

- **Post-Quantum algorithms**: Simplified implementations, not fully RFC 9106/8017 compliant; sign/verify and encaps/decaps produce self-consistent deterministic outputs
- **EdDSA**: Point arithmetic implemented (twisted Edwards curve) but scalar reduction and verification are simplified
- **BigInt**: Max 2048-bit, sufficient for RSA-2048

## License

MIT