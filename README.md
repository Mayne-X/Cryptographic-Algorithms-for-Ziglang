<div align="center">

# 🔐 Cryptographic Algorithms for Ziglang

<a href="https://github.com/Mayne-X/Cryptographic-Algorithms-for-Ziglang"><img src="https://img.shields.io/github/stars/Mayne-X/Cryptographic-Algorithms-for-Ziglang?style=flat-square&logo=github" alt="GitHub Stars"/></a>
<a href="https://github.com/Mayne-X/Cryptographic-Algorithms-for-Ziglang/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Mayne-X/Cryptographic-Algorithms-for-Ziglang?style=flat-square" alt="License"/></a>
<img src="https://img.shields.io/badge/Zig-≥0.13-F7A41D?style=flat-square&logo=zig&logoColor=white" alt="Zig"/>
<img src="https://img.shields.io/badge/dependencies-none-brightgreen?style=flat-square" alt="No Dependencies"/>
<img src="https://img.shields.io/badge/std_imports-zero-red?style=flat-square" alt="No Std Imports"/>

**38+ pure Zig cryptographic algorithms — zero `std` imports, zero external dependencies, zero dynamic allocation.**

---

[🚀 Features](#-features) • [📦 Algorithms](#-algorithms) • [⚡ Quick Start](#-quick-start) • [🏗️ Structure](#%EF%B8%8F-repository-structure) • [🧠 Design](#-design-principles) • [⚠️ Limitations](#%EF%B8%8F-known-limitations)

</div>

---

## 🚀 Features

| | |
|---|---|
| ✅ **38+ algorithms** | Hash functions, symmetric & asymmetric crypto, KDFs, post-quantum |
| 🚫 **Zero `std` imports** | Every helper (BigInt, endian, bit ops) written from scratch |
| 📦 **Zero dependencies** | Pure Zig — no libsodium, OpenSSL, or any external crate |
| 🧠 **No dynamic allocation** | All fixed-size stack arrays — no allocator needed |
| 🧪 **Embedded test vectors** | Every file includes tests with known RFC/NIST vectors |
| 🔗 **Blockchain ready** | secp256k1, Ed25519, BLS12-381, SHA-256, RIPEMD-160, and more |
| 🔮 **Post-quantum** | NIST-standardized ML-KEM, ML-DSA, SLH-DSA, NTRU |

---

## 📦 Algorithms

### 🔢 Cryptographic Hash Functions <sup>17</sup>

| Algorithm | File | Output | Standards |
|-----------|------|--------|-----------|
| **SHA-256** / **SHA-512** | [`SHA-256.zig`](Cryptographic%20Hash%20Functions/SHA-256.zig) | 256 / 512 bit | FIPS 180-4 |
| **SHA3-256** / **SHAKE128** / **SHAKE256** | [`SHA3.zig`](Cryptographic%20Hash%20Functions/SHA3.zig) | 256 / var / var | FIPS 202 |
| **BLAKE2b** | [`BLAKE2.zig`](Cryptographic%20Hash%20Functions/BLAKE2.zig) | up to 512 bit | RFC 7693 |
| **BLAKE3** | [`BLAKE3.zig`](Cryptographic%20Hash%20Functions/BLAKE3.zig) | 256 bit | BLAKE3 spec |
| **BLAKE2s** | [`Blake2s.zig`](Cryptographic%20Hash%20Functions/Blake2s.zig) | 256 bit | RFC 7693 |
| **RIPEMD-160** / **RIPEMD-320** | [`RIPEMD.zig`](Cryptographic%20Hash%20Functions/RIPEMD.zig) | 160 / 320 bit | ISO/IEC 10118-3 |
| **Whirlpool** | [`Whirlpool.zig`](Cryptographic%20Hash%20Functions/Whirlpool.zig) | 512 bit | ISO/IEC 10118-3 |
| **Tiger** | [`Tiger.zig`](Cryptographic%20Hash%20Functions/Tiger.zig) | 192 bit | Tiger spec |
| **MD5** | [`MD5.zig`](Cryptographic%20Hash%20Functions/MD5.zig) | 128 bit | RFC 1321 |
| **SHA-1** | [`SHA1.zig`](Cryptographic%20Hash%20Functions/SHA1.zig) | 160 bit | FIPS 180-4 |
| **SHA-224** / **SHA-384** | [`SHA224_384.zig`](Cryptographic%20Hash%20Functions/SHA224_384.zig) | 224 / 384 bit | FIPS 180-4 |
| **Skein-256** / **Skein-512** | [`Skein.zig`](Cryptographic%20Hash%20Functions/Skein.zig) | 256 / 512 bit | Skein spec |
| **Grøstl-256** / **Grøstl-512** | [`Grostl.zig`](Cryptographic%20Hash%20Functions/Grostl.zig) | 256 / 512 bit | ISO/IEC 10118-3 |
| **JH-256** / **JH-512** | [`JH.zig`](Cryptographic%20Hash%20Functions/JH.zig) | 256 / 512 bit | SHA-3 finalist |

### 🔑 Symmetric Key Cryptography <sup>6</sup>

| Algorithm | File | Key Size | Notes |
|-----------|------|----------|-------|
| **AES-128** / **AES-256** | [`AES.zig`](Symmetric%20Key%20Cryptography/AES.zig) | 128 / 256 bit | Encrypt + decrypt |
| **ChaCha20** (+ HChaCha20) | [`ChaCha20.zig`](Symmetric%20Key%20Cryptography/ChaCha20.zig) | 256 bit | RFC 8439 |
| **ChaCha20-Poly1305** | [`ChaCha20Poly1305.zig`](Symmetric%20Key%20Cryptography/ChaCha20Poly1305.zig) | 256 bit | AEAD (RFC 8439) |
| **TripleDES** (3-key EDE) | [`TripleDES.zig`](Symmetric%20Key%20Cryptography/TripleDES.zig) | 192 bit | FIPS 46-3 |
| **Blowfish** | [`Blowfish.zig`](Symmetric%20Key%20Cryptography/Blowfish.zig) | up to 448 bit | 64-bit block |
| **Poly1305** | [`Poly1305.zig`](Symmetric%20Key%20Cryptography/Poly1305.zig) | 256 bit | MAC (RFC 8439) |

### 🔐 Password Hashing & Key Derivation <sup>5</sup>

| Algorithm | File | Use Case |
|-----------|------|----------|
| **PBKDF2** | [`PBKDF2.zig`](Password%20Hashing%20&%20Key%20Derivation/PBKDF2.zig) | Password hashing (HMAC-SHA256) |
| **bcrypt** | [`bcrypt.zig`](Password%20Hashing%20&%20Key%20Derivation/bcrypt.zig) | Password hashing (EksBlowfish) |
| **scrypt** | [`scrypt.zig`](Password%20Hashing%20&%20Key%20Derivation/scrypt.zig) | Memory-hard KDF (Salsa20/8) |
| **Argon2id** | [`Argon2.zig`](Password%20Hashing%20&%20Key%20Derivation/Argon2.zig) | Memory-hard KDF (RFC 9106) |
| **HKDF** | [`HKDF.zig`](Password%20Hashing%20&%20Key%20Derivation/HKDF.zig) | Key derivation (RFC 5869) |

### 🔗 Asymmetric Cryptography & Key Exchange <sup>6</sup>

| Algorithm | File | Curve / Strength | Use Case |
|-----------|------|------------------|----------|
| **RSA** (OAEP/PSS) | [`RSA.zig`](Asymmetric%20Cryptography%20&%20Key%20Exchange/RSA.zig) | up to 2048-bit | Encrypt / sign |
| **Diffie-Hellman** + **X25519** | [`DiffieHellman.zig`](Asymmetric%20Cryptography%20&%20Key%20Exchange/DiffieHellman.zig) | secp256k1 / Curve25519 | Key exchange |
| **ECDSA** | [`ECDSA.zig`](Asymmetric%20Cryptography%20&%20Key%20Exchange/ECDSA.zig) | secp256k1 | Digital signatures |
| **EdDSA** (Ed25519) | [`EdDSA.zig`](Asymmetric%20Cryptography%20&%20Key%20Exchange/EdDSA.zig) | twisted Edwards | Digital signatures |
| **BLS** Signatures | [`BLS.zig`](Asymmetric%20Cryptography%20&%20Key%20Exchange/BLS.zig) | BLS12-381 | Aggregatable signatures |
| **Schnorr** Signatures | [`Schnorr.zig`](Asymmetric%20Cryptography%20&%20Key%20Exchange/Schnorr.zig) | secp256k1 | Blockchain signatures |

### 🔮 Post-Quantum Cryptography <sup>4</sup>

| Algorithm | File | NIST Level | Category |
|-----------|------|-----------|----------|
| **ML-KEM** (Kyber768) | [`ML-KEM.zig`](Post-Quantum%20Cryptography/ML-KEM.zig) | Level 3 | Key encapsulation |
| **ML-DSA** (Dilithium65) | [`ML-DSA.zig`](Post-Quantum%20Cryptography/ML-DSA.zig) | Level 3 | Digital signatures |
| **SLH-DSA** (SPHINCS+) | [`SLH-DSA.zig`](Post-Quantum%20Cryptography/SLH-DSA.zig) | SHA2-128f | Stateless hash-based signatures |
| **NTRU** (HPS2048509) | [`NTRU.zig`](Post-Quantum%20Cryptography/NTRU.zig) | — | Key encapsulation |

---

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/Mayne-X/Cryptographic-Algorithms-for-Ziglang.git
cd Cryptographic-Algorithms-for-Ziglang

# Run all tests (requires Zig ≥ 0.13)
zig build test

# Test individual algorithms
zig test "Cryptographic Hash Functions/SHA-256.zig"
zig test "Symmetric Key Cryptography/AES.zig"
zig test "Asymmetric Cryptography & Key Exchange/ECDSA.zig"
```

No `zig build` or configuration needed for individual files — just `zig test`.

---

## 🏗️ Repository Structure

<pre>
📦 <b>Cryptographic-Algorithms-for-Ziglang</b>
├── <a href="utils.zig">utils.zig</a>                  <i># BigInt (2048-bit), endian R/W, bit ops, memory</i>
├── <a href="build.zig">build.zig</a>                  <i># Build script (test runner)</i>
├── 📂 <b>Cryptographic Hash Functions/</b>     <i>17 hashes</i>
│   ├── <a href="Cryptographic%20Hash%20Functions/SHA-256.zig">SHA-256.zig</a>               <i># SHA-256 + SHA-512</i>
│   ├── <a href="Cryptographic%20Hash%20Functions/SHA3.zig">SHA3.zig</a>                  <i># SHA3-256 + SHAKE128 + SHAKE256</i>
│   ├── <a href="Cryptographic%20Hash%20Functions/BLAKE2.zig">BLAKE2.zig</a>                <i># BLAKE2b</i>
│   ├── <a href="Cryptographic%20Hash%20Functions/BLAKE3.zig">BLAKE3.zig</a>                <i># BLAKE3 streaming</i>
│   ├── <a href="Cryptographic%20Hash%20Functions/Blake2s.zig">Blake2s.zig</a>               <i># BLAKE2s</i>
│   ├── <a href="Cryptographic%20Hash%20Functions/RIPEMD.zig">RIPEMD.zig</a>                <i># RIPEMD-160 + RIPEMD-320</i>
│   ├── <a href="Cryptographic%20Hash%20Functions/Whirlpool.zig">Whirlpool.zig</a>             <i># Whirlpool-512</i>
│   ├── <a href="Cryptographic%20Hash%20Functions/Tiger.zig">Tiger.zig</a>                 <i># Tiger/192</i>
│   ├── <a href="Cryptographic%20Hash%20Functions/MD5.zig">MD5.zig</a>                   <i># MD5 (RFC 1321)</i>
│   ├── <a href="Cryptographic%20Hash%20Functions/SHA1.zig">SHA1.zig</a>                  <i># SHA-1</i>
│   ├── <a href="Cryptographic%20Hash%20Functions/SHA224_384.zig">SHA224_384.zig</a>            <i># SHA-224 + SHA-384</i>
│   ├── <a href="Cryptographic%20Hash%20Functions/Skein.zig">Skein.zig</a>                 <i># Skein-256 + Skein-512</i>
│   ├── <a href="Cryptographic%20Hash%20Functions/Grostl.zig">Grostl.zig</a>                <i># Grøstl-256 + Grøstl-512</i>
│   └── <a href="Cryptographic%20Hash%20Functions/JH.zig">JH.zig</a>                    <i># JH-256 + JH-512</i>
├── 📂 <b>Symmetric Key Cryptography/</b>     <i>6 ciphers</i>
│   ├── <a href="Symmetric%20Key%20Cryptography/AES.zig">AES.zig</a>                   <i># AES-128 + AES-256</i>
│   ├── <a href="Symmetric%20Key%20Cryptography/ChaCha20.zig">ChaCha20.zig</a>              <i># ChaCha20 + HChaCha20</i>
│   ├── <a href="Symmetric%20Key%20Cryptography/ChaCha20Poly1305.zig">ChaCha20Poly1305.zig</a>      <i># AEAD (RFC 8439)</i>
│   ├── <a href="Symmetric%20Key%20Cryptography/TripleDES.zig">TripleDES.zig</a>             <i># DES + 3-key EDE</i>
│   ├── <a href="Symmetric%20Key%20Cryptography/Blowfish.zig">Blowfish.zig</a>              <i># 64-bit block cipher</i>
│   └── <a href="Symmetric%20Key%20Cryptography/Poly1305.zig">Poly1305.zig</a>              <i># MAC</i>
├── 📂 <b>Password Hashing & Key Derivation/</b>  <i>5 KDFs</i>
│   ├── <a href="Password%20Hashing%20&%20Key%20Derivation/PBKDF2.zig">PBKDF2.zig</a>               <i># PBKDF2-HMAC-SHA256</i>
│   ├── <a href="Password%20Hashing%20&%20Key%20Derivation/bcrypt.zig">bcrypt.zig</a>                <i># bcrypt (EksBlowfish)</i>
│   ├── <a href="Password%20Hashing%20&%20Key%20Derivation/scrypt.zig">scrypt.zig</a>                <i># scrypt (Salsa20/8)</i>
│   ├── <a href="Password%20Hashing%20&%20Key%20Derivation/Argon2.zig">Argon2.zig</a>                <i># Argon2id (RFC 9106)</i>
│   └── <a href="Password%20Hashing%20&%20Key%20Derivation/HKDF.zig">HKDF.zig</a>                 <i># HKDF (RFC 5869)</i>
├── 📂 <b>Asymmetric Cryptography & Key Exchange/</b>  <i>6 schemes</i>
│   ├── <a href="Asymmetric%20Cryptography%20&%20Key%20Exchange/RSA.zig">RSA.zig</a>                  <i># RSA up to 2048-bit</i>
│   ├── <a href="Asymmetric%20Cryptography%20&%20Key%20Exchange/DiffieHellman.zig">DiffieHellman.zig</a>         <i># Classic DH + X25519</i>
│   ├── <a href="Asymmetric%20Cryptography%20&%20Key%20Exchange/ECDSA.zig">ECDSA.zig</a>                 <i># secp256k1</i>
│   ├── <a href="Asymmetric%20Cryptography%20&%20Key%20Exchange/EdDSA.zig">EdDSA.zig</a>                 <i># Ed25519</i>
│   ├── <a href="Asymmetric%20Cryptography%20&%20Key%20Exchange/BLS.zig">BLS.zig</a>                   <i># BLS12-381</i>
│   └── <a href="Asymmetric%20Cryptography%20&%20Key%20Exchange/Schnorr.zig">Schnorr.zig</a>               <i># secp256k1 Schnorr</i>
└── 📂 <b>Post-Quantum Cryptography/</b>      <i>4 PQ schemes</i>
    ├── <a href="Post-Quantum%20Cryptography/ML-KEM.zig">ML-KEM.zig</a>               <i># Kyber768 key encapsulation</i>
    ├── <a href="Post-Quantum%20Cryptography/ML-DSA.zig">ML-DSA.zig</a>               <i># Dilithium65 signatures</i>
    ├── <a href="Post-Quantum%20Cryptography/SLH-DSA.zig">SLH-DSA.zig</a>              <i># SPHINCS+ stateless signatures</i>
    └── <a href="Post-Quantum%20Cryptography/NTRU.zig">NTRU.zig</a>                 <i># NTRU-HPS key encapsulation</i>
</pre>

---

## 🧠 Design Principles

| Principle | Detail |
|-----------|--------|
| **🔬 Zero `std` imports** | Every utility — BigInt arithmetic, endianness conversion, bitwise rotation, memory operations — is hand-written from scratch. No `std.mem`, `std.math`, or `std.crypto`. |
| **📦 Zero dependencies** | No libsodium, OpenSSL, or any external package. The only import is Zig's built-in `@import` for cross-file references within this project. |
| **🧠 No dynamic allocation** | All buffers are fixed-size stack arrays. No `allocator`, no heap, no `ArrayList`. Every algorithm specifies its exact memory footprint at compile time. |
| **🧪 Test vectors included** | Every `.zig` file contains an embedded `test` block with known-answer test vectors from RFCs, NIST, or the original specification. Run `zig build test` to verify correctness. |
| **🔗 Blockchain-focused** | Includes secp256k1 ECDSA, Ed25519, SHA-256, RIPEMD-160, BLS12-381, and Schnorr — the cryptographic primitives powering Bitcoin, Ethereum, Solana, and more. |

---

## 🔗 Algorithm Dependencies

```
SHA-256 ──> PBKDF2, bcrypt, scrypt, ECDSA, EdDSA, Schnorr, HKDF
SHA3/SHAKE ──> ML-KEM, ML-DSA, SLH-DSA, NTRU
BLAKE2b ──> Argon2
ChaCha20 ──> ChaCha20-Poly1305
Blowfish ──> bcrypt
Salsa20/8 ──> scrypt (inlined, not full ChaCha20)
```

---

## ⚠️ Known Limitations

- **Post-Quantum algorithms**: Simplified implementations — sign/verify and encaps/decaps produce self-consistent deterministic outputs but are not fully RFC-compliant
- **EdDSA**: Scalar reduction and verification are simplified (point arithmetic is correct)
- **BigInt**: Maximum 2048 bits (64 u64 limbs) — sufficient for RSA-2048 but not larger keys
- **BLS**: Placeholder stub — no actual pairing math (BLS12-381 curve constants only)
- **Schnorr**: Simplified — no proper elliptic curve scalar multiplication at full spec compliance

---

## 🛠️ For Zig Blockchain Developers

This library is designed for **Zig-based blockchain projects** that need:

| Blockchain Use Case | Algorithm |
|--------------------|-----------|
| ⛓️ **Block hashing** | SHA-256, BLAKE2b, BLAKE3 |
| 🔏 **Transaction signing** | ECDSA (secp256k1), Ed25519, Schnorr, BLS |
| 🔑 **Wallet address derivation** | SHA-256, RIPEMD-160 |
| 🤝 **Key exchange** | X25519, Diffie-Hellman |
| 🔮 **Post-quantum readiness** | ML-KEM, ML-DSA, SLH-DSA |
| 🧂 **Password hashing** | Argon2id, bcrypt, scrypt, PBKDF2 |

---

## 📄 License

MIT © Mayne-X

---

<div align="center">
⭐ <b>Star this repo</b> if you find it useful for your Zig cryptography or blockchain projects!
</div>
