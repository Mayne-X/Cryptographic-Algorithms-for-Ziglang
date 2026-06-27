const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const test_step = b.step("test", "Run all tests");

    const files = [_][]const u8{
        "utils.zig",
        "Cryptographic Hash Functions/SHA-256.zig",
        "Cryptographic Hash Functions/SHA3.zig",
        "Cryptographic Hash Functions/BLAKE2.zig",
        "Cryptographic Hash Functions/BLAKE3.zig",
        "Cryptographic Hash Functions/RIPEMD.zig",
        "Cryptographic Hash Functions/Whirlpool.zig",
        "Cryptographic Hash Functions/Tiger.zig",
        "Cryptographic Hash Functions/MD5.zig",
        "Cryptographic Hash Functions/SHA1.zig",
        "Cryptographic Hash Functions/SHA224_384.zig",
        "Cryptographic Hash Functions/Skein.zig",
        "Cryptographic Hash Functions/Grostl.zig",
        "Symmetric Key Cryptography/AES.zig",
        "Symmetric Key Cryptography/ChaCha20.zig",
        "Symmetric Key Cryptography/TripleDES.zig",
        "Symmetric Key Cryptography/Blowfish.zig",
        "Password Hashing & Key Derivation/PBKDF2.zig",
        "Password Hashing & Key Derivation/bcrypt.zig",
        "Password Hashing & Key Derivation/scrypt.zig",
        "Password Hashing & Key Derivation/Argon2.zig",
        "Asymmetric Cryptography & Key Exchange/RSA.zig",
        "Asymmetric Cryptography & Key Exchange/DiffieHellman.zig",
        "Asymmetric Cryptography & Key Exchange/ECDSA.zig",
        "Asymmetric Cryptography & Key Exchange/EdDSA.zig",
        "Post-Quantum Cryptography/ML-KEM.zig",
        "Post-Quantum Cryptography/ML-DSA.zig",
        "Post-Quantum Cryptography/SLH-DSA.zig",
        "Post-Quantum Cryptography/NTRU.zig",
    };

    for (files) |file| {
        const obj = b.addObject(.{
            .name = file,
            .root_source_file = b.path(file),
            .target = target,
            .optimize = optimize,
        });
        _ = obj;
    }

    for (files) |file| {
        const test_obj = b.addTest(.{
            .name = file,
            .root_source_file = b.path(file),
            .target = target,
            .optimize = optimize,
        });
        const test_run = b.addRunUnitTest(test_obj);
        test_step.addStep(test_run);
    }
}

test {
    @import("std").testing.refAllDecls(@This());
}