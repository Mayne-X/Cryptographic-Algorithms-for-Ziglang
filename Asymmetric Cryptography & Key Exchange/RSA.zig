const u = @import("../utils.zig");
const BigInt = u.BigInt;

pub const RsaPublicKey = struct {
    n: BigInt,
    e: BigInt,
};

pub const RsaPrivateKey = struct {
    n: BigInt,
    d: BigInt,
};

pub const Rsa = struct {
    pub fn encrypt(pub_key: *const RsaPublicKey, message: *const BigInt) BigInt {
        return BigInt.modPow(message, &pub_key.e, &pub_key.n);
    }

    pub fn decrypt(priv_key: *const RsaPrivateKey, ciphertext: *const BigInt) BigInt {
        return BigInt.modPow(ciphertext, &priv_key.d, &priv_key.n);
    }

    pub fn sign(priv_key: *const RsaPrivateKey, hash: *const BigInt) BigInt {
        return BigInt.modPow(hash, &priv_key.d, &priv_key.n);
    }

    pub fn verify(pub_key: *const RsaPublicKey, signature: *const BigInt, hash: *const BigInt) bool {
        const recovered = BigInt.modPow(signature, &pub_key.e, &pub_key.n);
        return BigInt.cmp(&recovered, hash) == 0;
    }

    pub fn generatePrimes() struct { p: BigInt, q: BigInt } {
        var p = BigInt.fromU64(61);
        var q = BigInt.fromU64(53);
        return .{ .p = p, .q = q };
    }

    pub fn keygenFromPrimes(p: u64, q: u64) struct { pub_key: RsaPublicKey, priv_key: RsaPrivateKey } {
        const big_p = BigInt.fromU64(p);
        const big_q = BigInt.fromU64(q);
        const n = BigInt.mul(&big_p, &big_q);
        const p1 = BigInt.fromU64(p - 1);
        const q1 = BigInt.fromU64(q - 1);
        const phi = BigInt.mul(&p1, &q1);
        const e = BigInt.fromU64(65537);
        const d = BigInt.modInverse(&e, &phi);
        return .{
            .pub_key = .{ .n = n, .e = e },
            .priv_key = .{ .n = n, .d = d },
        };
    }

    pub fn simpleEncrypt(m: u64, e: u64, n: u64) u64 {
        var result: u64 = 1;
        var base = m % n;
        var exp = e;
        while (exp > 0) {
            if (exp & 1 == 1) {
                result = result * base % n;
            }
            base = base * base % n;
            exp >>= 1;
        }
        return result;
    }
};

test "RSA encrypt/decrypt roundtrip" {
    const keys = Rsa.keygenFromPrimes(61, 53);
    const m = BigInt.fromU64(65);
    const ct = Rsa.encrypt(&keys.pub_key, &m);
    const pt = Rsa.decrypt(&keys.priv_key, &ct);
    if (BigInt.cmp(&pt, &m) != 0) return error.TestUnexpectedResult;
}

test "RSA sign/verify" {
    const keys = Rsa.keygenFromPrimes(61, 53);
    const hash = BigInt.fromU64(42);
    const sig = Rsa.sign(&keys.priv_key, &hash);
    if (!Rsa.verify(&keys.pub_key, &sig, &hash)) return error.TestUnexpectedResult;
}

test "RSA simple encrypt" {
    const ct = Rsa.simpleEncrypt(65, 17, 3233);
    const pt = Rsa.simpleEncrypt(ct, 2753, 3233);
    if (pt != 65) return error.TestUnexpectedResult;
}
