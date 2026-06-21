const u = @import("../utils.zig");
const BigInt = u.BigInt;

pub const Secp256k1 = struct {
    const P: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    const N: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    const Gx: u256 = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    const Gy: u256 = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    const A: u256 = 0;
    const B: u256 = 7;

    pub const Point = struct {
        x: BigInt,
        y: BigInt,
        inf: bool,
    };

    var p_bi: BigInt = undefined;
    var n_bi: BigInt = undefined;
    var p_init: bool = false;

    fn getP() BigInt {
        if (!p_init) {
            var p_bytes = [32]u8{
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
            };
            p_bi = BigInt.fromBytes(&p_bytes);
            var n_bytes = [32]u8{
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
                0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
            };
            n_bi = BigInt.fromBytes(&n_bytes);
            p_init = true;
        }
        return p_bi;
    }

    fn getN() BigInt {
        _ = getP();
        return n_bi;
    }

    pub fn g() Point {
        var gx_bytes = [32]u8{
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
            0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
        };
        var gy_bytes = [32]u8{
            0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
            0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
        };
        return Point{
            .x = BigInt.fromBytes(&gx_bytes),
            .y = BigInt.fromBytes(&gy_bytes),
            .inf = false,
        };
    }

    pub fn pointAdd(p1: *const Point, p2: *const Point) Point {
        if (p1.inf) return p2.*;
        if (p2.inf) return p1.*;
        const mod_p = getP();
        if (BigInt.cmp(&p1.x, &p2.x) == 0 and BigInt.cmp(&p1.y, &p2.y) != 0) {
            return Point{ .x = BigInt.init(), .y = BigInt.init(), .inf = true };
        }
        var lam: BigInt = undefined;
        if (BigInt.cmp(&p1.x, &p2.x) == 0 and BigInt.cmp(&p1.y, &p2.y) == 0) {
            const num = BigInt.mul(&BigInt.fromU64(3), &BigInt.mul(&p1.x, &p1.x).mod(&mod_p));
            const den_inv = BigInt.modInverse(&BigInt.mul(&BigInt.fromU64(2), &p1.y).mod(&mod_p), &mod_p);
            lam = num.mod(&mod_p).mul(&den_inv).mod(&mod_p);
        } else {
            const dx = BigInt.sub(&p2.x, &p1.x).mod(&mod_p);
            const dy = BigInt.sub(&p2.y, &p1.y).mod(&mod_p);
            const dx_inv = BigInt.modInverse(&dx, &mod_p);
            lam = dy.mul(&dx_inv).mod(&mod_p);
        }
        const x3 = BigInt.sub(&BigInt.mul(&lam, &lam).mod(&mod_p), &p1.x).mod(&mod_p).sub(&p2.x).mod(&mod_p);
        const y3 = BigInt.sub(&BigInt.mul(&lam, &BigInt.sub(&p1.x, &x3).mod(&mod_p)).mod(&mod_p), &p1.y).mod(&mod_p);
        return Point{ .x = x3, .y = y3, .inf = false };
    }

    pub fn scalarMult(k: *const BigInt, point: *const Point) Point {
        var result = Point{ .x = BigInt.init(), .y = BigInt.init(), .inf = true };
        var current = point.*;
        var exp = k.*;
        while (!exp.isZero()) {
            if (exp.bit(0)) {
                result = pointAdd(&result, &current);
            }
            current = pointAdd(&current, &current);
            exp = exp.shr1();
        }
        return result;
    }
};

pub const EcdsaKeyPair = struct {
    private_key: BigInt,
    public_key: Secp256k1.Point,
};

pub const EcdsaSignature = struct {
    r: BigInt,
    s: BigInt,
};

pub const Ecdsa = struct {
    pub fn generateKeyPair(private_int: u64) EcdsaKeyPair {
        const priv_key = BigInt.fromU64(private_int);
        const pub_key = Secp256k1.scalarMult(&priv_key, &Secp256k1.g());
        return EcdsaKeyPair{ .private_key = priv_key, .public_key = pub_key };
    }

    pub fn sign(private_key: *const BigInt, hash: *const BigInt, k: u64) EcdsaSignature {
        const n = Secp256k1.getN();
        const k_bi = BigInt.fromU64(k);
        const r_point = Secp256k1.scalarMult(&k_bi, &Secp256k1.g());
        const r = r_point.x.mod(&n);
        const r_inv = BigInt.modInverse(&k_bi, &n);
        const s = BigInt.mul(&r_inv, hash.add(&BigInt.mul(&r, private_key).mod(&n)).mod(&n)).mod(&n);
        return EcdsaSignature{ .r = r, .s = s };
    }

    pub fn verify(public_key: *const Secp256k1.Point, hash: *const BigInt, sig: *const EcdsaSignature) bool {
        const n = Secp256k1.getN();
        if (BigInt.cmp(&sig.r, &BigInt.fromU64(1)) < 0 or BigInt.cmp(&sig.r, &n) >= 0) return false;
        if (BigInt.cmp(&sig.s, &BigInt.fromU64(1)) < 0 or BigInt.cmp(&sig.s, &n) >= 0) return false;
        const w = BigInt.modInverse(&sig.s, &n);
        const u1 = BigInt.mul(&w, hash).mod(&n);
        const u2 = BigInt.mul(&w, &sig.r).mod(&n);
        const gu1 = Secp256k1.scalarMult(&u1, &Secp256k1.g());
        const qu2 = Secp256k1.scalarMult(&u2, public_key);
        const point = Secp256k1.pointAdd(&gu1, &qu2);
        if (point.inf) return false;
        const v = point.x.mod(&n);
        return BigInt.cmp(&v, &sig.r) == 0;
    }
};

test "ECDSA sign/verify roundtrip" {
    const kp = Ecdsa.generateKeyPair(12345);
    const hash = BigInt.fromU64(999);
    const sig = Ecdsa.sign(&kp.private_key, &hash, 98765);
    if (!Ecdsa.verify(&kp.public_key, &hash, &sig)) return error.TestUnexpectedResult;
}

test "ECDSA wrong hash fails" {
    const kp = Ecdsa.generateKeyPair(12345);
    const hash = BigInt.fromU64(999);
    const sig = Ecdsa.sign(&kp.private_key, &hash, 98765);
    const wrong_hash = BigInt.fromU64(888);
    if (Ecdsa.verify(&kp.public_key, &wrong_hash, &sig)) return error.TestUnexpectedResult;
}
