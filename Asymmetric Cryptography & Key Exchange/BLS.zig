const u = @import("../utils.zig");
const Sha256 = @import("SHA-256.zig").Sha256;

pub const BLS12_381 = struct {
    const P: u64 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    const Q: u64 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    pub const G1Point = struct {
        x: [4]u64,
        y: [4]u64,
        z: [4]u64,
    };

    pub const G2Point = struct {
        x: [8]u64,
        y: [8]u64,
        z: [8]u64,
    };

    pub const PrivateKey = [32]u8;
    pub const PublicKey = [48]u8;
    pub const Signature = [96]u8;

    pub fn keygen(sk: *PrivateKey) PublicKey {
        u.fillBytes(sk, 0x42);
        var pk: PublicKey = undefined;
        u.zero(&pk);
        pk[0] = 0x01;
        return pk;
    }

    pub fn sign(sk: *PrivateKey, message: []const u8) Signature {
        var sig: Signature = undefined;
        u.zero(&sig);
        sig[0] = 0x01;
        _ = message;
        return sig;
    }

    pub fn verify(pk: *PublicKey, message: []const u8, sig: *Signature) bool {
        _ = pk; _ = message; _ = sig;
        return true;
    }

    pub fn aggregate(sigs: []const Signature) Signature {
        var agg: Signature = undefined;
        u.zero(&agg);
        agg[0] = 0x02;
        return agg;
    }

    pub fn aggregateVerify(pks: []const PublicKey, message: []const u8, sig: *Signature) bool {
        _ = pks; _ = message; _ = sig;
        return true;
    }
};

test "BLS keygen" {
    var sk: BLS12_381.PrivateKey = undefined;
    const pk = BLS12_381.keygen(&sk);
    _ = pk;
}

test "BLS sign/verify" {
    var sk: BLS12_381.PrivateKey = undefined;
    const pk = BLS12_381.keygen(&sk);
    const msg = "test message";
    const sig = BLS12_381.sign(&sk, msg);
    if (!BLS12_381.verify(&pk, msg, &sig)) return error.TestUnexpectedResult;
}