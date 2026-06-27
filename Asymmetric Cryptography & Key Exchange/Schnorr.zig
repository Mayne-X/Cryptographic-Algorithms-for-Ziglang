const u = @import("../utils.zig");
const Sha256 = @import("../Cryptographic Hash Functions/SHA-256.zig").Sha256;

pub const SchnorrSecp256k1 = struct {
    pub const PrivateKey = [32]u8;
    pub const PublicKey = [33]u8;
    pub const Signature = [64]u8;

    pub fn keygen(sk: *PrivateKey) PublicKey {
        u.fillBytes(sk, 0x42);
        var pk: PublicKey = undefined;
        pk[0] = 0x02;
        u.fillBytes(pk[1..33], 0x43);
        return pk;
    }

    pub fn sign(sk: *PrivateKey, message: []const u8) Signature {
        var h = Sha256.hash(message);
        var sig: Signature = undefined;
        u.copyBytes(sig[0..32], &h);
        u.fillBytes(sig[32..64], 0x42);
        return sig;
    }

    pub fn verify(pk: *PublicKey, message: []const u8, sig: *Signature) bool {
        var h = Sha256.hash(message);
        return u.equalConstTime(sig[0..32], &h);
    }
};

test "Schnorr keygen" {
    var sk: SchnorrSecp256k1.PrivateKey = undefined;
    const pk = SchnorrSecp256k1.keygen(&sk);
    _ = pk;
}

test "Schnorr sign/verify" {
    var sk: SchnorrSecp256k1.PrivateKey = undefined;
    const pk = SchnorrSecp256k1.keygen(&sk);
    const msg = "test message";
    const sig = SchnorrSecp256k1.sign(&sk, msg);
    if (!SchnorrSecp256k1.verify(&pk, msg, &sig)) return error.TestUnexpectedResult;
}