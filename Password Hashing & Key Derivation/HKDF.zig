const u = @import("../utils.zig");
const Sha256 = @import("../Cryptographic Hash Functions/SHA-256.zig").Sha256;

pub const HKDF = struct {
    pub fn extract(salt: []const u8, ikm: []const u8) [32]u8 {
        var prk: [32]u8 = undefined;
        if (salt.len == 0) {
            u.zero(&prk);
        } else {
            var hmac = HMACSHA256.init(salt);
            hmac.update(ikm);
            prk = hmac.final();
        }
        return prk;
    }

    pub fn expand(prk: *const [32]u8, info: []const u8, okm: []u8) void {
        var t: [32]u8 = undefined;
        var offset: usize = 0;
        var counter: u8 = 1;
        while (offset < okm.len) {
            var hmac = HMACSHA256.init(prk);
            if (t[0] != 0 || t[1] != 0) {
                hmac.update(&t);
            }
            hmac.update(info);
            hmac.update(&[_]u8{ counter });
            t = hmac.final();
            const take = @min(okm.len - offset, 32);
            u.copyBytes(okm[offset..offset + take], t[0..take]);
            offset += take;
            counter += 1;
        }
    }

    pub fn derive(salt: []const u8, ikm: []const u8, info: []const u8, okm: []u8) void {
        const prk = HKDF.extract(salt, ikm);
        HKDF.expand(&prk, info, okm);
    }
};

const HMACSHA256 = struct {
    key: [32]u8,
    inner_pad: [64]u8,
    outer_pad: [64]u8,
    state: Sha256,

    pub fn init(key: []const u8) HMACSHA256 {
        var h = HMACSHA256{
            .key = undefined,
            .inner_pad = undefined,
            .outer_pad = undefined,
            .state = Sha256.init(),
        };
        var k: [32]u8 = undefined;
        if (key.len > 64) {
            var h2 = Sha256.init();
            h2.update(key);
            k = h2.final();
        } else {
            u.copyBytes(&k, key);
        }
        u.copyBytes(&h.key, &k);
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            h.inner_pad[i] = if (i < 32) k[i] ^ 0x36 else 0x36;
            h.outer_pad[i] = if (i < 32) k[i] ^ 0x5C else 0x5C;
        }
        h.state.update(&h.inner_pad);
        return h;
    }

    pub fn update(h: *HMACSHA256, data: []const u8) void {
        h.state.update(data);
    }

    pub fn final(h: *HMACSHA256) [32]u8 {
        var inner_hash = h.state.final();
        var outer = Sha256.init();
        outer.update(&h.outer_pad);
        outer.update(&inner_hash);
        return outer.final();
    }
};

test "HKDF basic" {
    var salt: [0]u8 = undefined;
    var ikm: [32]u8 = undefined;
    u.fillBytes(&ikm, 0x42);
    var info: [0]u8 = undefined;
    var okm: [64]u8 = undefined;
    HKDF.derive(&salt, &ikm, &info, &okm);
    _ = okm;
}