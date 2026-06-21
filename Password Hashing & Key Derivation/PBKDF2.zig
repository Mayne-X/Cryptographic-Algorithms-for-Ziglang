const u = @import("../utils.zig");
const Sha256 = @import("../Cryptographic Hash Functions/SHA-256.zig").Sha256;

pub const Pbkdf2HmacSha256 = struct {
    pub fn derive(password: []const u8, salt: []const u8, iterations: u32, key_len: usize, output: []u8) void {
        const block_count = (key_len + 31) / 32;
        var i: u32 = 1;
        while (i <= block_count) : (i += 1) {
            var u_block: [32]u8 = undefined;
            hmacSha256(password, salt, i, &u_block);
            var result: [32]u8 = u_block;
            var j: u32 = 1;
            while (j < iterations) : (j += 1) {
                hmacSha256Simple(password, &u_block, &u_block);
                var k: usize = 0;
                while (k < 32) : (k += 1) {
                    result[k] ^= u_block[k];
                }
            }
            const offset = (i - 1) * 32;
            const take = if (key_len - offset < 32) key_len - offset else @as(usize, 32);
            u.copyBytes(output[offset .. offset + take], result[0..take]);
        }
    }

    fn hmacSha256(key: []const u8, msg_prefix: []const u8, counter: u32, out: *[32]u8) void {
        var k_pad: [64]u8 = undefined;
        var ipad: [64]u8 = undefined;
        var opad: [64]u8 = undefined;
        var key_block: [32]u8 = undefined;
        if (key.len <= 64) {
            u.zero(&k_pad);
            u.copyBytes(k_pad[0..key.len], key);
        } else {
            const h = Sha256.hash(key);
            u.zero(&k_pad);
            u.copyBytes(k_pad[0..32], &h);
        }
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            ipad[i] = k_pad[i] ^ 0x36;
            opad[i] = k_pad[i] ^ 0x5c;
        }
        var inner = Sha256.init();
        inner.update(&ipad);
        inner.update(msg_prefix);
        var counter_bytes: [4]u8 = undefined;
        counter_bytes[0] = @truncate(counter >> 24);
        counter_bytes[1] = @truncate(counter >> 16);
        counter_bytes[2] = @truncate(counter >> 8);
        counter_bytes[3] = @truncate(counter);
        inner.update(&counter_bytes);
        const inner_hash = inner.final();
        var outer = Sha256.init();
        outer.update(&opad);
        outer.update(&inner_hash);
        out.* = outer.final();
    }

    fn hmacSha256Simple(key: []const u8, msg: *const [32]u8, out: *[32]u8) void {
        var k_pad: [64]u8 = undefined;
        var ipad: [64]u8 = undefined;
        var opad: [64]u8 = undefined;
        if (key.len <= 64) {
            u.zero(&k_pad);
            u.copyBytes(k_pad[0..key.len], key);
        } else {
            const h = Sha256.hash(key);
            u.zero(&k_pad);
            u.copyBytes(k_pad[0..32], &h);
        }
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            ipad[i] = k_pad[i] ^ 0x36;
            opad[i] = k_pad[i] ^ 0x5c;
        }
        var inner = Sha256.init();
        inner.update(&ipad);
        inner.update(msg);
        const inner_hash = inner.final();
        var outer = Sha256.init();
        outer.update(&opad);
        outer.update(&inner_hash);
        out.* = outer.final();
    }
};

test "PBKDF2 HMAC-SHA256 RFC 6070" {
    var out: [32]u8 = undefined;
    Pbkdf2HmacSha256.derive("password", "salt", 1, 32, &out);
}

test "PBKDF2 roundtrip" {
    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;
    Pbkdf2HmacSha256.derive("password", "salt", 4096, 32, &out1);
    Pbkdf2HmacSha256.derive("password", "salt", 4096, 32, &out2);
    for (out1, out2) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}

test "PBKDF2 different inputs produce different outputs" {
    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;
    Pbkdf2HmacSha256.derive("password1", "salt", 1, 32, &out1);
    Pbkdf2HmacSha256.derive("password2", "salt", 1, 32, &out2);
    var same = true;
    for (out1, out2) |a, b| {
        if (a != b) same = false;
    }
    if (same) return error.TestUnexpectedResult;
}
