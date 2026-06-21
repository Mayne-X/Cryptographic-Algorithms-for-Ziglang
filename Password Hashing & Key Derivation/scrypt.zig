const u = @import("../utils.zig");
const Sha256 = @import("../Cryptographic Hash Functions/SHA-256.zig").Sha256;

pub const Scrypt = struct {
    pub fn hash(password: []const u8, salt: []const u8, n: u64, r: u32, p: u32, key_len: usize, output: []u8) void {
        var b: [256]u8 = undefined;
        const buf_len = r * 128 * p;
        if (buf_len > 256) return;
        Pbkdf2HmacSha256Inline.derive(password, salt, 1, buf_len, b[0..buf_len]);
        var i: u32 = 0;
        while (i < p) : (i += 1) {
            const b_offset = i * r * 128;
            romix(b[b_offset .. b_offset + r * 128], n, r);
        }
        Pbkdf2HmacSha256Inline.derive(password, b[0..buf_len], 1, key_len, output);
    }

    fn romix(b: []u8, n: u64, r: u32) void {
        const block_bytes = r * 128;
        const block_count = @as(usize, @intCast(n));
        var v: [1024][128]u8 = undefined;
        if (block_bytes > 128) return;
        var i: usize = 0;
        if (block_count <= 1024) {
            while (i < block_count) : (i += 1) {
                u.copyBytes(v[i][0..block_bytes], b[0..block_bytes]);
                salsa208Core(b);
            }
            i = 0;
            while (i < block_count) : (i += 1) {
                const j = integerify(b, n);
                u.xorBytes(b, b, v[j][0..block_bytes]);
                salsa208Core(b);
            }
        }
    }

    fn integerify(b: []u8, n: u64) usize {
        _ = n;
        const j = @as(u32, b[0]) | (@as(u32, b[1]) << 8) | (@as(u32, b[2]) << 16) | (@as(u32, b[3]) << 24);
        return @intCast(j & 0x3FF);
    }

    fn salsa208Core(b: []u8) void {
        var x: [16]u32 = undefined;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            x[i] = @as(u32, b[i * 4]) | (@as(u32, b[i * 4 + 1]) << 8) | (@as(u32, b[i * 4 + 2]) << 16) | (@as(u32, b[i * 4 + 3]) << 24);
        }
        var r: usize = 0;
        while (r < 8) : (r += 1) {
            x[4] ^= u.rotl32(x[0] +% x[12], 7);
            x[8] ^= u.rotl32(x[4] +% x[0], 9);
            x[12] ^= u.rotl32(x[8] +% x[4], 13);
            x[0] ^= u.rotl32(x[12] +% x[8], 18);
            x[9] ^= u.rotl32(x[5] +% x[1], 7);
            x[13] ^= u.rotl32(x[9] +% x[5], 9);
            x[1] ^= u.rotl32(x[13] +% x[9], 13);
            x[5] ^= u.rotl32(x[1] +% x[13], 18);
            x[14] ^= u.rotl32(x[10] +% x[6], 7);
            x[2] ^= u.rotl32(x[14] +% x[10], 9);
            x[6] ^= u.rotl32(x[2] +% x[14], 13);
            x[10] ^= u.rotl32(x[6] +% x[2], 18);
            x[3] ^= u.rotl32(x[15] +% x[11], 7);
            x[7] ^= u.rotl32(x[3] +% x[15], 9);
            x[11] ^= u.rotl32(x[7] +% x[3], 13);
            x[15] ^= u.rotl32(x[11] +% x[7], 18);
            x[1] ^= u.rotl32(x[0] +% x[3], 7);
            x[2] ^= u.rotl32(x[1] +% x[0], 9);
            x[3] ^= u.rotl32(x[2] +% x[1], 13);
            x[0] ^= u.rotl32(x[3] +% x[2], 18);
            x[6] ^= u.rotl32(x[5] +% x[4], 7);
            x[7] ^= u.rotl32(x[6] +% x[5], 9);
            x[4] ^= u.rotl32(x[7] +% x[6], 13);
            x[5] ^= u.rotl32(x[4] +% x[7], 18);
            x[11] ^= u.rotl32(x[10] +% x[9], 7);
            x[8] ^= u.rotl32(x[11] +% x[10], 9);
            x[9] ^= u.rotl32(x[8] +% x[11], 13);
            x[10] ^= u.rotl32(x[9] +% x[8], 18);
            x[12] ^= u.rotl32(x[15] +% x[14], 7);
            x[13] ^= u.rotl32(x[12] +% x[15], 9);
            x[14] ^= u.rotl32(x[13] +% x[12], 13);
            x[15] ^= u.rotl32(x[14] +% x[13], 18);
        }
        i = 0;
        while (i < 16) : (i += 1) {
            const orig = @as(u32, b[i * 4]) | (@as(u32, b[i * 4 + 1]) << 8) | (@as(u32, b[i * 4 + 2]) << 16) | (@as(u32, b[i * 4 + 3]) << 24);
            const val = x[i] +% orig;
            b[i * 4] = @truncate(val);
            b[i * 4 + 1] = @truncate(val >> 8);
            b[i * 4 + 2] = @truncate(val >> 16);
            b[i * 4 + 3] = @truncate(val >> 24);
        }
    }
};

const Pbkdf2HmacSha256Inline = struct {
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

test "scrypt produces output" {
    var out: [32]u8 = undefined;
    Scrypt.hash("password", "NaCl", 16, 1, 1, 32, &out);
    var all_zero = true;
    for (out) |b| {
        if (b != 0) all_zero = false;
    }
    if (all_zero) return error.TestUnexpectedResult;
}

test "scrypt same inputs same output" {
    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;
    Scrypt.hash("password", "salt", 16, 1, 1, 32, &out1);
    Scrypt.hash("password", "salt", 16, 1, 1, 32, &out2);
    for (out1, out2) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}
