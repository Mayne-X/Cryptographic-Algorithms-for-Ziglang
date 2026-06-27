const u = @import("../utils.zig");

pub const Blake2s = struct {
    h: [8]u32,
    t: [2]u32,
    buf: [64]u8,
    buf_len: usize,
    last_block: bool,
    key_len: usize,
    digest_len: usize,

    const IV = [8]u32{
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    const SIGMA = [10][16]u8{
        .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        .{ 6, 15, 14, 9, 11, 3, 6, 8, 12, 0, 2, 13, 5, 10, 15, 7 },
        .{ 8, 2, 1, 14, 7, 4, 0, 10, 5, 13, 15, 10, 3, 6, 12, 11 },
    };

    pub fn init(digest_len: usize) Blake2s {
        return initKey(&[_]u8{}, digest_len);
    }

    pub fn initKey(key: []const u8, digest_len: usize) Blake2s {
        var s = Blake2s{
            .h = IV,
            .t = [_]u32{0} ** 2,
            .buf = undefined,
            .buf_len = 0,
            .last_block = false,
            .key_len = key.len,
            .digest_len = digest_len,
        };
        u.zero(&s.buf);
        var param: u32 = 0;
        param = @as(u32, digest_len) | (@as(u32, key.len) << 8) | (@as(u32, 1) << 16) | (@as(u32, 1) << 24);
        s.h[0] ^= param;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            if (s.h[i] == 0) s.h[i] = IV[i];
        }
        u.zero(&s.buf);
        if (key.len > 0) {
            u.copyBytes(s.buf[0..key.len], key);
            s.buf_len = 64;
        }
        return s;
    }

    fn rotr(x: u32, n: u32) u32 {
        return (x >> n) | (x << (32 - n));
    }

    fn g(v: *[16]u32, a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) void {
        v[a] = v[a] +% v[b] +% x;
        v[d] = rotr(v[d] ^ v[a], 16);
        v[c] = v[c] +% v[d];
        v[b] = rotr(v[b] ^ v[c], 12);
        v[a] = v[a] +% v[b] +% y;
        v[d] = rotr(v[d] ^ v[a], 8);
        v[c] = v[c] +% v[d];
        v[b] = rotr(v[b] ^ v[c], 7);
    }

    fn compress(s: *Blake2s, block: *const [64]u8) void {
        var m: [16]u32 = undefined;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            m[i] = u.readU32Le(block[i * 4 ..][0..4]);
        }
        var v: [16]u32 = undefined;
        i = 0;
        while (i < 8) : (i += 1) {
            v[i] = s.h[i];
            v[i + 8] = IV[i];
        }
        v[12] ^= s.t[0];
        v[13] ^= s.t[1];
        if (s.last_block) v[14] = ~v[14];
        var r: usize = 0;
        while (r < 10) : (r += 1) {
            const sig = SIGMA[r];
            g(&v, 0, 4, 8, 12, m[sig[0]], m[sig[1]]);
            g(&v, 1, 5, 9, 13, m[sig[2]], m[sig[3]]);
            g(&v, 2, 6, 10, 14, m[sig[4]], m[sig[5]]);
            g(&v, 3, 7, 11, 15, m[sig[6]], m[sig[7]]);
            g(&v, 0, 5, 10, 15, m[sig[8]], m[sig[9]]);
            g(&v, 1, 6, 11, 12, m[sig[10]], m[sig[11]]);
            g(&v, 2, 7, 8, 13, m[sig[12]], m[sig[13]]);
            g(&v, 3, 4, 9, 14, m[sig[14]], m[sig[15]]);
        }
        i = 0;
        while (i < 8) : (i += 1) {
            s.h[i] = v[i] ^ v[i + 8];
        }
    }

    pub fn update(s: *Blake2s, data: []const u8) void {
        var offset: usize = 0;
        if (s.buf_len > 0) {
            const take = 64 - s.buf_len;
            if (data.len < take) {
                u.copyBytes(s.buf[s.buf_len..], data);
                s.buf_len += data.len;
                return;
            }
            u.copyBytes(s.buf[s.buf_len..], data[0..take]);
            s.t[0] +%= 64;
            if (s.t[0] < 64) s.t[1] +%= 1;
            s.compress(s.buf[0..64]);
            offset += take;
            s.buf_len = 0;
        }
        while (offset + 64 <= data.len) {
            s.t[0] +%= 64;
            if (s.t[0] < 64) s.t[1] +%= 1;
            s.compress(data[offset..][0..64]);
            offset += 64;
        }
        if (offset < data.len) {
            u.copyBytes(s.buf[s.buf_len..], data[offset..]);
            s.buf_len += data.len - offset;
        }
    }

    pub fn final(s: *Blake2s) [32]u8 {
        s.t[0] +%= @as(u32, s.buf_len);
        if (s.t[0] < s.buf_len) s.t[1] +%= 1;
        s.last_block = true;
        u.zero(s.buf[s.buf_len..]);
        s.compress(s.buf[0..64]);
        var out: [32]u8 = undefined;
        var i: usize = 0;
        while (i < s.digest_len / 4) : (i += 1) {
            u.writeU32Le(out[i * 4 ..][0..4], s.h[i]);
        }
        const rem = s.digest_len % 4;
        if (rem > 0) {
            var tmp: [4]u8 = undefined;
            u.writeU32Le(&tmp, s.h[s.digest_len / 4]);
            var j: usize = 0;
            while (j < rem) : (j += 1) {
                out[s.digest_len / 4 * 4 + j] = tmp[j];
            }
        }
        return out;
    }

    pub fn hash(data: []const u8) [32]u8 {
        var s = Blake2s.init(32);
        s.update(data);
        return s.final();
    }
};

test "BLAKE2s empty" {
    var s = Blake2s.init(32);
    const h = s.final();
    _ = h;
}

test "BLAKE2s abc" {
    var s = Blake2s.init(32);
    s.update("abc");
    const h = s.final();
    _ = h;
}