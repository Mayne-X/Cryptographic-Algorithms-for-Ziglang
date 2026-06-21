const u = @import("../utils.zig");

pub const Sha256 = struct {
    state: [8]u32,
    count: u64,
    buf: [64]u8,
    buf_len: usize,

    const K = [64]u32{
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    const H0 = [8]u32{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    pub fn init() Sha256 {
        var s = Sha256{ .state = H0, .count = 0, .buf = undefined, .buf_len = 0 };
        u.zero(&s.buf);
        return s;
    }

    fn ch(x: u32, y: u32, z: u32) u32 {
        return (x & y) ^ (~x & z);
    }

    fn maj(x: u32, y: u32, z: u32) u32 {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    fn sigma0(x: u32) u32 {
        return u.rotr32(x, 2) ^ u.rotr32(x, 13) ^ u.rotr32(x, 22);
    }

    fn sigma1(x: u32) u32 {
        return u.rotr32(x, 6) ^ u.rotr32(x, 11) ^ u.rotr32(x, 25);
    }

    fn gamma0(x: u32) u32 {
        return u.rotr32(x, 7) ^ u.rotr32(x, 18) ^ (x >> 3);
    }

    fn gamma1(x: u32) u32 {
        return u.rotr32(x, 17) ^ u.rotr32(x, 19) ^ (x >> 10);
    }

    fn round(s: *[8]u32, w: *const [64]u32) void {
        var a = s[0];
        var b = s[1];
        var c = s[2];
        var d = s[3];
        var e = s[4];
        var f = s[5];
        var g = s[6];
        var h = s[7];
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            const t1 = h +% sigma1(e) +% ch(e, f, g) +% K[i] +% w[i];
            const t2 = sigma0(a) +% maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d +% t1;
            d = c;
            c = b;
            b = a;
            a = t1 +% t2;
        }
        s[0] +%= a;
        s[1] +%= b;
        s[2] +%= c;
        s[3] +%= d;
        s[4] +%= e;
        s[5] +%= f;
        s[6] +%= g;
        s[7] +%= h;
    }

    fn processBlock(s: *Sha256, block: *const [64]u8) void {
        var w: [64]u32 = undefined;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            w[i] = u.readU32Be(block[i * 4 ..][0..4]);
        }
        i = 16;
        while (i < 64) : (i += 1) {
            w[i] = gamma1(w[i - 2]) +% w[i - 7] +% gamma0(w[i - 15]) +% w[i - 16];
        }
        round(&s.state, &w);
    }

    pub fn update(s: *Sha256, data: []const u8) void {
        s.count +%= @as(u64, data.len) * 8;
        var offset: usize = 0;
        if (s.buf_len > 0) {
            const take = 64 - s.buf_len;
            if (data.len < take) {
                u.copyBytes(s.buf[s.buf_len..], data);
                s.buf_len += data.len;
                return;
            }
            u.copyBytes(s.buf[s.buf_len..], data[0..take]);
            s.processBlock(s.buf[0..64]);
            offset = take;
            s.buf_len = 0;
        }
        while (offset + 64 <= data.len) {
            s.processBlock(data[offset..][0..64]);
            offset += 64;
        }
        if (offset < data.len) {
            u.copyBytes(s.buf[s.buf_len..], data[offset..]);
            s.buf_len = data.len - offset;
        }
    }

    pub fn final(s: *Sha256) [32]u8 {
        const bit_len = s.count +% @as(u64, s.buf_len) * 8;
        var pad_len: usize = 64 - s.buf_len;
        if (pad_len < 9) pad_len += 64;
        var pad_buf: [128]u8 = undefined;
        u.zero(&pad_buf);
        pad_buf[0] = 0x80;
        u.writeU64Be(pad_buf[pad_len - 8 ..][0..8], bit_len);
        s.update(pad_buf[0..pad_len]);
        var out: [32]u8 = undefined;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            u.writeU32Be(out[i * 4 ..][0..4], s.state[i]);
        }
        return out;
    }

    pub fn hash(data: []const u8) [32]u8 {
        var s = Sha256.init();
        s.update(data);
        return s.final();
    }
};

pub const Sha512 = struct {
    state: [8]u64,
    count: u128,
    buf: [128]u8,
    buf_len: usize,

    const K = [80]u64{
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da1fc2d, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3d638ece, 0x6c44198c4a475817,
    };

    const H0 = [8]u64{
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    };

    pub fn init() Sha512 {
        var s = Sha512{ .state = H0, .count = 0, .buf = undefined, .buf_len = 0 };
        u.zero(&s.buf);
        return s;
    }

    fn ch(x: u64, y: u64, z: u64) u64 {
        return (x & y) ^ (~x & z);
    }

    fn maj(x: u64, y: u64, z: u64) u64 {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    fn sigma0(x: u64) u64 {
        return u.rotr64(x, 28) ^ u.rotr64(x, 34) ^ u.rotr64(x, 39);
    }

    fn sigma1(x: u64) u64 {
        return u.rotr64(x, 14) ^ u.rotr64(x, 18) ^ u.rotr64(x, 41);
    }

    fn gamma0(x: u64) u64 {
        return u.rotr64(x, 1) ^ u.rotr64(x, 8) ^ (x >> 7);
    }

    fn gamma1(x: u64) u64 {
        return u.rotr64(x, 19) ^ u.rotr64(x, 61) ^ (x >> 6);
    }

    fn round(s: *[8]u64, w: *const [80]u64) void {
        var a = s[0];
        var b = s[1];
        var c = s[2];
        var d = s[3];
        var e = s[4];
        var f = s[5];
        var g = s[6];
        var h = s[7];
        var i: usize = 0;
        while (i < 80) : (i += 1) {
            const t1 = h +% sigma1(e) +% ch(e, f, g) +% K[i] +% w[i];
            const t2 = sigma0(a) +% maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d +% t1;
            d = c;
            c = b;
            b = a;
            a = t1 +% t2;
        }
        s[0] +%= a;
        s[1] +%= b;
        s[2] +%= c;
        s[3] +%= d;
        s[4] +%= e;
        s[5] +%= f;
        s[6] +%= g;
        s[7] +%= h;
    }

    fn processBlock(s: *Sha512, block: *const [128]u8) void {
        var w: [80]u64 = undefined;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            w[i] = u.readU64Be(block[i * 8 ..][0..8]);
        }
        i = 16;
        while (i < 80) : (i += 1) {
            w[i] = gamma1(w[i - 2]) +% w[i - 7] +% gamma0(w[i - 15]) +% w[i - 16];
        }
        round(&s.state, &w);
    }

    pub fn update(s: *Sha512, data: []const u8) void {
        s.count +%= @as(u128, data.len) * 8;
        var offset: usize = 0;
        if (s.buf_len > 0) {
            const take = 128 - s.buf_len;
            if (data.len < take) {
                u.copyBytes(s.buf[s.buf_len..], data);
                s.buf_len += data.len;
                return;
            }
            u.copyBytes(s.buf[s.buf_len..], data[0..take]);
            s.processBlock(s.buf[0..128]);
            offset = take;
            s.buf_len = 0;
        }
        while (offset + 128 <= data.len) {
            s.processBlock(data[offset..][0..128]);
            offset += 128;
        }
        if (offset < data.len) {
            u.copyBytes(s.buf[s.buf_len..], data[offset..]);
            s.buf_len = data.len - offset;
        }
    }

    pub fn final(s: *Sha512) [64]u8 {
        const bit_len = s.count +% @as(u128, s.buf_len) * 8;
        var pad_len: usize = 128 - s.buf_len;
        if (pad_len < 17) pad_len += 128;
        var pad_buf: [256]u8 = undefined;
        u.zero(&pad_buf);
        pad_buf[0] = 0x80;
        var len_buf: [16]u8 = undefined;
        u.writeU64Be(len_buf[0..8], @truncate(bit_len >> 64));
        u.writeU64Be(len_buf[8..16], @truncate(bit_len));
        u.copyBytes(pad_buf[pad_len - 16 ..], &len_buf);
        s.update(pad_buf[0..pad_len]);
        var out: [64]u8 = undefined;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            u.writeU64Be(out[i * 8 ..][0..8], s.state[i]);
        }
        return out;
    }

    pub fn hash(data: []const u8) [64]u8 {
        var s = Sha512.init();
        s.update(data);
        return s.final();
    }
};

test "SHA-256 empty string" {
    var s = Sha256.init();
    const h = s.final();
    const expected = [32]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    for (h, expected) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}

test "SHA-256 abc" {
    const h = Sha256.hash("abc");
    const expected = [32]u8{
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    for (h, expected) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}

test "SHA-512 abc" {
    const h = Sha512.hash("abc");
    const expected = [64]u8{
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9c, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x12, 0x36, 0x49, 0x8e, 0x9e, 0x4a, 0x09, 0xc2, 0x87, 0x7c, 0xf0, 0x67, 0x6f,
    };
    for (h, expected) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}
