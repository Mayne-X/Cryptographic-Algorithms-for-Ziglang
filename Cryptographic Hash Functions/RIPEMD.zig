const u = @import("../utils.zig");

pub const RipeMD160 = struct {
    state: [5]u32,
    buffer: [64]u8,
    buffer_len: usize,
    total_len: u64,

    const IV = [5]u32{
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
    };

    pub fn init() RipeMD160 {
        return RipeMD160{
            .state = IV,
            .buffer = undefined,
            .buffer_len = 0,
            .total_len = 0,
        };
    }

    fn f1(x: u32, y: u32, z: u32) u32 {
        return x ^ y ^ z;
    }

    fn f2(x: u32, y: u32, z: u32) u32 {
        return (x & y) | (~x & z);
    }

    fn f3(x: u32, y: u32, z: u32) u32 {
        return (x | ~y) ^ z;
    }

    fn f4(x: u32, y: u32, z: u32) u32 {
        return (x & z) | (y & ~z);
    }

    fn f5(x: u32, y: u32, z: u32) u32 {
        return x ^ (y | ~z);
    }

    fn rol(x: u32, n: u32) u32 {
        return (x << n) | (x >> (32 - n));
    }

    fn compress(s: *RipeMD160, block: *const [64]u8) void {
        var x: [16]u32 = undefined;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            x[i] = u.readU32Le(block[i * 4 ..][0..4]);
        }

        var aa = s.state[0];
        var bb = s.state[1];
        var cc = s.state[2];
        var dd = s.state[3];
        var ee = s.state[4];
        var aaa = aa;
        var bbb = bb;
        var ccc = cc;
        var ddd = dd;
        var eee = ee;

        const r = [_]u8{
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
            3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
            1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
            4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
        };

        const rp = [_]u8{
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
            6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
            15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
            8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
            12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
        };

        const s_ = [_]u8{
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
            9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
        };

        const sp = [_]u8{
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
            9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
            9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
            15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
            8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
        };

        const K = [_]u32{
            0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E,
        };

        const Kp = [_]u32{
            0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000,
        };

        var t: u32 = 0;
        i = 0;
        while (i < 80) : (i += 1) {
            if (i < 16) {
                t = aa + f1(bb, cc, dd) + x[r[i]] + K[0];
                t = rol(t, s_[i]);
                t = t + ee;
                aa = ee;
                ee = dd;
                dd = rol(cc, 10);
                cc = bb;
                bb = t;

                t = aaa + f5(bbb, ccc, ddd) + x[rp[i]] + Kp[0];
                t = rol(t, sp[i]);
                t = t + eee;
                aaa = eee;
                eee = ddd;
                ddd = rol(ccc, 10);
                ccc = bbb;
                bbb = t;
            } else if (i < 32) {
                t = aa + f2(bb, cc, dd) + x[r[i]] + K[1];
                t = rol(t, s_[i]);
                t = t + ee;
                aa = ee;
                ee = dd;
                dd = rol(cc, 10);
                cc = bb;
                bb = t;

                t = aaa + f4(bbb, ccc, ddd) + x[rp[i]] + Kp[1];
                t = rol(t, sp[i]);
                t = t + eee;
                aaa = eee;
                eee = ddd;
                ddd = rol(ccc, 10);
                ccc = bbb;
                bbb = t;
            } else if (i < 48) {
                t = aa + f3(bb, cc, dd) + x[r[i]] + K[2];
                t = rol(t, s_[i]);
                t = t + ee;
                aa = ee;
                ee = dd;
                dd = rol(cc, 10);
                cc = bb;
                bb = t;

                t = aaa + f3(bbb, ccc, ddd) + x[rp[i]] + Kp[2];
                t = rol(t, sp[i]);
                t = t + eee;
                aaa = eee;
                eee = ddd;
                ddd = rol(ccc, 10);
                ccc = bbb;
                bbb = t;
            } else if (i < 64) {
                t = aa + f4(bb, cc, dd) + x[r[i]] + K[3];
                t = rol(t, s_[i]);
                t = t + ee;
                aa = ee;
                ee = dd;
                dd = rol(cc, 10);
                cc = bb;
                bb = t;

                t = aaa + f2(bbb, ccc, ddd) + x[rp[i]] + Kp[3];
                t = rol(t, sp[i]);
                t = t + eee;
                aaa = eee;
                eee = ddd;
                ddd = rol(ccc, 10);
                ccc = bbb;
                bbb = t;
            } else {
                t = aa + f5(bb, cc, dd) + x[r[i]] + K[4];
                t = rol(t, s_[i]);
                t = t + ee;
                aa = ee;
                ee = dd;
                dd = rol(cc, 10);
                cc = bb;
                bb = t;

                t = aaa + f1(bbb, ccc, ddd) + x[rp[i]] + Kp[4];
                t = rol(t, sp[i]);
                t = t + eee;
                aaa = eee;
                eee = ddd;
                ddd = rol(ccc, 10);
                ccc = bbb;
                bbb = t;
            }
        }

        const temp = s.state[1] + cc + ddd;
        s.state[1] = s.state[2] + dd + eee;
        s.state[2] = s.state[3] + ee + aaa;
        s.state[3] = s.state[4] + aa + bbb;
        s.state[4] = s.state[0] + bb + ccc;
        s.state[0] = temp;
    }

    pub fn update(s: *RipeMD160, data: []const u8) void {
        var offset: usize = 0;
        if (s.buffer_len > 0) {
            const take = 64 - s.buffer_len;
            if (data.len < take) {
                u.copyBytes(s.buffer[s.buffer_len..], data);
                s.buffer_len += data.len;
                return;
            }
            u.copyBytes(s.buffer[s.buffer_len..], data[0..take]);
            s.compress(s.buffer[0..64]);
            s.total_len += 64;
            offset += take;
            s.buffer_len = 0;
        }
        while (offset + 64 <= data.len) {
            s.compress(data[offset..][0..64]);
            s.total_len += 64;
            offset += 64;
        }
        if (offset < data.len) {
            u.copyBytes(s.buffer[s.buffer_len..], data[offset..]);
            s.buffer_len += data.len - offset;
        }
    }

    pub fn final(s: *RipeMD160) [20]u8 {
        var pad: [64]u8 = undefined;
        u.zero(&pad);
        pad[0] = 0x80;
        s.update(&pad);
        while (s.buffer_len != 56) {
            s.update(&[0]u8);
        }
        var len_bytes: [8]u8 = undefined;
        u.writeU64Le(&len_bytes, s.total_len * 8);
        s.update(&len_bytes);

        var out: [20]u8 = undefined;
        var i: usize = 0;
        while (i < 5) : (i += 1) {
            u.writeU32Le(out[i * 4 ..][0..4], s.state[i]);
        }
        return out;
    }

    pub fn hash(data: []const u8) [20]u8 {
        var s = RipeMD160.init();
        s.update(data);
        return s.final();
    }
};

pub const RipeMD320 = struct {
    state: [10]u32,
    buffer: [64]u8,
    buffer_len: usize,
    total_len: u64,

    const IV = [10]u32{
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
        0x76543210, 0xFEDCBA98, 0x89ABCDEF, 0x01234567, 0x3C2D1E0F,
    };

    pub fn init() RipeMD320 {
        return RipeMD320{
            .state = IV,
            .buffer = undefined,
            .buffer_len = 0,
            .total_len = 0,
        };
    }

    fn f1(x: u32, y: u32, z: u32) u32 { return x ^ y ^ z; }
    fn f2(x: u32, y: u32, z: u32) u32 { return (x & y) | (~x & z); }
    fn f3(x: u32, y: u32, z: u32) u32 { return (x | ~y) ^ z; }
    fn f4(x: u32, y: u32, z: u32) u32 { return (x & z) | (y & ~z); }
    fn f5(x: u32, y: u32, z: u32) u32 { return x ^ (y | ~z); }
    fn rol(x: u32, n: u32) u32 { return (x << n) | (x >> (32 - n)); }

    fn compress(s: *RipeMD320, block: *const [64]u8) void {
        var x: [16]u32 = undefined;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            x[i] = u.readU32Le(block[i * 4 ..][0..4]);
        }

        var aa = s.state[0];
        var bb = s.state[1];
        var cc = s.state[2];
        var dd = s.state[3];
        var ee = s.state[4];
        var aaa = s.state[5];
        var bbb = s.state[6];
        var ccc = s.state[7];
        var ddd = s.state[8];
        var eee = s.state[9];

        const r = [_]u8{
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
            3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
            1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
            4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
        };

        const rp = [_]u8{
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
            6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
            15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
            8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
            12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
        };

        const s_ = [_]u8{
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
            9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
        };

        const sp = [_]u8{
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
            9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
            9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
            15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
            8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
        };

        const K = [_]u32{ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E };
        const Kp = [_]u32{ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000 };

        var t: u32 = 0;
        i = 0;
        while (i < 80) : (i += 1) {
            if (i < 16) {
                t = aa + f1(bb, cc, dd) + x[r[i]] + K[0];
                t = rol(t, s_[i]);
                t = t + ee;
                aa = ee; ee = dd; dd = rol(cc, 10); cc = bb; bb = t;
                t = aaa + f5(bbb, ccc, ddd) + x[rp[i]] + Kp[0];
                t = rol(t, sp[i]);
                t = t + eee;
                aaa = eee; eee = ddd; ddd = rol(ccc, 10); ccc = bbb; bbb = t;
            } else if (i < 32) {
                t = aa + f2(bb, cc, dd) + x[r[i]] + K[1];
                t = rol(t, s_[i]);
                t = t + ee;
                aa = ee; ee = dd; dd = rol(cc, 10); cc = bb; bb = t;
                t = aaa + f4(bbb, ccc, ddd) + x[rp[i]] + Kp[1];
                t = rol(t, sp[i]);
                t = t + eee;
                aaa = eee; eee = ddd; ddd = rol(ccc, 10); ccc = bbb; bbb = t;
            } else if (i < 48) {
                t = aa + f3(bb, cc, dd) + x[r[i]] + K[2];
                t = rol(t, s_[i]);
                t = t + ee;
                aa = ee; ee = dd; dd = rol(cc, 10); cc = bb; bb = t;
                t = aaa + f3(bbb, ccc, ddd) + x[rp[i]] + Kp[2];
                t = rol(t, sp[i]);
                t = t + eee;
                aaa = eee; eee = ddd; ddd = rol(ccc, 10); ccc = bbb; bbb = t;
            } else if (i < 64) {
                t = aa + f4(bb, cc, dd) + x[r[i]] + K[3];
                t = rol(t, s_[i]);
                t = t + ee;
                aa = ee; ee = dd; dd = rol(cc, 10); cc = bb; bb = t;
                t = aaa + f2(bbb, ccc, ddd) + x[rp[i]] + Kp[3];
                t = rol(t, sp[i]);
                t = t + eee;
                aaa = eee; eee = ddd; ddd = rol(ccc, 10); ccc = bbb; bbb = t;
            } else {
                t = aa + f5(bb, cc, dd) + x[r[i]] + K[4];
                t = rol(t, s_[i]);
                t = t + ee;
                aa = ee; ee = dd; dd = rol(cc, 10); cc = bb; bb = t;
                t = aaa + f1(bbb, ccc, ddd) + x[rp[i]] + Kp[4];
                t = rol(t, sp[i]);
                t = t + eee;
                aaa = eee; eee = ddd; ddd = rol(ccc, 10); ccc = bbb; bbb = t;
            }
        }

        const temp1 = s.state[1] + cc + ddd;
        s.state[1] = s.state[2] + dd + eee;
        s.state[2] = s.state[3] + ee + aaa;
        s.state[3] = s.state[4] + aa + bbb;
        s.state[4] = s.state[5] + bb + ccc;
        s.state[5] = s.state[6] + ccc + ddd;
        s.state[6] = s.state[7] + ddd + eee;
        s.state[7] = s.state[8] + eee + aaa;
        s.state[8] = s.state[9] + aa + bbb;
        s.state[9] = s.state[0] + bb + ccc;
        s.state[0] = temp1;
    }

    pub fn update(s: *RipeMD320, data: []const u8) void {
        var offset: usize = 0;
        if (s.buffer_len > 0) {
            const take = 64 - s.buffer_len;
            if (data.len < take) {
                u.copyBytes(s.buffer[s.buffer_len..], data);
                s.buffer_len += data.len;
                return;
            }
            u.copyBytes(s.buffer[s.buffer_len..], data[0..take]);
            s.compress(s.buffer[0..64]);
            s.total_len += 64;
            offset += take;
            s.buffer_len = 0;
        }
        while (offset + 64 <= data.len) {
            s.compress(data[offset..][0..64]);
            s.total_len += 64;
            offset += 64;
        }
        if (offset < data.len) {
            u.copyBytes(s.buffer[s.buffer_len..], data[offset..]);
            s.buffer_len += data.len - offset;
        }
    }

    pub fn final(s: *RipeMD320) [40]u8 {
        var pad: [64]u8 = undefined;
        u.zero(&pad);
        pad[0] = 0x80;
        s.update(&pad);
        while (s.buffer_len != 56) {
            s.update(&[0]u8);
        }
        var len_bytes: [8]u8 = undefined;
        u.writeU64Le(&len_bytes, s.total_len * 8);
        s.update(&len_bytes);

        var out: [40]u8 = undefined;
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            u.writeU32Le(out[i * 4 ..][0..4], s.state[i]);
        }
        return out;
    }

    pub fn hash(data: []const u8) [40]u8 {
        var s = RipeMD320.init();
        s.update(data);
        return s.final();
    }
};

test "RIPEMD-160 empty" {
    const h = RipeMD160.hash("");
    const expected = [20]u8{
        0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28,
        0x08, 0x97, 0x8e, 0xf8, 0xae, 0x9e, 0xbe, 0x0b, 0x77, 0x4c,
    };
    for (h, expected) |a, b| { if (a != b) return error.TestUnexpectedResult; }
}

test "RIPEMD-160 abc" {
    const h = RipeMD160.hash("abc");
    const expected = [20]u8{
        0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04,
        0x4a, 0x8e, 0x98, 0xc6, 0xb0, 0x87, 0xf1, 0x5a, 0x0b, 0xfc,
    };
    for (h, expected) |a, b| { if (a != b) return error.TestUnexpectedResult; }
}

test "RIPEMD-320 empty" {
    const h = RipeMD320.hash("");
    _ = h;
}

test "RIPEMD-320 abc" {
    const h = RipeMD320.hash("abc");
    _ = h;
}