const u = @import("../utils.zig");

pub const MD5 = struct {
    state: [4]u32,
    buffer: [64]u8,
    buffer_len: usize,
    total_len: u64,

    const IV = [4]u32{
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476,
    };

    pub fn init() MD5 {
        return MD5{
            .state = IV,
            .buffer = undefined,
            .buffer_len = 0,
            .total_len = 0,
        };
    }

    fn F(x: u32, y: u32, z: u32) u32 { return (x & y) | (~x & z); }
    fn G(x: u32, y: u32, z: u32) u32 { return (x & z) | (y & ~z); }
    fn H(x: u32, y: u32, z: u32) u32 { return x ^ y ^ z; }
    fn I(x: u32, y: u32, z: u32) u32 { return y ^ (x | ~z); }
    fn rol(x: u32, n: u32) u32 { return (x << n) | (x >> (32 - n)); }

    const K = [64]u32{
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    };

    const S = [64]u32{
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    };

    fn compress(s: *MD5, block: *const [64]u8) void {
        var x: [16]u32 = undefined;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            x[i] = u.readU32Le(block[i * 4 ..][0..4]);
        }

        var a = s.state[0];
        var b = s.state[1];
        var c = s.state[2];
        var d = s.state[3];

        i = 0;
        while (i < 16) : (i += 1) {
            const temp = d;
            d = c;
            c = b;
            b = b + rol(a + F(b, c, d) + x[i] + K[i], S[i]);
            a = temp;
        }
        while (i < 32) : (i += 1) {
            const temp = d;
            d = c;
            c = b;
            const g = (5 * i + 1) % 16;
            b = b + rol(a + G(b, c, d) + x[g] + K[i], S[i]);
            a = temp;
        }
        while (i < 48) : (i += 1) {
            const temp = d;
            d = c;
            c = b;
            const g = (3 * i + 5) % 16;
            b = b + rol(a + H(b, c, d) + x[g] + K[i], S[i]);
            a = temp;
        }
        while (i < 64) : (i += 1) {
            const temp = d;
            d = c;
            c = b;
            const g = (7 * i) % 16;
            b = b + rol(a + I(b, c, d) + x[g] + K[i], S[i]);
            a = temp;
        }

        s.state[0] += a;
        s.state[1] += b;
        s.state[2] += c;
        s.state[3] += d;
    }

    pub fn update(s: *MD5, data: []const u8) void {
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

    pub fn final(s: *MD5) [16]u8 {
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

        var out: [16]u8 = undefined;
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            u.writeU32Le(out[i * 4 ..][0..4], s.state[i]);
        }
        return out;
    }

    pub fn hash(data: []const u8) [16]u8 {
        var s = MD5.init();
        s.update(data);
        return s.final();
    }
};

test "MD5 empty" {
    const h = MD5.hash("");
    const expected = [16]u8{
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
    };
    for (h, expected) |a, b| { if (a != b) return error.TestUnexpectedResult; }
}

test "MD5 abc" {
    const h = MD5.hash("abc");
    const expected = [16]u8{
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
    };
    for (h, expected) |a, b| { if (a != b) return error.TestUnexpectedResult; }
}

test "MD5 message digest" {
    const h = MD5.hash("message digest");
    const expected = [16]u8{
        0xf9, 0x6b, 0x69, 0x7c, 0x7c, 0xb4, 0x10, 0xff, 0x61, 0x71, 0x8c, 0x6a, 0x1a, 0x61, 0x4e, 0x5a,
    };
    for (h, expected) |a, b| { if (a != b) return error.TestUnexpectedResult; }
}