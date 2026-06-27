const u = @import("../utils.zig");

pub const SHA1 = struct {
    state: [5]u32,
    buffer: [64]u8,
    buffer_len: usize,
    total_len: u64,

    const IV = [5]u32{
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
    };

    pub fn init() SHA1 {
        return SHA1{
            .state = IV,
            .buffer = undefined,
            .buffer_len = 0,
            .total_len = 0,
        };
    }

    fn rol(x: u32, n: u32) u32 { return (x << n) | (x >> (32 - n)); }

    fn compress(s: *SHA1, block: *const [64]u8) void {
        var w: [80]u32 = undefined;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            w[i] = u.readU32Be(block[i * 4 ..][0..4]);
        }
        while (i < 80) : (i += 1) {
            w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        var a = s.state[0];
        var b = s.state[1];
        var c = s.state[2];
        var d = s.state[3];
        var e = s.state[4];

        i = 0;
        while (i < 20) : (i += 1) {
            const f = (b & c) | (~b & d);
            const temp = rol(a, 5) + f + e + w[i] + 0x5A827999;
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = temp;
        }
        while (i < 40) : (i += 1) {
            const f = b ^ c ^ d;
            const temp = rol(a, 5) + f + e + w[i] + 0x6ED9EBA1;
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = temp;
        }
        while (i < 60) : (i += 1) {
            const f = (b & c) | (b & d) | (c & d);
            const temp = rol(a, 5) + f + e + w[i] + 0x8F1BBCDC;
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = temp;
        }
        while (i < 80) : (i += 1) {
            const f = b ^ c ^ d;
            const temp = rol(a, 5) + f + e + w[i] + 0xCA62C1D6;
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = temp;
        }

        s.state[0] += a;
        s.state[1] += b;
        s.state[2] += c;
        s.state[3] += d;
        s.state[4] += e;
    }

    pub fn update(s: *SHA1, data: []const u8) void {
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

    pub fn final(s: *SHA1) [20]u8 {
        var pad: [64]u8 = undefined;
        u.zero(&pad);
        pad[0] = 0x80;
        s.update(&pad);
        while (s.buffer_len != 56) {
            s.update(&[0]u8);
        }
        var len_bytes: [8]u8 = undefined;
        u.writeU64Be(&len_bytes, s.total_len * 8);
        s.update(&len_bytes);

        var out: [20]u8 = undefined;
        var i: usize = 0;
        while (i < 5) : (i += 1) {
            u.writeU32Be(out[i * 4 ..][0..4], s.state[i]);
        }
        return out;
    }

    pub fn hash(data: []const u8) [20]u8 {
        var s = SHA1.init();
        s.update(data);
        return s.final();
    }
};

test "SHA-1 empty" {
    const h = SHA1.hash("");
    const expected = [20]u8{
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
        0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
    };
    for (h, expected) |a, b| { if (a != b) return error.TestUnexpectedResult; }
}

test "SHA-1 abc" {
    const h = SHA1.hash("abc");
    const expected = [20]u8{
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
        0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
    };
    for (h, expected) |a, b| { if (a != b) return error.TestUnexpectedResult; }
}