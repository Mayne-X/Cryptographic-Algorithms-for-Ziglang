const u = @import("../utils.zig");

pub const Whirlpool = struct {
    state: [8]u64,
    buffer: [64]u8,
    buffer_len: usize,
    total_len: u64,

    const SBOX = [256]u8{
        0x18, 0x23, 0xC6, 0xE8, 0x87, 0x48, 0xD9, 0xA9, 0x1D, 0xF5, 0xEB, 0xC3, 0xE5, 0xE1, 0x1F, 0xAC,
        0xDB, 0x01, 0x02, 0x0D, 0x49, 0xC2, 0x54, 0xBB, 0xDE, 0xA3, 0x7A, 0xF0, 0x33, 0x6B, 0x47, 0xE2,
        0x51, 0xA6, 0x10, 0x29, 0xE4, 0xF8, 0x8C, 0x9D, 0xC8, 0x6F, 0xE7, 0xAE, 0xB5, 0x3F, 0x12, 0xCE,
        0x7B, 0x21, 0x82, 0x46, 0x14, 0x99, 0x2E, 0x8A, 0x17, 0x5E, 0x34, 0xC7, 0xE0, 0x5B, 0x3A, 0x2A,
        0x6C, 0xC5, 0x2C, 0xBF, 0x1E, 0xE9, 0x0F, 0x4B, 0x3B, 0x24, 0x9F, 0x84, 0x4F, 0x4E, 0x50, 0x6D,
        0xD6, 0x93, 0x7E, 0x15, 0x3D, 0xCA, 0xAE, 0xF1, 0xED, 0x30, 0x5D, 0xD2, 0xCF, 0x1C, 0x3E, 0x0B,
        0x85, 0x2B, 0x98, 0x0E, 0x39, 0x35, 0x6A, 0x9E, 0xA0, 0x58, 0x65, 0xFA, 0xDD, 0xC4, 0xFB, 0x1B,
        0x94, 0x03, 0xA4, 0xD5, 0x64, 0x5C, 0x96, 0x4A, 0x90, 0x57, 0x80, 0x40, 0x9C, 0xAF, 0x20, 0x97,
        0x56, 0x53, 0x95, 0x07, 0x8B, 0x91, 0x9A, 0x7D, 0xC1, 0x11, 0x08, 0x22, 0x3C, 0xEE, 0x68, 0xF4,
        0x71, 0xB2, 0x37, 0x4D, 0x7F, 0x00, 0x6E, 0x25, 0x8D, 0x86, 0x06, 0xF9, 0xF2, 0xA8, 0x2D, 0xBE,
        0xAB, 0xE6, 0x88, 0x92, 0x38, 0x59, 0x67, 0x13, 0x75, 0x2F, 0xB0, 0x43, 0xC9, 0xD1, 0x7C, 0xA5,
        0x28, 0x72, 0x62, 0x27, 0x05, 0xD3, 0x5A, 0x04, 0x19, 0x79, 0xA7, 0x4C, 0x74, 0x26, 0x31, 0xD4,
        0xFE, 0x0C, 0x45, 0x83, 0x20, 0x66, 0xD8, 0xF6, 0xDC, 0x8F, 0x77, 0xB1, 0x41, 0xAD, 0x73, 0xEF,
        0xB8, 0x63, 0x5F, 0xE3, 0x44, 0xD7, 0xA1, 0x2C, 0xBD, 0x1A, 0xFC, 0x60, 0x81, 0x42, 0x16, 0xB9,
        0xF7, 0x9B, 0x32, 0x76, 0x09, 0x52, 0xF3, 0x8E, 0xBC, 0xB6, 0xDA, 0x61, 0x55, 0xA2, 0xEC, 0xB4,
        0x36, 0xD0, 0x4B, 0x78, 0xFF, 0x70, 0xE5, 0x89, 0xCD, 0x4E, 0xB3, 0x0A, 0xCC, 0x9D, 0x5E, 0xA1,
    };

    const C = [8]u64{
        0x735A6BC5DBE39413, 0x5D82D5C1C8E5A49C, 0x72A4D7C3E8D1C5D7, 0x6FD1E3F7A1D8E4C7,
        0x1D9A4B8E6C5A3D7E, 0xE8A3F4D2C6B9A1D7, 0x5C2F7E3D1A6B8C4E, 0x2D4E9C7A1F6B8D3E,
    };

    pub fn init() Whirlpool {
        return Whirlpool{
            .state = [_]u64{0} ** 8,
            .buffer = undefined,
            .buffer_len = 0,
            .total_len = 0,
        };
    }

    fn mulGF2(a: u8, b: u8) u8 {
        var p: u8 = 0;
        var aa = a;
        var bb = b;
        while (bb > 0) : (bb >>= 1) {
            if (bb & 1 != 0) p ^= aa;
            var hi = aa & 0x80;
            aa <<= 1;
            if (hi != 0) aa ^= 0x1D;
        }
        return p;
    }

    fn compress(s: *Whirlpool, block: *const [64]u8) void {
        var K: [8]u64 = undefined;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            K[i] = u.readU64Be(block[i * 8 ..][0..8]);
        }
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            K[i] ^= s.state[i];
        }

        var r = 0;
        while (r < 10) : (r += 1) {
            var S: [8]u64 = undefined;
            i = 0;
            while (i < 8) : (i += 1) {
                var v: u64 = 0;
                var j: usize = 0;
                while (j < 8) : (j += 1) {
                    const idx = (i - j) & 7;
                    const byte = @truncate((K[idx] >> @truncate((7 - j) * 8)) & 0xFF);
                    v |= @as(u64, SBOX[byte]) << @truncate(j * 8);
                }
                S[i] = v;
            }
            i = 0;
            while (i < 8) : (i += 1) {
                var v: u64 = 0;
                v = 0;
                var j: usize = 0;
                while (j < 8) : (j += 1) {
                    var sum: u64 = 0;
                    var k: usize = 0;
                    while (k < 8) : (k += 1) {
                        const byte = @truncate((S[k] >> @truncate((7 - j) * 8)) & 0xFF);
                        sum ^= @as(u64, SBOX[byte]) << @truncate((k * 8));
                    }
                    v |= sum & 0xFF;
                    v = v << 8;
                }
                K[i] = v ^ C[i];
            }
        }
        i = 0;
        while (i < 8) : (i += 1) {
            s.state[i] ^= K[i];
        }
    }

    pub fn update(s: *Whirlpool, data: []const u8) void {
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
            s.total_len += 512;
            offset += take;
            s.buffer_len = 0;
        }
        while (offset + 64 <= data.len) {
            s.compress(data[offset..][0..64]);
            s.total_len += 512;
            offset += 64;
        }
        if (offset < data.len) {
            u.copyBytes(s.buffer[s.buffer_len..], data[offset..]);
            s.buffer_len += data.len - offset;
        }
    }

    pub fn final(s: *Whirlpool) [64]u8 {
        var pad: [64]u8 = undefined;
        u.zero(&pad);
        pad[0] = 0x80;
        s.update(&pad);
        while (s.buffer_len != 32) {
            s.update(&[0]u8);
        }
        var len_bytes: [32]u8 = undefined;
        u.writeU64Be(&len_bytes, s.total_len);
        s.update(&len_bytes);

        var out: [64]u8 = undefined;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            u.writeU64Be(out[i * 8 ..][0..8], s.state[i]);
        }
        return out;
    }

    pub fn hash(data: []const u8) [64]u8 {
        var s = Whirlpool.init();
        s.update(data);
        return s.final();
    }
};

test "Whirlpool empty" {
    const h = Whirlpool.hash("");
    _ = h;
}

test "Whirlpool abc" {
    const h = Whirlpool.hash("abc");
    _ = h;
}