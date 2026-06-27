const u = @import("../utils.zig");

pub const Grostl256 = struct {
    state: [8]u64,
    buffer: [64]u8,
    buffer_len: usize,
    total_len: u64,

    const SBOX = [256]u8{
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    };

    const INV_SBOX = [256]u8{
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    };

    const R = [10]u8{
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
    };

    pub fn init() Grostl256 {
        return Grostl256{
            .state = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
            .buffer = undefined,
            .buffer_len = 0,
            .total_len = 0,
        };
    }

    fn subBytes(s: *[64]u8) void {
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            s[i] = SBOX[s[i]];
        }
    }

    fn invSubBytes(s: *[64]u8) void {
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            s[i] = INV_SBOX[s[i]];
        }
    }

    fn shiftBytes(s: *[64]u8) void {
        var tmp: [64]u8 = s.*;
        var row: usize = 0;
        while (row < 8) : (row += 1) {
            var col: usize = 0;
            while (col < 8) : (col += 1) {
                s[row * 8 + col] = tmp[row * 8 + ((col + row) % 8)];
            }
        }
    }

    fn invShiftBytes(s: *[64]u8) void {
        var tmp: [64]u8 = s.*;
        var row: usize = 0;
        while (row < 8) : (row += 1) {
            var col: usize = 0;
            while (col < 8) : (col += 1) {
                s[row * 8 + col] = tmp[row * 8 + ((col + 8 - row) % 8)];
            }
        }
    }

    fn xtime(a: u8) u8 {
        return if ((a & 0x80) != 0) (a << 1) ^ 0x1B else a << 1;
    }

    fn mul(a: u8, b: u8) u8 {
        var p: u8 = 0;
        var aa = a;
        var bb = b;
        while (bb > 0) : (bb >>= 1) {
            if (bb & 1 != 0) p ^= aa;
            aa = xtime(aa);
        }
        return p;
    }

    fn mixColumns(s: *[64]u8) void {
        var i: usize = 0;
        while (i < 64) : (i += 8) {
            const a0 = s[i];
            const a1 = s[i + 1];
            const a2 = s[i + 2];
            const a3 = s[i + 3];
            const a4 = s[i + 4];
            const a5 = s[i + 5];
            const a6 = s[i + 6];
            const a7 = s[i + 7];
            s[i] = mul(2, a0) ^ mul(2, a1) ^ mul(3, a2) ^ mul(3, a3) ^ a4 ^ a5 ^ a6 ^ a7;
            s[i + 1] = a0 ^ mul(2, a1) ^ mul(2, a2) ^ mul(3, a3) ^ mul(3, a4) ^ a5 ^ a6 ^ a7;
            s[i + 2] = a0 ^ a1 ^ mul(2, a2) ^ mul(2, a3) ^ mul(3, a4) ^ mul(3, a5) ^ a6 ^ a7;
            s[i + 3] = mul(3, a0) ^ a1 ^ a2 ^ mul(2, a3) ^ mul(2, a4) ^ mul(3, a5) ^ mul(3, a6) ^ a7;
            s[i + 4] = a0 ^ mul(3, a1) ^ a2 ^ a3 ^ mul(2, a4) ^ mul(2, a5) ^ mul(3, a6) ^ mul(3, a7);
            s[i + 5] = mul(3, a0) ^ mul(3, a1) ^ a2 ^ a3 ^ a4 ^ mul(2, a5) ^ mul(2, a6) ^ mul(3, a7);
            s[i + 6] = mul(3, a0) ^ mul(3, a1) ^ mul(3, a2) ^ a3 ^ a4 ^ a5 ^ mul(2, a6) ^ mul(2, a7);
            s[i + 7] = mul(2, a0) ^ mul(3, a1) ^ mul(3, a2) ^ mul(3, a3) ^ a4 ^ a5 ^ a6 ^ mul(2, a7);
        }
    }

    fn invMixColumns(s: *[64]u8) void {
        var i: usize = 0;
        while (i < 64) : (i += 8) {
            const a0 = s[i];
            const a1 = s[i + 1];
            const a2 = s[i + 2];
            const a3 = s[i + 3];
            const a4 = s[i + 4];
            const a5 = s[i + 5];
            const a6 = s[i + 6];
            const a7 = s[i + 7];
            s[i] = mul(14, a0) ^ mul(11, a1) ^ mul(13, a2) ^ mul(9, a3) ^ mul(14, a4) ^ mul(11, a5) ^ mul(13, a6) ^ mul(9, a7);
            s[i + 1] = mul(9, a0) ^ mul(14, a1) ^ mul(11, a2) ^ mul(13, a3) ^ mul(9, a4) ^ mul(14, a5) ^ mul(11, a6) ^ mul(13, a7);
            s[i + 2] = mul(13, a0) ^ mul(9, a1) ^ mul(14, a2) ^ mul(11, a3) ^ mul(13, a4) ^ mul(9, a5) ^ mul(14, a6) ^ mul(11, a7);
            s[i + 3] = mul(11, a0) ^ mul(13, a1) ^ mul(9, a2) ^ mul(14, a3) ^ mul(11, a4) ^ mul(13, a5) ^ mul(9, a6) ^ mul(14, a7);
            s[i + 4] = mul(14, a0) ^ mul(11, a1) ^ mul(13, a2) ^ mul(9, a3) ^ mul(14, a4) ^ mul(11, a5) ^ mul(13, a6) ^ mul(9, a7);
            s[i + 5] = mul(9, a0) ^ mul(14, a1) ^ mul(11, a2) ^ mul(13, a3) ^ mul(9, a4) ^ mul(14, a5) ^ mul(11, a6) ^ mul(13, a7);
            s[i + 6] = mul(13, a0) ^ mul(9, a1) ^ mul(14, a2) ^ mul(11, a3) ^ mul(13, a4) ^ mul(9, a5) ^ mul(14, a6) ^ mul(11, a7);
            s[i + 7] = mul(11, a0) ^ mul(13, a1) ^ mul(9, a2) ^ mul(14, a3) ^ mul(11, a4) ^ mul(13, a5) ^ mul(9, a6) ^ mul(14, a7);
        }
    }

    fn addRoundConstant(s: *[8]u64, round: usize) void {
        s[0] ^= @as(u64, R[round]) << 56;
    }

    fn P(s: *Grostl256, Q: *[8]u64) void {
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            Q[i] = s.state[i];
        }
        var round: usize = 0;
        while (round < 10) : (round += 1) {
            var i: usize = 0;
            while (i < 8) : (i += 1) {
                var bytes: [8]u8 = undefined;
                u.writeU64Be(&bytes, Q[i]);
                s.subBytes(&bytes);
                var bytes2: [8]u8 = bytes;
                s.shiftBytes(&bytes2);
                var j: usize = 0;
                while (j < 8) : (j += 1) {
                    s.mixColumns(&bytes2);
                }
                var mixed: [8]u8 = bytes2;
                s.addRoundConstant(Q, round);
                u.writeU64Be(&bytes, Q[i]);
                s.shiftBytes(&bytes);
                var j2: usize = 0;
                while (j2 < 8) : (j2 += 1) {
                    s.mixColumns(&bytes);
                }
                var final_bytes: [8]u8 = bytes;
                var k: usize = 0;
                while (k < 8) : (k += 1) {
                    Q[k] ^= u.readU64Be(&final_bytes[k * 8 ..][0..8]);
                }
            }
        }
    }

    fn Q(s: *Grostl256, Q: *[8]u64) void {
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            Q[i] = s.state[i];
        }
        var round: usize = 0;
        while (round < 10) : (round += 1) {
            var i: usize = 0;
            while (i < 8) : (i += 1) {
                var bytes: [8]u8 = undefined;
                u.writeU64Be(&bytes, Q[i]);
                s.subBytes(&bytes);
                s.shiftBytes(&bytes);
                s.mixColumns(&bytes);
                s.addRoundConstant(Q, round);
            }
        }
    }

    fn compress(s: *Grostl256, block: *const [64]u8) void {
        var P_state: [8]u64 = undefined;
        var Q_state: [8]u64 = undefined;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            s.state[i] = u.readU64Be(block[i * 8 ..][0..8]) ^ s.state[i];
        }
        s.P(&P_state);
        s.Q(&Q_state);
        i = 0;
        while (i < 8) : (i += 1) {
            s.state[i] ^= P_state[i] ^ Q_state[i];
        }
    }

    pub fn update(s: *Grostl256, data: []const u8) void {
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

    pub fn final(s: *Grostl256) [32]u8 {
        var pad: [64]u8 = undefined;
        u.zero(&pad);
        pad[0] = 0x80;
        s.update(&pad);
        while (s.buffer_len != 55) {
            s.update(&[0]u8);
        }
        var len_bytes: [8]u8 = undefined;
        u.writeU64Be(&len_bytes, s.total_len);
        s.update(&len_bytes);

        var out: [32]u8 = undefined;
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            u.writeU64Be(out[i * 8 ..][0..8], s.state[i]);
        }
        return out;
    }

    pub fn hash(data: []const u8) [32]u8 {
        var s = Grostl256.init();
        s.update(data);
        return s.final();
    }
};

pub const Grostl512 = struct {
    pub fn hash(data: []const u8) [64]u8 {
        _ = data;
        var out: [64]u8 = undefined;
        return out;
    }
};

test "Grøstl-256 empty" {
    const h = Grostl256.hash("");
    _ = h;
}

test "Grøstl-256 abc" {
    const h = Grostl256.hash("abc");
    _ = h;
}

test "Grøstl-512 empty" {
    const h = Grostl512.hash("");
    _ = h;
}