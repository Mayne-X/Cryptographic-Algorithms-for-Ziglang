const u = @import("../utils.zig");

pub const Sha3_256 = struct {
    state: [25]u64,
    buf: [136]u8,
    buf_len: usize,
    digest_len: usize,

    const RATE: usize = 136;
    const ROUNDS: usize = 24;

    const RC = [24]u64{
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000880a, 0x000000008000000a, 0x0000000080008081, 0x8000000080008080,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008, 0x000000000000808b,
        0x000000008000000a, 0x0000000080008082, 0x8000000000000080, 0x8000000080000001,
        0x8000000080008008, 0x000000000000808a, 0x000000000000008b, 0x800000008000000a,
    };

    const ROTATIONS = [5][5]u6{
        .{ 0, 1, 62, 28, 27 },
        .{ 36, 44, 6, 55, 20 },
        .{ 3, 10, 43, 25, 39 },
        .{ 41, 45, 15, 21, 8 },
        .{ 18, 2, 61, 56, 14 },
    };

    pub fn init() Sha3_256 {
        var s = Sha3_256{
            .state = [_]u64{0} ** 25,
            .buf = undefined,
            .buf_len = 0,
            .digest_len = 32,
        };
        u.zero(&s.buf);
        return s;
    }

    fn keccakF(state: *[25]u64) void {
        var r: usize = 0;
        while (r < ROUNDS) : (r += 1) {
            var c: [5]u64 = undefined;
            var i: usize = 0;
            while (i < 5) : (i += 1) {
                c[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
            }
            var d: [5]u64 = undefined;
            i = 0;
            while (i < 5) : (i += 1) {
                d[i] = c[(i + 4) % 5] ^ u.rotl64(c[(i + 1) % 5], 1);
            }
            var b: [25]u64 = undefined;
            i = 0;
            while (i < 25) : (i += 1) {
                state[i] ^= d[i % 5];
            }
            i = 0;
            while (i < 25) : (i += 1) {
                const x = i % 5;
                const y = i / 5;
                b[(2 * x + 3 * y) % 5 * 5 + x] = u.rotl64(state[i], ROTATIONS[y][x]);
            }
            i = 0;
            while (i < 25) : (i += 1) {
                const x = i % 5;
                const y = i / 5;
                state[i] = b[i] ^ (~b[(x + 1) % 5 + y * 5] & b[(x + 2) % 5 + y * 5]);
            }
            state[0] ^= RC[r];
        }
    }

    fn absorb(s: *Sha3_256, block: *const [RATE]u8) void {
        var i: usize = 0;
        while (i < RATE / 8) : (i += 1) {
            s.state[i] ^= u.readU64Le(block[i * 8 ..][0..8]);
        }
        keccakF(&s.state);
    }

    pub fn update(s: *Sha3_256, data: []const u8) void {
        var offset: usize = 0;
        if (s.buf_len > 0) {
            const take = RATE - s.buf_len;
            if (data.len < take) {
                u.copyBytes(s.buf[s.buf_len..], data);
                s.buf_len += data.len;
                return;
            }
            u.copyBytes(s.buf[s.buf_len..], data[0..take]);
            s.absorb(s.buf[0..RATE]);
            offset = take;
            s.buf_len = 0;
        }
        while (offset + RATE <= data.len) {
            s.absorb(data[offset..][0..RATE]);
            offset += RATE;
        }
        if (offset < data.len) {
            u.copyBytes(s.buf[s.buf_len..], data[offset..]);
            s.buf_len = data.len - offset;
        }
    }

    pub fn final(s: *Sha3_256) [32]u8 {
        u.zero(s.buf[s.buf_len..]);
        s.buf[s.buf_len] = 0x06;
        s.buf[RATE - 1] |= 0x80;
        s.absorb(s.buf[0..RATE]);
        var out: [32]u8 = undefined;
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            u.writeU64Le(out[i * 8 ..][0..8], s.state[i]);
        }
        return out;
    }

    pub fn hash(data: []const u8) [32]u8 {
        var s = Sha3_256.init();
        s.update(data);
        return s.final();
    }
};

pub const Shake128 = struct {
    state: [25]u64,
    buf: [168]u8,
    buf_len: usize,
    squeeze_pos: usize,

    const RATE: usize = 168;
    const ROUNDS: usize = 24;

    const RC = [24]u64{
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000880a, 0x000000008000000a, 0x0000000080008081, 0x8000000080008080,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008, 0x000000000000808b,
        0x000000008000000a, 0x0000000080008082, 0x8000000000000080, 0x8000000080000001,
        0x8000000080008008, 0x000000000000808a, 0x000000000000008b, 0x800000008000000a,
    };

    const ROTATIONS = [5][5]u6{
        .{ 0, 1, 62, 28, 27 },
        .{ 36, 44, 6, 55, 20 },
        .{ 3, 10, 43, 25, 39 },
        .{ 41, 45, 15, 21, 8 },
        .{ 18, 2, 61, 56, 14 },
    };

    pub fn init() Shake128 {
        var s = Shake128{
            .state = [_]u64{0} ** 25,
            .buf = undefined,
            .buf_len = 0,
            .squeeze_pos = 0,
        };
        u.zero(&s.buf);
        return s;
    }

    fn keccakF(state: *[25]u64) void {
        var r: usize = 0;
        while (r < ROUNDS) : (r += 1) {
            var c: [5]u64 = undefined;
            var i: usize = 0;
            while (i < 5) : (i += 1) {
                c[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
            }
            var d: [5]u64 = undefined;
            i = 0;
            while (i < 5) : (i += 1) {
                d[i] = c[(i + 4) % 5] ^ u.rotl64(c[(i + 1) % 5], 1);
            }
            var b: [25]u64 = undefined;
            i = 0;
            while (i < 25) : (i += 1) {
                state[i] ^= d[i % 5];
            }
            i = 0;
            while (i < 25) : (i += 1) {
                const x = i % 5;
                const y = i / 5;
                b[(2 * x + 3 * y) % 5 * 5 + x] = u.rotl64(state[i], ROTATIONS[y][x]);
            }
            i = 0;
            while (i < 25) : (i += 1) {
                const x = i % 5;
                const y = i / 5;
                state[i] = b[i] ^ (~b[(x + 1) % 5 + y * 5] & b[(x + 2) % 5 + y * 5]);
            }
            state[0] ^= RC[r];
        }
    }

    fn absorb(s: *Shake128, block: *const [RATE]u8) void {
        var i: usize = 0;
        while (i < RATE / 8) : (i += 1) {
            s.state[i] ^= u.readU64Le(block[i * 8 ..][0..8]);
        }
        keccakF(&s.state);
    }

    pub fn update(s: *Shake128, data: []const u8) void {
        var offset: usize = 0;
        if (s.buf_len > 0) {
            const take = RATE - s.buf_len;
            if (data.len < take) {
                u.copyBytes(s.buf[s.buf_len..], data);
                s.buf_len += data.len;
                return;
            }
            u.copyBytes(s.buf[s.buf_len..], data[0..take]);
            s.absorb(s.buf[0..RATE]);
            offset = take;
            s.buf_len = 0;
        }
        while (offset + RATE <= data.len) {
            s.absorb(data[offset..][0..RATE]);
            offset += RATE;
        }
        if (offset < data.len) {
            u.copyBytes(s.buf[s.buf_len..], data[offset..]);
            s.buf_len = data.len - offset;
        }
    }

    pub fn squeeze(s: *Shake128, output: []u8) void {
        u.zero(s.buf[s.buf_len..]);
        s.buf[s.buf_len] = 0x1f;
        s.buf[RATE - 1] |= 0x80;
        var i: usize = 0;
        while (i < RATE / 8) : (i += 1) {
            s.state[i] ^= u.readU64Le(s.buf[i * 8 ..][0..8]);
        }
        Sha3_256.keccakF(&s.state);
        var out_pos: usize = 0;
        while (out_pos < output.len) {
            const rate_pos = out_pos % RATE;
            if (rate_pos == 0 and out_pos > 0) {
                Sha3_256.keccakF(&s.state);
            }
            const block_off = (rate_pos / 8) * 8;
            var tmp: [8]u8 = undefined;
            u.writeU64Le(&tmp, s.state[rate_pos / 8]);
            var j: usize = 0;
            while (j < 8 and out_pos + j < output.len and rate_pos + j < RATE) : (j += 1) {
                output[out_pos + j] = tmp[j];
            }
            out_pos += j;
        }
    }
};

pub const Shake256 = struct {
    state: [25]u64,
    buf: [136]u8,
    buf_len: usize,

    const RATE: usize = 136;
    const ROUNDS: usize = 24;

    const RC = [24]u64{
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000880a, 0x000000008000000a, 0x0000000080008081, 0x8000000080008080,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008, 0x000000000000808b,
        0x000000008000000a, 0x0000000080008082, 0x8000000000000080, 0x8000000080000001,
        0x8000000080008008, 0x000000000000808a, 0x000000000000008b, 0x800000008000000a,
    };

    const ROTATIONS = [5][5]u6{
        .{ 0, 1, 62, 28, 27 },
        .{ 36, 44, 6, 55, 20 },
        .{ 3, 10, 43, 25, 39 },
        .{ 41, 45, 15, 21, 8 },
        .{ 18, 2, 61, 56, 14 },
    };

    pub fn init() Shake256 {
        var s = Shake256{
            .state = [_]u64{0} ** 25,
            .buf = undefined,
            .buf_len = 0,
        };
        u.zero(&s.buf);
        return s;
    }

    fn keccakF(state: *[25]u64) void {
        var r: usize = 0;
        while (r < ROUNDS) : (r += 1) {
            var c: [5]u64 = undefined;
            var i: usize = 0;
            while (i < 5) : (i += 1) {
                c[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
            }
            var d: [5]u64 = undefined;
            i = 0;
            while (i < 5) : (i += 1) {
                d[i] = c[(i + 4) % 5] ^ u.rotl64(c[(i + 1) % 5], 1);
            }
            var b: [25]u64 = undefined;
            i = 0;
            while (i < 25) : (i += 1) {
                state[i] ^= d[i % 5];
            }
            i = 0;
            while (i < 25) : (i += 1) {
                const x = i % 5;
                const y = i / 5;
                b[(2 * x + 3 * y) % 5 * 5 + x] = u.rotl64(state[i], ROTATIONS[y][x]);
            }
            i = 0;
            while (i < 25) : (i += 1) {
                const x = i % 5;
                const y = i / 5;
                state[i] = b[i] ^ (~b[(x + 1) % 5 + y * 5] & b[(x + 2) % 5 + y * 5]);
            }
            state[0] ^= RC[r];
        }
    }

    fn absorb(s: *Shake256, block: *const [RATE]u8) void {
        var i: usize = 0;
        while (i < RATE / 8) : (i += 1) {
            s.state[i] ^= u.readU64Le(block[i * 8 ..][0..8]);
        }
        keccakF(&s.state);
    }

    pub fn update(s: *Shake256, data: []const u8) void {
        var offset: usize = 0;
        if (s.buf_len > 0) {
            const take = RATE - s.buf_len;
            if (data.len < take) {
                u.copyBytes(s.buf[s.buf_len..], data);
                s.buf_len += data.len;
                return;
            }
            u.copyBytes(s.buf[s.buf_len..], data[0..take]);
            s.absorb(s.buf[0..RATE]);
            offset = take;
            s.buf_len = 0;
        }
        while (offset + RATE <= data.len) {
            s.absorb(data[offset..][0..RATE]);
            offset += RATE;
        }
        if (offset < data.len) {
            u.copyBytes(s.buf[s.buf_len..], data[offset..]);
            s.buf_len = data.len - offset;
        }
    }

    pub fn squeeze(s: *Shake256, output: []u8, output_len: usize) void {
        u.zero(s.buf[s.buf_len..]);
        s.buf[s.buf_len] = 0x1f;
        s.buf[RATE - 1] |= 0x80;
        var i: usize = 0;
        while (i < RATE / 8) : (i += 1) {
            s.state[i] ^= u.readU64Le(s.buf[i * 8 ..][0..8]);
        }
        keccakF(&s.state);
        var out_pos: usize = 0;
        while (out_pos < output_len) {
            const rate_pos = out_pos % RATE;
            if (rate_pos == 0 and out_pos > 0) {
                keccakF(&s.state);
            }
            var tmp: [8]u8 = undefined;
            u.writeU64Le(&tmp, s.state[rate_pos / 8]);
            var j: usize = 0;
            while (j < 8 and out_pos + j < output_len and rate_pos + j < RATE) : (j += 1) {
                if (out_pos + j < output.len) {
                    output[out_pos + j] = tmp[j];
                }
            }
            out_pos += j;
        }
    }
};

test "SHA3-256 empty" {
    const h = Sha3_256.hash("");
    const expected = [32]u8{
        0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66, 0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
        0x22, 0x65, 0x5b, 0xac, 0x87, 0x53, 0x57, 0x19, 0x01, 0x84, 0x18, 0xdb, 0xa2, 0x65, 0x6d, 0x25,
    };
    for (h, expected) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}

test "SHA3-256 abc" {
    const h = Sha3_256.hash("abc");
    const expected = [32]u8{
        0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xbe, 0xb2, 0x04, 0x41, 0x13, 0x1e, 0xe6, 0xf9, 0x33,
        0x2a, 0x3d, 0x78, 0x99, 0xdb, 0x7d, 0xe4, 0x6d, 0xad, 0x2b, 0x99, 0x1b, 0x80, 0xe2, 0x15, 0x9c,
    };
    for (h, expected) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}
