const u = @import("../utils.zig");
const Threefish256 = struct {
    const WORDS = 4;
    const ROUNDS = 72;

    k: [WORDS + 1]u64,
    tweak: [2]u64,
    s: [4]u64,

    const C240 = 0x1BD11BDAA9FC1A22;

    fn rotl(x: u64, n: u32) u64 { return (x << n) | (x >> (64 - n)); }
    fn rotr(x: u64, n: u32) u64 { return (x >> n) | (x << (64 - n)); }

    pub fn init(key: *const [32]u8, tweak: *const [16]u8) Threefish256 {
        var tf = Threefish256{
            .k = undefined,
            .tweak = .{ u.readU64Le(tweak[0..8]), u.readU64Le(tweak[8..16]) },
            .s = undefined,
        };
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            tf.k[i] = u.readU64Le(key[i * 8 ..][0..8]);
        }
        tf.k[4] = C240;
        i = 0;
        while (i < 4) : (i += 1) {
            tf.k[4] ^= tf.k[i];
        }
        return tf;
    }

    fn mix(s: *Threefish256, d: usize, i: usize, j: usize) void {
        const x0 = s.s[i];
        const x1 = s.s[j];
        s.s[i] = x0 + x1;
        s.s[j] = s.rotl(x1, if (d % 2 == 0) 14 else 16) ^ s.s[i];
    }

    fn permute(s: *Threefish256, r: usize) void {
        if (r % 2 == 0) {
            s.mix(r, 0, 1);
            s.mix(r, 2, 3);
        } else {
            s.mix(r, 0, 3);
            s.mix(r, 2, 1);
        }
    }

    fn subkey(s: *Threefish256, r: usize) void {
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            s.s[i] += s.k[(r + i) % 5];
        }
        s.s[0] += s.tweak[r % 3];
        s.s[1] += s.tweak[(r + 1) % 3];
        s.s[2] += s.k[(r + 2) % 5];
        s.s[3] += s.k[(r + 3) % 5];
    }

    pub fn encrypt(s: *Threefish256, plaintext: *const [32]u8) [32]u8 {
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            s.s[i] = u.readU64Le(plaintext[i * 8 ..][0..8]);
        }
        s.subkey(0);
        var r: usize = 1;
        while (r <= ROUNDS) : (r += 1) {
            s.permute(r);
            if (r % 4 == 0) s.subkey(r / 4);
        }
        var out: [32]u8 = undefined;
        i = 0;
        while (i < 4) : (i += 1) {
            u.writeU64Le(out[i * 8 ..][0..8], s.s[i]);
        }
        return out;
    }
};

pub const Skein256 = struct {
    state: [4]u64,
    buffer: [32]u8,
    buffer_len: usize,
    total_len: u64,
    tweak: [2]u64,
    first: bool,

    pub fn init() Skein256 {
        return Skein256{
            .state = .{ 0, 0, 0, 0 },
            .buffer = undefined,
            .buffer_len = 0,
            .total_len = 0,
            .tweak = .{ 0, 0 },
            .first = true,
        };
    }

    fn process(s: *Skein256, block: *const [32]u8, is_final: bool) void {
        s.tweak[0] += 32;
        if (s.tweak[0] < 32) s.tweak[1] += 1;
        if (s.first) {
            s.tweak[1] |= 0x1 << 62;
            s.first = false;
        }
        if (is_final) {
            s.tweak[1] |= 0x1 << 63;
        }
        var tf = Threefish256.init(&s.state, &s.tweak);
        tf.encrypt(block);
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            s.state[i] ^= tf.s[i];
        }
    }

    pub fn update(s: *Skein256, data: []const u8) void {
        var offset: usize = 0;
        if (s.buffer_len > 0) {
            const take = 32 - s.buffer_len;
            if (data.len < take) {
                u.copyBytes(s.buffer[s.buffer_len..], data);
                s.buffer_len += data.len;
                return;
            }
            u.copyBytes(s.buffer[s.buffer_len..], data[0..take]);
            s.process(s.buffer[0..32], false);
            s.total_len += 32;
            offset += take;
            s.buffer_len = 0;
        }
        while (offset + 32 <= data.len) {
            s.process(data[offset..][0..32], false);
            s.total_len += 32;
            offset += 32;
        }
        if (offset < data.len) {
            u.copyBytes(s.buffer[s.buffer_len..], data[offset..]);
            s.buffer_len += data.len - offset;
        }
    }

    pub fn final(s: *Skein256) [32]u8 {
        var pad: [32]u8 = undefined;
        u.zero(&pad);
        if (s.buffer_len > 0) {
            u.copyBytes(&pad, s.buffer[0..s.buffer_len]);
        }
        pad[s.buffer_len] = 0x80;
        s.process(&pad, s.buffer_len < 31);
        while (s.buffer_len != 0) {
            u.zero(&pad);
            s.process(&pad, true);
        }
        var out: [32]u8 = undefined;
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            u.writeU64Le(out[i * 8 ..][0..8], s.state[i]);
        }
        return out;
    }

    pub fn hash(data: []const u8) [32]u8 {
        var s = Skein256.init();
        s.update(data);
        return s.final();
    }
};

pub const Skein512 = struct {
    state: [8]u64,
    buffer: [64]u8,
    buffer_len: usize,
    total_len: u64,
    tweak: [2]u64,
    first: bool,

    pub fn init() Skein512 {
        return Skein512{
            .state = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
            .buffer = undefined,
            .buffer_len = 0,
            .total_len = 0,
            .tweak = .{ 0, 0 },
            .first = true,
        };
    }

    pub fn hash(data: []const u8) [64]u8 {
        _ = data;
        var out: [64]u8 = undefined;
        return out;
    }
};

test "Skein-256 empty" {
    const h = Skein256.hash("");
    _ = h;
}

test "Skein-256 abc" {
    const h = Skein256.hash("abc");
    _ = h;
}

test "Skein-512 empty" {
    const h = Skein512.hash("");
    _ = h;
}