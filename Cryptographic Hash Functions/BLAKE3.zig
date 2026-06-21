const u = @import("../utils.zig");

pub const Blake3 = struct {
    cv: [8]u32,
    chunk_counter: u64,
    buf: [64]u8,
    buf_len: usize,
    chunk_remaining: usize,
    key: [8]u32,
    is_keyed: bool,
    is_derive: bool,

    const IV = [8]u32{
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    };

    const CHUNK_LEN: usize = 1024;
    const BLOCK_LEN: usize = 64;

    const MSG_SCHEDULE = [7][16]u8{
        .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        .{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 },
        .{ 3, 4, 10, 12, 9, 7, 14, 1, 15, 5, 6, 8, 2, 0, 13, 11 },
        .{ 4, 8, 12, 0, 5, 2, 15, 10, 9, 1, 6, 14, 7, 3, 11, 13 },
        .{ 9, 0, 5, 7, 11, 12, 2, 4, 14, 15, 6, 8, 3, 13, 1, 10 },
        .{ 1, 5, 7, 11, 3, 9, 8, 6, 15, 2, 0, 14, 10, 12, 4, 13 },
        .{ 2, 6, 8, 14, 11, 1, 15, 3, 4, 10, 7, 13, 0, 5, 9, 12 },
    };

    const DOMAIN = enum(u32) {
        chunk = 0,
        parent = 1,
        root = 2,
        keyed = 3,
        derive_key = 4,
    };

    fn g(v: *[16]u32, a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) void {
        v[a] = v[a] +% v[b] +% x;
        v[d] = u.rotr32(v[d] ^ v[a], 16);
        v[c] = v[c] +% v[d];
        v[b] = u.rotr32(v[b] ^ v[c], 12);
        v[a] = v[a] +% v[b] +% y;
        v[d] = u.rotr32(v[d] ^ v[a], 8);
        v[c] = v[c] +% v[d];
        v[b] = u.rotr32(v[b] ^ v[c], 7);
    }

    fn roundFn(v: *[16]u32, m: *const [16]u32, sch: [16]u8) void {
        g(v, 0, 4, 8, 12, m[sch[0]], m[sch[1]]);
        g(v, 1, 5, 9, 13, m[sch[2]], m[sch[3]]);
        g(v, 2, 6, 10, 14, m[sch[4]], m[sch[5]]);
        g(v, 3, 7, 11, 15, m[sch[6]], m[sch[7]]);
        g(v, 0, 5, 10, 15, m[sch[8]], m[sch[9]]);
        g(v, 1, 6, 11, 12, m[sch[10]], m[sch[11]]);
        g(v, 2, 7, 8, 13, m[sch[12]], m[sch[13]]);
        g(v, 3, 4, 9, 14, m[sch[14]], m[sch[15]]);
    }

    pub fn compress(cv: [8]u32, block: *const [64]u8, counter: u64, flags: u32) [8]u32 {
        var m: [16]u32 = undefined;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            m[i] = u.readU32Le(block[i * 4 ..][0..4]);
        }
        var v: [16]u32 = undefined;
        i = 0;
        while (i < 8) : (i += 1) {
            v[i] = cv[i];
            v[i + 8] = IV[i];
        }
        v[8 + 4] ^= @truncate(counter);
        v[8 + 5] ^= @truncate(counter >> 32);
        v[8 + 6] ^= 0;
        v[8 + 7] ^= flags;
        var r: usize = 0;
        while (r < 7) : (r += 1) {
            roundFn(&v, &m, MSG_SCHEDULE[r]);
        }
        var out: [8]u32 = undefined;
        i = 0;
        while (i < 8) : (i += 1) {
            out[i] = v[i] ^ v[i + 8];
        }
        return out;
    }

    pub fn init() Blake3 {
        return Blake3{
            .cv = IV,
            .chunk_counter = 0,
            .buf = undefined,
            .buf_len = 0,
            .chunk_remaining = CHUNK_LEN,
            .key = IV,
            .is_keyed = false,
            .is_derive = false,
        };
    }

    pub fn initKey(key: *const [32]u8) Blake3 {
        var k: [8]u32 = undefined;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            k[i] = u.readU32Le(key[i * 4 ..][0..4]);
        }
        return Blake3{
            .cv = k,
            .chunk_counter = 0,
            .buf = undefined,
            .buf_len = 0,
            .chunk_remaining = CHUNK_LEN,
            .key = k,
            .is_keyed = true,
            .is_derive = false,
        };
    }

    pub fn update(s: *Blake3, data: []const u8) void {
        var offset: usize = 0;
        while (offset < data.len) {
            if (s.buf_len > 0) {
                const take = BLOCK_LEN - s.buf_len;
                const avail = data.len - offset;
                const n = if (take < avail) take else avail;
                u.copyBytes(s.buf[s.buf_len..], data[offset .. offset + n]);
                s.buf_len += n;
                offset += n;
                if (s.buf_len == BLOCK_LEN) {
                    const flags = @as(u32, @intFromEnum(Domain.chunk));
                    const block_arr: [64]u8 = s.buf[0..64].*;
                    s.cv = compress(s.cv, &block_arr, s.chunk_counter, flags);
                    s.buf_len = 0;
                    s.chunk_remaining -= BLOCK_LEN;
                    if (s.chunk_remaining == 0) {
                        s.chunk_counter +%= 1;
                        s.chunk_remaining = CHUNK_LEN;
                    }
                }
            } else if (s.chunk_remaining > 0 and offset + BLOCK_LEN <= data.len) {
                const flags = @as(u32, @intFromEnum(Domain.chunk));
                var num_blocks = (data.len - offset) / BLOCK_LEN;
                const chunk_blocks = s.chunk_remaining / BLOCK_LEN;
                if (num_blocks > chunk_blocks) num_blocks = chunk_blocks;
                var b: usize = 0;
                while (b < num_blocks) : (b += 1) {
                    var block: [64]u8 = undefined;
                    u.copyBytes(&block, data[offset .. offset + BLOCK_LEN]);
                    const is_last = (b == num_blocks - 1) and (s.chunk_remaining - num_blocks * BLOCK_LEN == 0);
                    var f = flags;
                    if (is_last) f |= 0x10;
                    s.cv = compress(s.cv, &block, s.chunk_counter, f);
                    offset += BLOCK_LEN;
                    s.chunk_remaining -= BLOCK_LEN;
                }
                if (s.chunk_remaining == 0) {
                    s.chunk_counter +%= 1;
                    s.chunk_remaining = CHUNK_LEN;
                }
            } else {
                const avail = data.len - offset;
                const n = if (avail < s.chunk_remaining) avail else s.chunk_remaining;
                const take = if (n > BLOCK_LEN) BLOCK_LEN else n;
                if (take > 0) {
                    u.copyBytes(s.buf[s.buf_len..], data[offset .. offset + take]);
                    s.buf_len += take;
                    offset += take;
                    s.chunk_remaining -= take;
                }
            }
        }
    }

    pub fn final(s: *Blake3) [32]u8 {
        var flags: u32 = @as(u32, @intFromEnum(Domain.root));
        if (s.is_keyed) flags = @as(u32, @intFromEnum(Domain.keyed));
        if (s.buf_len > 0) {
            flags |= @as(u32, @intFromEnum(Domain.chunk));
        }
        var block: [64]u8 = undefined;
        u.zero(&block);
        u.copyBytes(&block, s.buf[0..s.buf_len]);
        const out_cv = compress(s.cv, &block, s.chunk_counter, flags);
        var out: [32]u8 = undefined;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            u.writeU32Le(out[i * 4 ..][0..4], out_cv[i]);
        }
        return out;
    }

    pub fn hash(data: []const u8) [32]u8 {
        var s = Blake3.init();
        s.update(data);
        return s.final();
    }
};

test "BLAKE3 empty" {
    const h = Blake3.hash("");
    const expected = [32]u8{
        0xaf, 0x13, 0x49, 0xe8, 0x4d, 0x6f, 0x5d, 0xf0, 0x27, 0x6c, 0x74, 0xaf, 0xb5, 0x95, 0x5b, 0x40,
        0x3e, 0x6b, 0x9c, 0xa0, 0xd2, 0xc4, 0xe8, 0x1b, 0x3c, 0xa3, 0x76, 0xf7, 0x5f, 0x46, 0x3a, 0x10,
    };
    for (h, expected) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}

test "BLAKE3 abc" {
    const h = Blake3.hash("abc");
    const expected = [32]u8{
        0x64, 0x37, 0x43, 0x9a, 0xeb, 0x43, 0x6d, 0x9a, 0x05, 0xa9, 0x6b, 0xd1, 0x9c, 0x6a, 0x7b, 0x47,
        0xc8, 0x6d, 0x86, 0x44, 0x1e, 0x6a, 0x4e, 0x61, 0x97, 0x96, 0xec, 0xf0, 0x43, 0x14, 0x8f, 0xf5,
    };
    for (h, expected) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}
