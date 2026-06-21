const u = @import("../utils.zig");

pub const ChaCha20 = struct {
    state: [16]u32,
    block_pos: usize,

    const CONSTANTS = [4]u32{ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

    fn quarterRound(state: *[16]u32, a: usize, b: usize, c: usize, d: usize) void {
        state[a] +%= state[b];
        state[d] ^= state[a];
        state[d] = u.rotl32(state[d], 16);
        state[c] +%= state[d];
        state[b] ^= state[c];
        state[b] = u.rotl32(state[b], 12);
        state[a] +%= state[b];
        state[d] ^= state[a];
        state[d] = u.rotl32(state[d], 8);
        state[c] +%= state[d];
        state[b] ^= state[c];
        state[b] = u.rotl32(state[b], 7);
    }

    pub fn init(key: *const [32]u8, nonce: *const [12]u8, counter: u32) ChaCha20 {
        var s = ChaCha20{ .state = undefined, .block_pos = 64 };
        s.state[0] = CONSTANTS[0];
        s.state[1] = CONSTANTS[1];
        s.state[2] = CONSTANTS[2];
        s.state[3] = CONSTANTS[3];
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            s.state[4 + i] = u.readU32Le(key[i * 4 ..][0..4]);
        }
        s.state[12] = counter;
        s.state[13] = u.readU32Le(nonce[0..4]);
        s.state[14] = u.readU32Le(nonce[4..8]);
        s.state[15] = u.readU32Le(nonce[8..12]);
        return s;
    }

    pub fn initIetf(key: *const [32]u8, nonce: *const [12]u8, counter: u32) ChaCha20 {
        return init(key, nonce, counter);
    }

    fn generateBlock(s: *ChaCha20) [64]u8 {
        var working: [16]u32 = s.state;
        var i: usize = 0;
        while (i < 10) : (i += 1) {
            quarterRound(&working, 0, 4, 8, 12);
            quarterRound(&working, 1, 5, 9, 13);
            quarterRound(&working, 2, 6, 10, 14);
            quarterRound(&working, 3, 7, 11, 15);
            quarterRound(&working, 0, 5, 10, 15);
            quarterRound(&working, 1, 6, 11, 12);
            quarterRound(&working, 2, 7, 8, 13);
            quarterRound(&working, 3, 4, 9, 14);
        }
        var i2: usize = 0;
        while (i2 < 16) : (i2 += 1) {
            working[i2] +%= s.state[i2];
        }
        var out: [64]u8 = undefined;
        i2 = 0;
        while (i2 < 16) : (i2 += 1) {
            u.writeU32Le(out[i2 * 4 ..][0..4], working[i2]);
        }
        s.state[12] +%= 1;
        return out;
    }

    pub fn encrypt(s: *ChaCha20, plaintext: []u8) void {
        var offset: usize = 0;
        var block: [64]u8 = undefined;
        while (offset < plaintext.len) {
            if (s.block_pos >= 64) {
                block = s.generateBlock();
                s.block_pos = 0;
            }
            const remaining = 64 - s.block_pos;
            const take = if (remaining < plaintext.len - offset) remaining else plaintext.len - offset;
            u.xorBytes(plaintext[offset .. offset + take], plaintext[offset .. offset + take], block[s.block_pos .. s.block_pos + take]);
            s.block_pos += take;
            offset += take;
        }
    }

    pub fn decrypt(s: *ChaCha20, ciphertext: []u8) void {
        s.encrypt(ciphertext);
    }

    pub fn keystream(s: *ChaCha20, output: []u8) void {
        var offset: usize = 0;
        while (offset < output.len) {
            const block = s.generateBlock();
            const take = if (64 < output.len - offset) @as(usize, 64) else output.len - offset;
            u.copyBytes(output[offset .. offset + take], block[0..take]);
            offset += take;
        }
    }
};

pub const HChaCha20 = struct {
    pub fn derive(key: *const [32]u8, nonce: *const [16]u8) [32]u8 {
        var state: [16]u32 = undefined;
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            state[4 + i] = u.readU32Le(key[i * 4 ..][0..4]);
        }
        state[12] = u.readU32Le(nonce[0..4]);
        state[13] = u.readU32Le(nonce[4..8]);
        state[14] = u.readU32Le(nonce[8..12]);
        state[15] = u.readU32Le(nonce[12..16]);
        var r: usize = 0;
        while (r < 10) : (r += 1) {
            ChaCha20.quarterRound(&state, 0, 4, 8, 12);
            ChaCha20.quarterRound(&state, 1, 5, 9, 13);
            ChaCha20.quarterRound(&state, 2, 6, 10, 14);
            ChaCha20.quarterRound(&state, 3, 7, 11, 15);
            ChaCha20.quarterRound(&state, 0, 5, 10, 15);
            ChaCha20.quarterRound(&state, 1, 6, 11, 12);
            ChaCha20.quarterRound(&state, 2, 7, 8, 13);
            ChaCha20.quarterRound(&state, 3, 4, 9, 14);
        }
        var out: [32]u8 = undefined;
        u.writeU32Le(out[0..4], state[0]);
        u.writeU32Le(out[4..8], state[1]);
        u.writeU32Le(out[8..12], state[2]);
        u.writeU32Le(out[12..16], state[3]);
        u.writeU32Le(out[16..20], state[12]);
        u.writeU32Le(out[20..24], state[13]);
        u.writeU32Le(out[24..28], state[14]);
        u.writeU32Le(out[28..32], state[15]);
        return out;
    }
};

test "ChaCha20 quarter round" {
    var state: [16]u32 = [_]u64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} ** 1;
    state[0] = 0x11111111;
    state[1] = 0x01020304;
    state[2] = 0x9b8d6f43;
    state[3] = 0x01234567;
    ChaCha20.quarterRound(&state, 0, 1, 2, 3);
}

test "ChaCha20 encrypt/decrypt roundtrip" {
    const key = [_]u8{0x00} ** 32;
    const nonce = [_]u8{0x00} ** 12;
    var cipher = ChaCha20.init(&key, &nonce, 0);
    var msg = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const orig = msg;
    cipher.encrypt(&msg);
    var cipher2 = ChaCha20.init(&key, &nonce, 0);
    cipher2.decrypt(&msg);
    for (msg, orig) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}

test "ChaCha20 RFC 8432 test vector" {
    const key = [32]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const nonce = [12]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };
    var c = ChaCha20.init(&key, &nonce, 1);
    var msg = [_]u8{
        0x4c, 0x61, 0x64, 0x79, 0x20, 0x4f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x4c, 0x61, 0x6b, 0x65,
    };
    c.encrypt(&msg);
    const expected = [16]u8{
        0xd2, 0x78, 0x51, 0xdb, 0x7c, 0x48, 0xb1, 0x27,
        0x9d, 0x7a, 0x6e, 0x5a, 0xb8, 0x5b, 0x25, 0x3a,
    };
    for (msg, expected) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}
