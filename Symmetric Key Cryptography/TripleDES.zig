const u = @import("../utils.zig");

const Des = struct {
    subkeys: [16]u64,

    const IP = [64]u8{
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    };

    const FP = [64]u8{
        39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24,
    };

    const EXP = [48]u8{
        31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10,
        11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20,
        21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 30,
    };

    const P = [32]u8{
        15, 6, 19, 20, 28, 11, 27, 16, 0, 14, 22, 25, 4, 17, 30, 9,
        1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24,
    };

    const SBOXES = [8][64]u8{
        .{
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
            0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
            4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
        },
        .{
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
            3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
            0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
            13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
        },
        .{
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
            13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
            13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
            1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
        },
        .{
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
            13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
            10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 8, 2, 12,
            3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
        },
        .{
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
            14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
            4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
            11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
        },
        .{
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
            10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
            9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
            4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
        },
        .{
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
            13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
            1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
            6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
        },
        .{
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
            13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
            1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        },
    };

    const PC1 = [56]u8{
        56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17,
        9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35,
        62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21,
        13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3,
    };

    const PC2 = [48]u8{
        13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
        22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
        40, 51, 30, 36, 46, 54, 29, 42, 44, 49, 37, 33,
        43, 52, 48, 38, 55, 47, 56, 34, 53, 32, 41, 31,
    };

    const SHIFTS = [16]u8{ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

    fn permute(input: u64, table: []const u8, out_bits: usize) u64 {
        var output: u64 = 0;
        var i: usize = 0;
        while (i < out_bits) : (i += 1) {
            output <<= 1;
            output |= (input >> (63 - table[i])) & 1;
        }
        return output;
    }

    pub fn init(key: *const [8]u8) Des {
        var d = Des{ .subkeys = undefined };
        const key64: u64 = @as(u64, key[0]) << 56 | @as(u64, key[1]) << 48 | @as(u64, key[2]) << 40 | @as(u64, key[3]) << 32 | @as(u64, key[4]) << 24 | @as(u64, key[5]) << 16 | @as(u64, key[6]) << 8 | @as(u64, key[7]);
        const perm = permute(key64, &PC1, 56);
        var left: u32 = @truncate(perm >> 28);
        var right: u32 = @truncate(perm & 0x0FFFFFFF);
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            const shift = SHIFTS[i];
            left = ((left << @as(u5, @truncate(shift))) | (left >> @as(u5, @truncate(28 - shift)))) & 0x0FFFFFFF;
            right = ((right << @as(u5, @truncate(shift))) | (right >> @as(u5, @truncate(28 - shift)))) & 0x0FFFFFFF;
            const combined = (@as(u64, left) << 28) | @as(u64, right);
            d.subkeys[i] = permute(combined, &PC2, 48);
        }
        return d;
    }

    fn feistel(d: *Des, right: u32, round_idx: usize) u32 {
        const expanded = permute(@as(u64, right), &EXP, 48);
        const xored = expanded ^ d.subkeys[round_idx];
        var output: u32 = 0;
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            const six_bits: u6 = @truncate(xored >> (42 - i * 6));
            const row = @as(u8, ((six_bits >> 5) << 1) | (six_bits & 1));
            const col = @as(u8, (six_bits >> 1) & 0xF);
            output = (output << 4) | SBOXES[i][@as(usize, row) * 16 + col];
        }
        return @truncate(permute(@as(u64, output), &P, 32));
    }

    pub fn encryptBlock(d: *Des, block: *const [8]u8) [8]u8 {
        const block64: u64 = @as(u64, block[0]) << 56 | @as(u64, block[1]) << 48 | @as(u64, block[2]) << 40 | @as(u64, block[3]) << 32 | @as(u64, block[4]) << 24 | @as(u64, block[5]) << 16 | @as(u64, block[6]) << 8 | @as(u64, block[7]);
        const perm = permute(block64, &IP, 64);
        var left: u32 = @truncate(perm >> 32);
        var right: u32 = @truncate(perm & 0xFFFFFFFF);
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            const new_right = left ^ d.feistel(right, i);
            left = right;
            right = new_right;
        }
        const pre_fp = (@as(u64, right) << 32) | @as(u64, left);
        const result = permute(pre_fp, &FP, 64);
        var out: [8]u8 = undefined;
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            out[j] = @truncate(result >> (56 - j * 8));
        }
        return out;
    }

    pub fn decryptBlock(d: *Des, block: *const [8]u8) [8]u8 {
        const block64: u64 = @as(u64, block[0]) << 56 | @as(u64, block[1]) << 48 | @as(u64, block[2]) << 40 | @as(u64, block[3]) << 32 | @as(u64, block[4]) << 24 | @as(u64, block[5]) << 16 | @as(u64, block[6]) << 8 | @as(u64, block[7]);
        const perm = permute(block64, &IP, 64);
        var left: u32 = @truncate(perm >> 32);
        var right: u32 = @truncate(perm & 0xFFFFFFFF);
        var i: usize = 16;
        while (i > 0) : (i -= 1) {
            const new_right = left ^ d.feistel(right, i - 1);
            left = right;
            right = new_right;
        }
        const pre_fp = (@as(u64, right) << 32) | @as(u64, left);
        const result = permute(pre_fp, &FP, 64);
        var out: [8]u8 = undefined;
        var j: usize = 0;
        while (j < 8) : (j += 1) {
            out[j] = @truncate(result >> (56 - j * 8));
        }
        return out;
    }
};

pub const TripleDes = struct {
    des1: Des,
    des2: Des,
    des3: Des,

    pub fn init(k1: *const [8]u8, k2: *const [8]u8, k3: *const [8]u8) TripleDes {
        return TripleDes{
            .des1 = Des.init(k1),
            .des2 = Des.init(k2),
            .des3 = Des.init(k3),
        };
    }

    pub fn initDouble(key: *const [16]u8) TripleDes {
        return TripleDes{
            .des1 = Des.init(key[0..8]),
            .des2 = Des.init(key[8..16]),
            .des3 = Des.init(key[0..8]),
        };
    }

    pub fn encrypt(td: *TripleDes, block: *const [8]u8) [8]u8 {
        const step1 = td.des1.encryptBlock(block);
        const step2 = td.des2.decryptBlock(&step1);
        return td.des3.encryptBlock(&step2);
    }

    pub fn decrypt(td: *TripleDes, block: *const [8]u8) [8]u8 {
        const step1 = td.des3.decryptBlock(block);
        const step2 = td.des2.encryptBlock(&step1);
        return td.des1.decryptBlock(&step2);
    }
};

test "DES encrypt/decrypt roundtrip" {
    const key = [8]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const pt = [8]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    var d = Des.init(&key);
    const ct = d.encryptBlock(&pt);
    const dt = d.decryptBlock(&ct);
    for (dt, pt) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}

test "Triple DES encrypt/decrypt roundtrip" {
    const k1 = [8]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const k2 = [8]u8{ 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01 };
    const k3 = [8]u8{ 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23 };
    const pt = [8]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    var td = TripleDes.init(&k1, &k2, &k3);
    const ct = td.encrypt(&pt);
    const dt = td.decrypt(&ct);
    for (dt, pt) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}

test "Triple DES NIST known answer" {
    const k1 = [8]u8{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
    const k2 = [8]u8{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
    const k3 = [8]u8{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
    const pt = [8]u8{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    var td = TripleDes.init(&k1, &k2, &k3);
    const ct = td.encrypt(&pt);
    const dt = td.decrypt(&ct);
    for (dt, pt) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}
