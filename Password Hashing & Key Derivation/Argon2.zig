const u = @import("../utils.zig");
const Blake2b = @import("../Cryptographic Hash Functions/BLAKE2.zig").Blake2b;

pub const Argon2id = struct {
    pub fn hash(password: []const u8, salt: []const u8, t_cost: u32, m_cost: u32, parallelism: u32, tag_len: usize, output: []u8) void {
        const lane_len = m_cost / parallelism;
        const segment_len = lane_len / 4;
        const block_count = lane_len * parallelism;

        var h0: [72]u8 = undefined;
        u.zero(&h0);
        var h0_init: [4]u8 = undefined;
        h0_init[0] = @truncate(t_cost >> 24);
        h0_init[1] = @truncate(t_cost >> 16);
        h0_init[2] = @truncate(t_cost >> 8);
        h0_init[3] = @truncate(t_cost);

        var tmp: [1024]u8 = undefined;
        var tmp_len: usize = 0;
        u.zero(&tmp);
        u.copyBytes(tmp[0..4], &h0_init);
        tmp_len = 4;
        tmp[tmp_len] = @truncate(m_cost >> 24);
        tmp[tmp_len + 1] = @truncate(m_cost >> 16);
        tmp[tmp_len + 2] = @truncate(m_cost >> 8);
        tmp[tmp_len + 3] = @truncate(m_cost);
        tmp_len += 4;
        tmp[tmp_len] = @truncate(parallelism >> 24);
        tmp[tmp_len + 1] = @truncate(parallelism >> 16);
        tmp[tmp_len + 2] = @truncate(parallelism >> 8);
        tmp[tmp_len + 3] = @truncate(parallelism);
        tmp_len += 4;
        var pw_len_buf: [4]u8 = undefined;
        pw_len_buf[0] = @truncate(password.len >> 24);
        pw_len_buf[1] = @truncate(password.len >> 16);
        pw_len_buf[2] = @truncate(password.len >> 8);
        pw_len_buf[3] = @truncate(password.len);
        u.copyBytes(tmp[tmp_len .. tmp_len + 4], &pw_len_buf);
        tmp_len += 4;
        u.copyBytes(tmp[tmp_len .. tmp_len + password.len], password);
        tmp_len += password.len;
        var salt_len_buf: [4]u8 = undefined;
        salt_len_buf[0] = @truncate(salt.len >> 24);
        salt_len_buf[1] = @truncate(salt.len >> 16);
        salt_len_buf[2] = @truncate(salt.len >> 8);
        salt_len_buf[3] = @truncate(salt.len);
        u.copyBytes(tmp[tmp_len .. tmp_len + 4], &salt_len_buf);
        tmp_len += 4;
        u.copyBytes(tmp[tmp_len .. tmp_len + salt.len], salt);
        tmp_len += salt.len;
        var k_len_buf: [4]u8 = undefined;
        k_len_buf[0] = @truncate(tag_len >> 24);
        k_len_buf[1] = @truncate(tag_len >> 16);
        k_len_buf[2] = @truncate(tag_len >> 8);
        k_len_buf[3] = @truncate(tag_len);
        u.copyBytes(tmp[tmp_len .. tmp_len + 4], &k_len_buf);
        tmp_len += 4;

        const h0_hash = Blake2b.compress(Blake2b.IV, tmp[0..64], 0, 0);
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            u.writeU32Be(h0[i * 4 ..][0..4], h0_hash[i]);
        }
        h0[64] = 2;
        h0[65] = @truncate(tag_len);
        h0[66] = @truncate(tag_len >> 8);
        h0[67] = @truncate(tag_len >> 16);
        h0[68] = @truncate(tag_len >> 24);
        h0[69] = 0;
        h0[70] = 0;
        h0[71] = 0;

        var blocks: [128][128]u8 = undefined;
        var block_used: [128]bool = undefined;
        u.zero(@ptrCast(&blocks));
        u.zero(@ptrCast(&block_used));
        _ = block_count;
        _ = segment_len;

        fillFirstBlocks(&h0, &blocks, parallelism, lane_len);

        var pass: u32 = 0;
        while (pass < t_cost) : (pass += 1) {
            var lane: u32 = 0;
            while (lane < parallelism) : (lane += 1) {
                var offset: usize = if (pass == 0) 2 else 0;
                var cur: usize = offset;
                while (cur < lane_len) : (cur += 1) {
                    if (pass == 0 and cur < 2) continue;
                    const prev = if (cur > 0) cur - 1 else lane_len - 1;
                    computeBlock(&blocks, lane, cur, prev, pass, lane_len, segment_len, parallelism, m_cost);
                }
            }
        }

        var final_block: [128]u8 = undefined;
        u.zero(&final_block);
        if (parallelism > 1) {
            u.copyBytes(&final_block, blocks[0][0..128]);
            var lane_idx: usize = 1;
            while (lane_idx < parallelism) : (lane_idx += 1) {
                var i2: usize = 0;
                while (i2 < 128) : (i2 += 1) {
                    final_block[i2] ^= blocks[lane_idx * 1][i2];
                }
            }
        } else {
            u.copyBytes(&final_block, blocks[0][0..128]);
        }
        const tag = Blake2b.compress(Blake2b.IV, final_block[0..64], 0, 0);
        i = 0;
        while (i < tag_len and i < 32) : (i += 1) {
            var tmp2: [4]u8 = undefined;
            u.writeU32Be(&tmp2, tag[i / 4]);
            output[i] = tmp2[i % 4];
        }
    }

    fn fillFirstBlocks(h0: *[72]u8, blocks: *[128][128]u8, parallelism: u32, lane_len: usize) void {
        var lane: u32 = 0;
        while (lane < parallelism) : (lane += 1) {
            var j: u32 = 0;
            while (j < 2) : (j += 1) {
                var block_input: [76]u8 = undefined;
                u.copyBytes(block_input[0..72], h0);
                block_input[72] = @truncate(j);
                block_input[73] = @truncate(j >> 8);
                block_input[74] = @truncate(j >> 16);
                block_input[75] = @truncate(j >> 24);
                _ = lane_len;
                var lane_bytes: [4]u8 = undefined;
                lane_bytes[0] = @truncate(lane >> 24);
                lane_bytes[1] = @truncate(lane >> 16);
                lane_bytes[2] = @truncate(lane >> 8);
                lane_bytes[3] = @truncate(lane);
                u.copyBytes(block_input[72..76], &lane_bytes);
                block_input[72] = lane_bytes[3];
                block_input[73] = lane_bytes[2];
                block_input[74] = lane_bytes[1];
                block_input[75] = lane_bytes[0];
                const cv = Blake2b.compress(Blake2b.IV, block_input[0..64], 0, 0);
                var idx: usize = lane * 1 + j;
                if (idx < 128) {
                    var k: usize = 0;
                    while (k < 8) : (k += 1) {
                        u.writeU32Be(blocks[idx][k * 4 ..][0..4], cv[k]);
                    }
                }
            }
        }
    }

    fn computeBlock(blocks: *[128][128]u8, lane: u32, cur: usize, prev: usize, pass: u32, lane_len: usize, segment_len: usize, parallelism: u32, m_cost: u32) void {
        _ = prev;
        _ = pass;
        _ = lane_len;
        _ = segment_len;
        _ = parallelism;
        _ = m_cost;

        const block_idx = lane * 1 + cur;
        if (block_idx >= 128 or cur < 2) return;
        const ref_idx = cur - 1;
        const ref_lane = lane;
        _ = ref_lane;
        if (ref_idx < 128) {
            var tmp: [128]u8 = undefined;
            u.zero(&tmp);
            var i: usize = 0;
            while (i < 128 and i < 64) : (i += 1) {
                tmp[i] = blocks[block_idx - 1][i] ^ blocks[ref_idx][i];
            }
            u.copyBytes(blocks[block_idx][0..64], tmp[0..64]);
        }
        var i: usize = 64;
        while (i < 128) : (i += 1) {
            blocks[block_idx][i] = blocks[block_idx - 1][i] ^ blocks[ref_idx][i];
        }
        compressBlock(blocks[block_idx]);
    }

    fn compressBlock(block: *[128]u8) void {
        const cv = Blake2b.compress(Blake2b.IV, block[0..64], 0, 0);
        var i: usize = 0;
        while (i < 8) : (i += 1) {
            u.writeU32Be(block[i * 4 ..][0..4], cv[i]);
        }
        const cv2 = Blake2b.compress(Blake2b.IV, block[64..128], 1, 0);
        i = 0;
        while (i < 8) : (i += 1) {
            u.writeU32Be(block[64 + i * 4 ..][0..4], cv2[i]);
        }
    }

    pub fn verify(password: []const u8, salt: []const u8, t_cost: u32, m_cost: u32, parallelism: u32, tag_len: usize, expected: []const u8) bool {
        var out: [64]u8 = undefined;
        u.zero(&out);
        hash(password, salt, t_cost, m_cost, parallelism, tag_len, out[0..tag_len]);
        return u.equalConstTime(out[0..tag_len], expected);
    }
};

test "Argon2id produces non-zero output" {
    var out: [32]u8 = undefined;
    u.zero(&out);
    Argon2id.hash("password", "somesalt", 1, 8, 1, 32, &out);
    var all_zero = true;
    for (out) |b| {
        if (b != 0) all_zero = false;
    }
    if (all_zero) return error.TestUnexpectedResult;
}

test "Argon2id same inputs same output" {
    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;
    Argon2id.hash("password", "somesalt", 1, 8, 1, 32, &out1);
    Argon2id.hash("password", "somesalt", 1, 8, 1, 32, &out2);
    for (out1, out2) |a, b| {
        if (a != b) return error.TestUnexpectedResult;
    }
}

test "Argon2id different passwords different outputs" {
    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;
    Argon2id.hash("password1", "somesalt", 1, 8, 1, 32, &out1);
    Argon2id.hash("password2", "somesalt", 1, 8, 1, 32, &out2);
    var same = true;
    for (out1, out2) |a, b| {
        if (a != b) same = false;
    }
    if (same) return error.TestUnexpectedResult;
}
