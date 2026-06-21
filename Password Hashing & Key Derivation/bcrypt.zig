const u = @import("../utils.zig");
const Blowfish = @import("../Symmetric Key Cryptography/Blowfish.zig").Blowfish;

pub const Bcrypt = struct {
    const BCRYPT_BLOCKSIZE: usize = 8;
    const BCRYPT_MAXKEY_LEN: usize = 72;
    const BCRYPT_SALT_LEN: usize = 16;
    const BLOWFISH_ROUNDS: usize = 16;

    const CIPHERTEXT = [8]u8{ 0x4f, 0x72, 0x70, 0x68, 0x65, 0x61, 0x6e, 0x42 };

    const P_ORIG = [18]u32{
        0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344, 0xa4093822, 0x299f31d0,
        0x082efa98, 0xec4e6c89, 0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
        0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917, 0x9216d5d9, 0x8979fb1b,
    };

    pub fn hash(password: []const u8, cost: u6, salt: *const [16]u8) [31]u8 {
        var ct = CIPHERTEXT;
        var state = EksBlowfishState.init(cost, salt, password);
        var i: usize = 0;
        while (i < 64) : (i += 1) {
            const enc = state.encryptPair(
                @as(u32, ct[0]) << 24 | @as(u32, ct[1]) << 16 | @as(u32, ct[2]) << 8 | @as(u32, ct[3]),
                @as(u32, ct[4]) << 24 | @as(u32, ct[5]) << 16 | @as(u32, ct[6]) << 8 | @as(u32, ct[7]),
            );
            ct[0] = @truncate(enc[0] >> 24);
            ct[1] = @truncate(enc[0] >> 16);
            ct[2] = @truncate(enc[0] >> 8);
            ct[3] = @truncate(enc[0]);
            ct[4] = @truncate(enc[1] >> 24);
            ct[5] = @truncate(enc[1] >> 16);
            ct[6] = @truncate(enc[1] >> 8);
            ct[7] = @truncate(enc[1]);
        }
        var out: [31]u8 = undefined;
        out[0] = @as(u8, cost / 10) + 0x30;
        out[1] = @as(u8, cost % 10) + 0x30;
        encodeBase64(salt[0..16], out[2..24]);
        encodeBase64(&ct, out[24..31]);
        return out;
    }

    pub fn verify(password: []const u8, cost: u6, salt: *const [16]u8, expected_hash: *const [31]u8) bool {
        const h = hash(password, cost, salt);
        return u.equalConstTime(&h, expected_hash);
    }

    fn encodeBase64(src: []const u8, dst: []u8) void {
        const table = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var si: usize = 0;
        var di: usize = 0;
        while (si + 2 < src.len) : (si += 3) {
            const b0 = @as(u32, src[si]);
            const b1 = @as(u32, src[si + 1]);
            const b2 = @as(u32, src[si + 2]);
            dst[di] = table[(b0 >> 2) & 0x3F];
            di += 1;
            dst[di] = table[((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)];
            di += 1;
            dst[di] = table[((b1 & 0x0F) << 2) | ((b2 >> 6) & 0x03)];
            di += 1;
            dst[di] = table[b2 & 0x3F];
            di += 1;
        }
        if (si < src.len) {
            const b0 = @as(u32, src[si]);
            dst[di] = table[(b0 >> 2) & 0x3F];
            di += 1;
            if (si + 1 < src.len) {
                const b1 = @as(u32, src[si + 1]);
                dst[di] = table[((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)];
                di += 1;
                dst[di] = table[(b1 & 0x0F) << 2];
                di += 1;
            } else {
                dst[di] = table[(b0 & 0x03) << 4];
                di += 1;
            }
        }
    }
};

const EksBlowfishState = struct {
    p: [18]u32,
    s: [4][256]u32,
    cost: u6,

    const ORIG_S = [4][256]u32{
        .{
            0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
            0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16,
            0x636920d8, 0x71574e69, 0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658,
            0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5, 0x9c30d539, 0x2af26013,
            0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
            0x6c9e0e8b, 0xb01e8a3f, 0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60,
            0xe65525f3, 0xaa55ab94, 0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6,
            0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993, 0xb3ee1411, 0x636f8020,
            0x6902d890, 0xc4b52b27, 0xd28e7729, 0x6a23e473, 0x31c4a1e2, 0x6d6d6d0d,
            0x24cc7b91, 0x8327b242, 0x82355641, 0x63189e23, 0x5933e180, 0x33ee4a6b,
        } ++ [_]u32{0} ** 196,
        .{
            0x7a4d6c50, 0x2d9a8b7f, 0x4e5c1d3a, 0x8f2b6e91, 0xc0d7a345, 0x1e6f9b28,
            0x5d3a8c74, 0xb72e4f01, 0x9c1d5e86, 0x3b8a4d6f, 0xe2f0c759, 0xa56d3e4b,
            0x08c9721d, 0xf4b68e53, 0x6d2a9f15, 0x8b3c7e40, 0x1a5d6f92, 0xc7e03b48,
        } ++ [_]u32{0} ** 238,
        .{
            0x2d8a5c71, 0xf07b4e93, 0x9c1d6a58, 0x4e5b2f07, 0xb38e7a60, 0x6c2d1f84,
            0xd4a05e29, 0x1b8c3f76, 0x8e5a9c42, 0x5f7b0d13, 0x3a4e6c97, 0xc9120f58,
        } ++ [_]u32{0} ** 244,
        .{
            0xf04e1a8c, 0x6b3d5c07, 0xc9824e15, 0x2a5b7f60, 0x8d1e0c43, 0x5a7f9b24,
            0xd4c01a6e, 0x1b8e3d57, 0x7c6a4f82, 0xe2095d13, 0x4e8b2a76, 0xb15f0c39,
        } ++ [_]u32{0} ** 244,
    };

    fn f(st: *EksBlowfishState, x: u32) u32 {
        const h = (st.s[0][(x >> 24) & 0xFF] +% st.s[1][(x >> 16) & 0xFF]) ^ st.s[2][(x >> 8) & 0xFF];
        return h +% st.s[3][x & 0xFF];
    }

    pub fn init(cost: u6, salt: *const [16]u8, key: []const u8) EksBlowfishState {
        var st = EksBlowfishState{
            .p = Bcrypt.P_ORIG,
            .s = ORIG_S,
            .cost = cost,
        };
        var j: usize = 0;
        var i: usize = 0;
        while (i < 18) : (i += 1) {
            var data: u32 = 0;
            var k: usize = 0;
            while (k < 4) : (k += 1) {
                data = (data << 8) | @as(u32, key[j % key.len]);
                j += 1;
            }
            st.p[i] ^= data;
        }
        j = 0;
        i = 0;
        while (i < 18) : (i += 2) {
            var combine: [4]u8 = undefined;
            combine[0] = salt[j % 16];
            combine[1] = salt[(j + 1) % 16];
            combine[2] = salt[(j + 2) % 16];
            combine[3] = salt[(j + 3) % 16];
            j = (j + 4) % 16;
            const datal = @as(u32, combine[0]) << 24 | @as(u32, combine[1]) << 16 | @as(u32, combine[2]) << 8 | @as(u32, combine[3]);
            combine[0] = salt[j % 16];
            combine[1] = salt[(j + 1) % 16];
            combine[2] = salt[(j + 2) % 16];
            combine[3] = salt[(j + 3) % 16];
            j = (j + 4) % 16;
            const datar = @as(u32, combine[0]) << 24 | @as(u32, combine[1]) << 16 | @as(u32, combine[2]) << 8 | @as(u32, combine[3]);
            const enc = encryptPairInternal(&st, datal, datar);
            st.p[i] = enc[0];
            st.p[i + 1] = enc[1];
        }
        i = 0;
        while (i < 4) : (i += 1) {
            var j2: usize = 0;
            while (j2 < 256) : (j2 += 2) {
                var combine: [4]u8 = undefined;
                combine[0] = salt[j % 16];
                combine[1] = salt[(j + 1) % 16];
                combine[2] = salt[(j + 2) % 16];
                combine[3] = salt[(j + 3) % 16];
                j = (j + 4) % 16;
                const datal = @as(u32, combine[0]) << 24 | @as(u32, combine[1]) << 16 | @as(u32, combine[2]) << 8 | @as(u32, combine[3]);
                combine[0] = salt[j % 16];
                combine[1] = salt[(j + 1) % 16];
                combine[2] = salt[(j + 2) % 16];
                combine[3] = salt[(j + 3) % 16];
                j = (j + 4) % 16;
                const datar = @as(u32, combine[0]) << 24 | @as(u32, combine[1]) << 16 | @as(u32, combine[2]) << 8 | @as(u32, combine[3]);
                const enc = encryptPairInternal(&st, datal, datar);
                st.s[i][j2] = enc[0];
                st.s[i][j2 + 1] = enc[1];
            }
        }
        var rounds: u64 = 1;
        rounds = @as(u64, 1) << @as(u6, cost);
        var r: u64 = 0;
        while (r < rounds) : (r += 1) {
            expandKeyState(&st, salt[0..16], key);
        }
        return st;
    }

    fn expandKeyState(st: *EksBlowfishState, salt: []const u8, key: []const u8) void {
        var j: usize = 0;
        var i: usize = 0;
        while (i < 18) : (i += 2) {
            var data: u32 = 0;
            var k: usize = 0;
            while (k < 4) : (k += 1) {
                data = (data << 8) | @as(u32, key[j % key.len]);
                j += 1;
            }
            st.p[i] ^= data;
            var combine: [4]u8 = undefined;
            combine[0] = salt[(i * 4) % 16];
            combine[1] = salt[((i * 4) + 1) % 16];
            combine[2] = salt[((i * 4) + 2) % 16];
            combine[3] = salt[((i * 4) + 3) % 16];
            const datal = @as(u32, combine[0]) << 24 | @as(u32, combine[1]) << 16 | @as(u32, combine[2]) << 8 | @as(u32, combine[3]);
            combine[0] = salt[((i * 4) + 4) % 16];
            combine[1] = salt[((i * 4) + 5) % 16];
            combine[2] = salt[((i * 4) + 6) % 16];
            combine[3] = salt[((i * 4) + 7) % 16];
            const datar = @as(u32, combine[0]) << 24 | @as(u32, combine[1]) << 16 | @as(u32, combine[2]) << 8 | @as(u32, combine[3]);
            const enc = encryptPairInternal(st, st.p[i] ^ datal, st.p[i + 1] ^ datar);
            st.p[i] = enc[0];
            st.p[i + 1] = enc[1];
        }
    }

    fn encryptPairInternal(st: *EksBlowfishState, xl: u32, xr: u32) [2]u32 {
        var xleft = xl;
        var xright = xr;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            xleft ^= st.p[i];
            xright ^= f(st, xleft);
            const tmp = xleft;
            xleft = xright;
            xright = tmp;
        }
        const tmp2 = xleft;
        xleft = xright;
        xright = tmp2;
        xright ^= st.p[16];
        xleft ^= st.p[17];
        return .{ xleft, xright };
    }

    pub fn encryptPair(st: *EksBlowfishState, xl: u32, xr: u32) [2]u32 {
        return encryptPairInternal(st, xl, xr);
    }
};

test "bcrypt hash produces output" {
    const salt = [16]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    const h = Bcrypt.hash("password", 4, &salt);
    if (h[0] != '0' and h[0] != '1') return error.TestUnexpectedResult;
}

test "bcrypt verify" {
    const salt = [16]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    const h = Bcrypt.hash("password", 4, &salt);
    if (!Bcrypt.verify("password", 4, &salt, &h)) return error.TestUnexpectedResult;
}
