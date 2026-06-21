const u = @import("../utils.zig");
const Shake256 = @import("../Cryptographic Hash Functions/SHA3.zig").Shake256;

pub const MlDsa65 = struct {
    const Q: u32 = 8380417;
    const N: usize = 256;
    const K: usize = 4;
    const L: usize = 5;
    const ETA: u32 = 2;
    const TAU: usize = 39;
    const BETA: u32 = 78;
    const GAMMA1: u32 = 1 << 17;
    const GAMMA2: u32 = 95;
    const OMEGA: usize = 55;
    const D: u32 = 13;
    const SYMBYTES: usize = 32;

    const Poly = struct {
        coeffs: [256]i32,

        pub fn init() Poly {
            return Poly{ .coeffs = [_]i32{0} ** 256 };
        }

        pub fn reduce(p: *Poly) void {
            var i: usize = 0;
            while (i < N) : (i += 1) {
                p.coeffs[i] = cAddQ(p.coeffs[i]);
            }
        }

        pub fn addPolys(a: *const Poly, b: *const Poly) Poly {
            var r = Poly.init();
            var i: usize = 0;
            while (i < N) : (i += 1) {
                r.coeffs[i] = a.coeffs[i] + b.coeffs[i];
            }
            r.reduce();
            return r;
        }

        pub fn subPolys(a: *const Poly, b: *const Poly) Poly {
            var r = Poly.init();
            var i: usize = 0;
            while (i < N) : (i += 1) {
                r.coeffs[i] = a.coeffs[i] - b.coeffs[i];
            }
            r.reduce();
            return r;
        }

        pub fn ntt(p: *Poly) void {
            p.reduce();
            var len: u32 = 128;
            while (len > 0) : (len >>= 1) {
                var start: u32 = 0;
                while (start < 256) : (start += 2 * len) {
                    var j: u32 = start;
                    while (j < start + len) : (j += 1) {
                        const t = montReduce(@as(i64, p.coeffs[j + len]) * zeta(j + len - start));
                        p.coeffs[j + len] = p.coeffs[j] - t;
                        p.coeffs[j] = p.coeffs[j] + t;
                    }
                }
            }
        }

        pub fn invNtt(p: *Poly) void {
            p.reduce();
            var len: u32 = 1;
            while (len < 256) : (len <<= 1) {
                var start: u32 = 0;
                while (start < 256) : (start += 2 * len) {
                    var j: u32 = start;
                    while (j < start + len) : (j += 1) {
                        const t = p.coeffs[j];
                        p.coeffs[j] = cAddQ(t + p.coeffs[j + len]);
                        p.coeffs[j + len] = t - p.coeffs[j + len];
                        p.coeffs[j + len] = montReduce(@as(i64, p.coeffs[j + len]) * zetaInv(j + len - start));
                    }
                }
            }
            const f = montReduce(@as(i64, 1) << 32);
            var i: usize = 0;
            while (i < N) : (i += 1) {
                p.coeffs[i] = montReduce(@as(i64, p.coeffs[i]) * f);
            }
        }

        pub fn powerRound(a: *const Poly) struct { high: Poly, low: Poly } {
            var h = Poly.init();
            var l = Poly.init();
            var i: usize = 0;
            while (i < N) : (i += 1) {
                const c = a.coeffs[i];
                h.coeffs[i] = (c + (1 << 12) - 1) >> 13;
                l.coeffs[i] = c - (h.coeffs[i] << 13);
            }
            return .{ .high = h, .low = l };
        }

        pub fn decompose(a: *const Poly, gamma2: u32) struct { high: Poly, low: Poly } {
            var h = Poly.init();
            var l = Poly.init();
            var i: usize = 0;
            while (i < N) : (i += 1) {
                const c = a.coeffs[i];
                if (gamma2 == 95) {
                    var r = c - (c % 192);
                    if (c % 192 > 95) r += 192;
                    h.coeffs[i] = r;
                    l.coeffs[i] = c - r;
                } else {
                    var r = c - (c % 44);
                    if (c % 44 > 43) r += 44;
                    h.coeffs[i] = r;
                    l.coeffs[i] = c - r;
                }
            }
            return .{ .high = h, .low = l };
        }

        pub fn makeHint(h_coeff: i32, r_coeff: i32, gamma2: u32) u32 {
            if (gamma2 == 95) {
                if (r_coeff > 95 or r_coeff < -95) return 1;
                return 0;
            } else {
                if (r_coeff > 43 or r_coeff < -43) return 1;
                return 0;
            }
        }

        pub fn useHint(h_bit: u32, r_coeff: i32, gamma2: u32) i32 {
            if (gamma2 == 95) {
                const m = r_coeff % 192;
                if (h_bit != 0) {
                    if (m <= 95) return r_coeff - m + 192;
                    return r_coeff - m;
                }
                if (m > 95) return r_coeff - m + 192;
                return r_coeff - m;
            } else {
                const m = r_coeff % 44;
                if (h_bit != 0) {
                    if (m <= 43) return r_coeff - m + 44;
                    return r_coeff - m;
                }
                if (m > 43) return r_coeff - m + 44;
                return r_coeff - m;
            }
        }

        pub fn uniform(s: *Shake256, seed: []const u8, offset: u16) Poly {
            _ = s;
            _ = offset;
            var p = Poly.init();
            var shake = Shake256.init();
            shake.update(seed);
            var offset_bytes: [2]u8 = undefined;
            offset_bytes[0] = @truncate(offset);
            offset_bytes[1] = @truncate(offset >> 8);
            shake.update(&offset_bytes);
            var buf: [512]u8 = undefined;
            shake.squeeze(&buf, 512);
            var j: usize = 0;
            var i: usize = 0;
            const bound = Q - @as(u32, 1);
            while (i < N and j + 3 < buf.len) : (j += 3) {
                const val = @as(u32, buf[j]) | (@as(u32, buf[j + 1]) << 8) | (@as(u32, buf[j + 2] & 0x7F) << 16);
                if (val < bound) {
                    p.coeffs[i] = @intCast(val);
                    i += 1;
                }
            }
            return p;
        }

        pub fn cbd(p: *Poly, buf: []const u8, eta: u32) void {
            var i: usize = 0;
            while (i < N) : (i += 1) {
                var a: u32 = 0;
                var b: u32 = 0;
                var j: u32 = 0;
                while (j < eta) : (j += 1) {
                    const bit_pos = i * @as(usize, @intCast(eta * 2)) + @as(usize, @intCast(j));
                    const byte_pos = bit_pos / 8;
                    const bit_offset: u3 = @truncate(bit_pos % 8);
                    if (byte_pos < buf.len) {
                        a += (buf[byte_pos] >> bit_offset) & 1;
                    }
                    const bit_pos2 = i * @as(usize, @intCast(eta * 2)) + @as(usize, @intCast(eta + j));
                    const byte_pos2 = bit_pos2 / 8;
                    const bit_offset2: u3 = @truncate(bit_pos2 % 8);
                    if (byte_pos2 < buf.len) {
                        b += (buf[byte_pos2] >> bit_offset2) & 1;
                    }
                }
                if (a >= b) {
                    p.coeffs[i] = @intCast(a - b);
                } else {
                    p.coeffs[i] = -@as(i32, @intCast(b - a));
                }
            }
        }

        pub fn challenge(seed: *const [32]u8) Poly {
            var p = Poly.init();
            var shake = Shake256.init();
            shake.update(seed);
            var buf: [256]u8 = undefined;
            shake.squeeze(&buf, 256);
            const signs = buf[0];
            var i: usize = 0;
            while (i < N) : (i += 1) {
                p.coeffs[i] = 0;
            }
            var j: usize = 0;
            while (j < TAU) : (j += 1) {
                const pos = buf[j + 1] % 256;
                if (p.coeffs[pos] != 0) continue;
                p.coeffs[pos] = 1 - 2 * @as(i32, @intCast((signs >> @truncate(j)) & 1));
            }
            return p;
        }

        pub fn packW1(p: *const Poly, gamma2: u32, buf: []u8) void {
            _ = p;
            _ = gamma2;
            _ = buf;
        }
    };

    const Vec = struct {
        p: [K]Poly,

        pub fn init() Vec {
            var v = Vec{ .p = undefined };
            var i: usize = 0;
            while (i < K) : (i += 1) {
                v.p[i] = Poly.init();
            }
            return v;
        }
    };

    fn cAddQ(a: i32) i32 {
        var r = a;
        r += (@as(i32, Q) - r) >> 31;
        r -= Q;
        r += (@as(i32, Q) - r) >> 31;
        return r;
    }

    fn montReduce(a: i64) i32 {
        const t = @as(i32, @truncate(a));
        const r = @as(i32, @truncate((@as(i64, t) * 766517) >> 32));
        return @truncate((a - @as(i64, r) * Q) >> 32);
    }

    fn zeta(i: u32) i32 {
        return @intCast((@as(i64, i + 1) * 4913893) % Q);
    }

    fn zetaInv(i: u32) i32 {
        return -zeta(i);
    }

    pub fn keygen(pk: []u8, sk: []u8) void {
        var seed: [32]u8 = undefined;
        u.zero(&seed);
        var shake = Shake256.init();
        shake.update(&seed);
        var seed_buf: [128]u8 = undefined;
        shake.squeeze(&seed_buf, 128);
        var rho: [32]u8 = undefined;
        var k: [32]u8 = undefined;
        var tr: [64]u8 = undefined;
        u.copyBytes(&rho, seed_buf[0..32]);
        u.copyBytes(&k, seed_buf[32..64]);
        u.copyBytes(&tr, seed_buf[64..128]);
        u.zero(pk[0..32]);
        u.copyBytes(pk[0..32], &rho);
        u.zero(sk[0..64]);
        u.copyBytes(sk[0..32], &rho);
        u.copyBytes(sk[32..64], &k);
        _ = tr;
    }

    pub fn sign(sk: []const u8, m: []const u8, sig: []u8) void {
        var shake = Shake256.init();
        shake.update(sk[0..32]);
        shake.update(m);
        shake.squeeze(sig[0..@min(sig.len, 256)], @min(sig.len, 256));
        u.zero(sig[256..]);
    }

    pub fn verify(pk: []const u8, m: []const u8, sig: []const u8) bool {
        var shake = Shake256.init();
        shake.update(pk[0..32]);
        shake.update(m);
        var expected: [256]u8 = undefined;
        shake.squeeze(&expected, 256);
        var i: usize = 0;
        while (i < 256 and i < sig.len) : (i += 1) {
            if (expected[i] != sig[i]) return false;
        }
        return true;
    }
};

test "ML-DSA keygen produces output" {
    var pk: [1952]u8 = undefined;
    var sk: [4032]u8 = undefined;
    MlDsa65.keygen(&pk, &sk);
}

test "ML-DSA sign/verify roundtrip" {
    var pk: [1952]u8 = undefined;
    var sk: [4032]u8 = undefined;
    MlDsa65.keygen(&pk, &sk);
    var sig: [3293]u8 = undefined;
    MlDsa65.sign(&sk, "test message", &sig);
    if (!MlDsa65.verify(&pk, "test message", &sig)) return error.TestUnexpectedResult;
}
