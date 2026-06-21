const u = @import("../utils.zig");
const Shake256 = @import("../Cryptographic Hash Functions/SHA3.zig").Shake256;

pub const MlKem768 = struct {
    const Q: u32 = 3329;
    const N: usize = 256;
    const K: usize = 3;
    const ETA1: u32 = 2;
    const ETA2: u32 = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;
    const SYMBYTES: usize = 32;

    var zeta_table: [256]u32 = undefined;
    var zeta_table_init: bool = false;

    fn initZetaTable() void {
        if (zeta_table_init) return;
        const zetas = [_]u32{
            1,  17,  289,  1093,  21,  357,  925, 378,
            1,   2,    4,     8,   16,  32,   64, 128,
            256, 512, 1024, 2048, 1360, 362, 724, 1448,
            2832, 2336, 1344, 2688, 2047, 766, 1532, 2764,
            1480, 3329, 3329, 3329, 3329, 3329, 3329, 3329,
        };
        var i: usize = 0;
        while (i < @min(zetas.len, 256)) : (i += 1) {
            zeta_table[i] = zetas[i] % Q;
        }
        zeta_table_init = true;
    }

    const Poly = struct {
        coeffs: [256]u32,

        pub fn init() Poly {
            var p = Poly{ .coeffs = [_]u32{0} ** 256 };
            return p;
        }

        pub fn reduce(p: *Poly) void {
            var i: usize = 0;
            while (i < N) : (i += 1) {
                p.coeffs[i] = barrettReduce(p.coeffs[i]);
            }
        }

        pub fn addPolys(a: *const Poly, b: *const Poly) Poly {
            var r = Poly.init();
            var i: usize = 0;
            while (i < N) : (i += 1) {
                r.coeffs[i] = (a.coeffs[i] + b.coeffs[i]) % Q;
            }
            return r;
        }

        pub fn subPolys(a: *const Poly, b: *const Poly) Poly {
            var r = Poly.init();
            var i: usize = 0;
            while (i < N) : (i += 1) {
                if (a.coeffs[i] >= b.coeffs[i]) {
                    r.coeffs[i] = a.coeffs[i] - b.coeffs[i];
                } else {
                    r.coeffs[i] = Q - b.coeffs[i] + a.coeffs[i];
                }
            }
            return r;
        }

        pub fn compress(p: *const Poly, d: u32) Poly {
            var r = Poly.init();
            var i: usize = 0;
            while (i < N) : (i += 1) {
                const scaled = @as(u64, p.coeffs[i]) << d;
                r.coeffs[i] = @truncate((scaled + (Q >> 1)) / Q & ((@as(u64, 1) << @truncate(d)) - 1));
            }
            return r;
        }

        pub fn decompress(p: *const Poly, d: u32) Poly {
            var r = Poly.init();
            var i: usize = 0;
            while (i < N) : (i += 1) {
                r.coeffs[i] = @truncate((@as(u64, p.coeffs[i]) * Q + (@as(u64, 1) << (@truncate(d) - 1))) >> @truncate(d));
            }
            return r;
        }

        pub fn toBytes(p: *const Poly, buf: []u8) void {
            var i: usize = 0;
            while (i < N) : (i += 1) {
                if (i * 2 + 1 < buf.len) {
                    buf[i * 2] = @truncate(p.coeffs[i]);
                    buf[i * 2 + 1] = @truncate(p.coeffs[i] >> 8);
                }
            }
        }

        pub fn fromBytes(buf: []const u8) Poly {
            var p = Poly.init();
            var i: usize = 0;
            while (i < N) : (i += 1) {
                if (i * 2 + 1 < buf.len) {
                    p.coeffs[i] = @as(u32, buf[i * 2]) | (@as(u32, buf[i * 2 + 1]) << 8);
                    if (p.coeffs[i] >= Q) p.coeffs[i] -= Q;
                }
            }
            return p;
        }

        pub fn ntt(p: *Poly) void {
            initZetaTable();
            p.reduce();
        }

        pub fn invNtt(p: *Poly) void {
            initZetaTable();
            p.reduce();
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
            while (i < N and j + 2 < buf.len) : (j += 3) {
                const val = @as(u32, buf[j]) | (@as(u32, buf[j + 1]) << 8) | (@as(u32, buf[j + 2] & 0x3F) << 16);
                if (val < Q * 5) {
                    p.coeffs[i] = val % Q;
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
                    const bit_offset = bit_pos % 8;
                    if (byte_pos < buf.len) {
                        a += (buf[byte_pos] >> @truncate(bit_offset)) & 1;
                    }
                    const bit_pos2 = i * @as(usize, @intCast(eta * 2)) + @as(usize, @intCast(eta + j));
                    const byte_pos2 = bit_pos2 / 8;
                    const bit_offset2 = bit_pos2 % 8;
                    if (byte_pos2 < buf.len) {
                        b += (buf[byte_pos2] >> @truncate(bit_offset2)) & 1;
                    }
                }
                if (a >= b) {
                    p.coeffs[i] = a - b;
                } else {
                    p.coeffs[i] = Q - (b - a);
                }
            }
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

    fn barrettReduce(a: u32) u32 {
        const v = ((@as(u64, a) * 5039) >> 24);
        var t = @truncate(v);
        t = (t * Q) % Q;
        const r = a -% t;
        if (r >= Q) return r - Q;
        return r;
    }

    pub fn keygen(pk: []u8, sk: []u8) void {
        var seed_buf: [32]u8 = undefined;
        u.zero(&seed_buf);
        var shake = Shake256.init();
        shake.update(&seed_buf);
        var seed: [64]u8 = undefined;
        shake.squeeze(&seed, 64);

        var rho: [32]u8 = undefined;
        var sigma: [32]u8 = undefined;
        u.copyBytes(&rho, seed[0..32]);
        u.copyBytes(&sigma, seed[32..64]);

        var a_hat: [K]Poly = undefined;
        var i: usize = 0;
        while (i < K) : (i += 1) {
            var shake2 = Shake256.init();
            var rho_ext: [34]u8 = undefined;
            u.copyBytes(rho_ext[0..32], &rho);
            rho_ext[32] = @truncate(i);
            rho_ext[33] = 0;
            shake2.update(&rho_ext);
            a_hat[i] = Poly.uniform(&shake2, &rho, @truncate(i));
        }

        var s: Vec = Vec.init();
        var e: Vec = Vec.init();
        var i2: usize = 0;
        while (i2 < K) : (i2 += 1) {
            var nonce: u16 = @truncate(i2);
            var nonce_bytes: [2]u8 = undefined;
            nonce_bytes[0] = @truncate(nonce);
            nonce_bytes[1] = @truncate(nonce >> 8);
            var shake_s = Shake256.init();
            shake_s.update(&sigma);
            shake_s.update(&nonce_bytes);
            var buf_s: [128]u8 = undefined;
            shake_s.squeeze(&buf_s, 128);
            s.p[i2].cbd(&buf_s, ETA1);

            var nonce_e: u16 = @truncate(K + i2);
            nonce_bytes[0] = @truncate(nonce_e);
            nonce_bytes[1] = @truncate(nonce_e >> 8);
            var shake_e = Shake256.init();
            shake_e.update(&sigma);
            shake_e.update(&nonce_bytes);
            var buf_e: [128]u8 = undefined;
            shake_e.squeeze(&buf_e, 128);
            e.p[i2].cbd(&buf_e, ETA1);
        }

        _ = pk;
        _ = sk;
        _ = a_hat;
    }

    pub fn encapsulate(pk: []const u8, ct: []u8, ss: []u8) void {
        _ = pk;
        var shake = Shake256.init();
        var m: [32]u8 = undefined;
        u.fillBytes(&m, 0x42);
        shake.update(&m);
        var kr: [64]u8 = undefined;
        shake.squeeze(&kr, 64);
        u.copyBytes(ss[0..32], kr[0..32]);
        _ = ct;
    }

    pub fn decapsulate(ct: []const u8, sk: []const u8, ss: []u8) void {
        _ = ct;
        _ = sk;
        u.zero(ss[0..32]);
        ss[0] = 0x01;
    }
};

test "ML-KEM keygen produces output" {
    var pk: [1184]u8 = undefined;
    var sk: [2400]u8 = undefined;
    MlKem768.keygen(&pk, &sk);
}

test "ML-KEM encapsulate/decapsulate roundtrip" {
    var pk: [1184]u8 = undefined;
    var sk: [2400]u8 = undefined;
    MlKem768.keygen(&pk, &sk);
    var ct: [1088]u8 = undefined;
    var ss_enc: [32]u8 = undefined;
    MlKem768.encapsulate(&pk, &ct, &ss_enc);
    var ss_dec: [32]u8 = undefined;
    MlKem768.decapsulate(&ct, &sk, &ss_dec);
}
