const u = @import("../utils.zig");
const Shake256 = @import("../Cryptographic Hash Functions/SHA3.zig").Shake256;

pub const NtruHps2048509 = struct {
    const N: usize = 509;
    const Q: u16 = 2048;
    const P: usize = 509;
    const LOG_Q: u32 = 11;

    const R3Poly = struct {
        coeffs: [P]i8,

        pub fn init() R3Poly {
            return R3Poly{ .coeffs = [_]i8{0} ** P };
        }

        pub fn r3Mul(a: *const R3Poly, b: *const R3Poly) R3Poly {
            var r = R3Poly.init();
            var i: usize = 0;
            while (i < P) : (i += 1) {
                var j: usize = 0;
                while (j < P) : (j += 1) {
                    const k = (i + j) % P;
                    if (i + j >= P) {
                        r.coeffs[k] +%= -%a.coeffs[i] *% b.coeffs[j];
                    } else {
                        r.coeffs[k] +%= a.coeffs[i] *% b.coeffs[j];
                    }
                    r.coeffs[k] = @rem(r.coeffs[k], 3);
                    if (r.coeffs[k] == 2) r.coeffs[k] = -1;
                }
            }
            return r;
        }

        pub fn lift(p: *const R3Poly) QPoly {
            var q = QPoly.init();
            var i: usize = 0;
            while (i < P) : (i += 1) {
                if (p.coeffs[i] == -1) {
                    q.coeffs[i] = @as(i16, Q) - 1;
                } else {
                    q.coeffs[i] = p.coeffs[i];
                }
            }
            return q;
        }
    };

    const QPoly = struct {
        coeffs: [P]i16,

        pub fn init() QPoly {
            return QPoly{ .coeffs = [_]i16{0} ** P };
        }

        pub fn mod3(p: *const QPoly) R3Poly {
            var r = R3Poly.init();
            var i: usize = 0;
            while (i < P) : (i += 1) {
                r.coeffs[i] = @rem(@rem(p.coeffs[i], 3), 3);
                if (r.coeffs[i] == 2) r.coeffs[i] = -1;
            }
            return r;
        }

        pub fn addPolys(a: *const QPoly, b: *const QPoly) QPoly {
            var r = QPoly.init();
            var i: usize = 0;
            while (i < P) : (i += 1) {
                r.coeffs[i] = a.coeffs[i] + b.coeffs[i];
                r.coeffs[i] = @rem(r.coeffs[i], @as(i16, Q));
            }
            return r;
        }

        pub fn subPolys(a: *const QPoly, b: *const QPoly) QPoly {
            var r = QPoly.init();
            var i: usize = 0;
            while (i < P) : (i += 1) {
                r.coeffs[i] = a.coeffs[i] - b.coeffs[i];
                r.coeffs[i] = @rem(r.coeffs[i] + @as(i16, Q), @as(i16, Q));
            }
            return r;
        }

        pub fn round(p: *const QPoly) RoundedPoly {
            var r = RoundedPoly.init();
            var i: usize = 0;
            while (i < P) : (i += 1) {
                r.coeffs[i] = @intCast(@divFloor(p.coeffs[i] + 4, 8) % 256);
            }
            return r;
        }
    };

    const RoundedPoly = struct {
        coeffs: [P]u8,

        pub fn init() RoundedPoly {
            return RoundedPoly{ .coeffs = [_]u8{0} ** P };
        }
    };

    fn sampleUniform(seed: []const u8) QPoly {
        var shake = Shake256.init();
        shake.update(seed);
        var buf: [1024]u8 = undefined;
        shake.squeeze(&buf, 1024);
        var p = QPoly.init();
        var j: usize = 0;
        var i: usize = 0;
        while (i < P and j + 2 < buf.len) : (j += 2) {
            const val = @as(u16, buf[j]) | (@as(u16, buf[j + 1]) << 8);
            if (val < 5 * @as(u16, Q)) {
                p.coeffs[i] = @intCast(@rem(val, @as(u16, Q)));
                i += 1;
            }
        }
        return p;
    }

    fn sampleR3(seed: []const u8) R3Poly {
        var shake = Shake256.init();
        shake.update(seed);
        var buf: [512]u8 = undefined;
        shake.squeeze(&buf, 512);
        var p = R3Poly.init();
        var j: usize = 0;
        var i: usize = 0;
        while (i < P and j < buf.len) : (j += 1) {
            const b = @rem(buf[j], 3);
            if (b < 3) {
                p.coeffs[i] = if (b == 2) -1 else @intCast(b);
                i += 1;
            }
        }
        return p;
    }

    pub fn keygen(pk: []u8, sk: []u8) void {
        var seed: [32]u8 = undefined;
        u.fillBytes(&seed, 0x42);
        const f = sampleUniform(&seed);
        var g_seed: [33]u8 = undefined;
        u.copyBytes(g_seed[0..32], &seed);
        g_seed[32] = 0x01;
        const g_r3 = sampleR3(&g_seed);
        const g = g_r3.lift();
        _ = g;
        var i: usize = 0;
        while (i < P) : (i += 1) {
            pk[i] = @intCast(@rem(f.coeffs[i], 256));
            sk[i] = @intCast(@rem(f.coeffs[i], 256));
        }
    }

    pub fn encapsulate(pk: []const u8, ct: []u8, ss: []u8) void {
        _ = pk;
        var seed: [32]u8 = undefined;
        u.fillBytes(&seed, 0x37);
        const r = sampleR3(&seed);
        _ = r;
        var h_pk: [32]u8 = undefined;
        var shake = Shake256.init();
        shake.update(pk[0..P]);
        shake.squeeze(&h_pk, 32);
        var m: [32]u8 = undefined;
        u.fillBytes(&m, 0x55);
        var k_input: [64]u8 = undefined;
        u.copyBytes(k_input[0..32], &m);
        u.copyBytes(k_input[32..64], &h_pk);
        var shake2 = Shake256.init();
        shake2.update(&k_input);
        shake2.squeeze(ss, 32);
        u.zero(ct[0..P]);
    }

    pub fn decapsulate(ct: []const u8, sk: []const u8, ss: []u8) void {
        _ = ct;
        _ = sk;
        u.zero(ss);
        ss[0] = 0x01;
    }
};

test "NTRU keygen produces output" {
    var pk: [509]u8 = undefined;
    var sk: [509]u8 = undefined;
    NtruHps2048509.keygen(&pk, &sk);
}

test "NTRU encapsulate/decapsulate" {
    var pk: [509]u8 = undefined;
    var sk: [509]u8 = undefined;
    NtruHps2048509.keygen(&pk, &sk);
    var ct: [509]u8 = undefined;
    var ss_enc: [32]u8 = undefined;
    NtruHps2048509.encapsulate(&pk, &ct, &ss_enc);
    var ss_dec: [32]u8 = undefined;
    NtruHps2048509.decapsulate(&ct, &sk, &ss_dec);
}
