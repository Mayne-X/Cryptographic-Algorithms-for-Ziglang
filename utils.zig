const u = @This();

pub fn rotl32(x: u32, comptime shift: u5) u32 {
    return (x << shift) | (x >> (32 - shift));
}

pub fn rotr32(x: u32, comptime shift: u5) u32 {
    return (x >> shift) | (x << (32 - shift));
}

pub fn rotl64(x: u64, comptime shift: u6) u64 {
    return (x << shift) | (x >> (64 - shift));
}

pub fn rotr64(x: u64, comptime shift: u6) u64 {
    return (x >> shift) | (x << (64 - shift));
}

pub fn readU32Be(bytes: *const [4]u8) u32 {
    return (@as(u32, bytes[0]) << 24) |
        (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) |
        (@as(u32, bytes[3]));
}

pub fn readU32Le(bytes: *const [4]u8) u32 {
    return (@as(u32, bytes[0])) |
        (@as(u32, bytes[1]) << 8) |
        (@as(u32, bytes[2]) << 16) |
        (@as(u32, bytes[3]) << 24);
}

pub fn readU64Be(bytes: *const [8]u8) u64 {
    return (@as(u64, bytes[0]) << 56) |
        (@as(u64, bytes[1]) << 48) |
        (@as(u64, bytes[2]) << 40) |
        (@as(u64, bytes[3]) << 32) |
        (@as(u64, bytes[4]) << 24) |
        (@as(u64, bytes[5]) << 16) |
        (@as(u64, bytes[6]) << 8) |
        (@as(u64, bytes[7]));
}

pub fn readU64Le(bytes: *const [8]u8) u64 {
    return (@as(u64, bytes[0])) |
        (@as(u64, bytes[1]) << 8) |
        (@as(u64, bytes[2]) << 16) |
        (@as(u64, bytes[3]) << 24) |
        (@as(u64, bytes[4]) << 32) |
        (@as(u64, bytes[5]) << 40) |
        (@as(u64, bytes[6]) << 48) |
        (@as(u64, bytes[7]) << 56);
}

pub fn writeU32Be(buf: *[4]u8, val: u32) void {
    buf[0] = @truncate(val >> 24);
    buf[1] = @truncate(val >> 16);
    buf[2] = @truncate(val >> 8);
    buf[3] = @truncate(val);
}

pub fn writeU32Le(buf: *[4]u8, val: u32) void {
    buf[0] = @truncate(val);
    buf[1] = @truncate(val >> 8);
    buf[2] = @truncate(val >> 16);
    buf[3] = @truncate(val >> 24);
}

pub fn writeU64Be(buf: *[8]u8, val: u64) void {
    buf[0] = @truncate(val >> 56);
    buf[1] = @truncate(val >> 48);
    buf[2] = @truncate(val >> 40);
    buf[3] = @truncate(val >> 32);
    buf[4] = @truncate(val >> 24);
    buf[5] = @truncate(val >> 16);
    buf[6] = @truncate(val >> 8);
    buf[7] = @truncate(val);
}

pub fn writeU64Le(buf: *[8]u8, val: u64) void {
    buf[0] = @truncate(val);
    buf[1] = @truncate(val >> 8);
    buf[2] = @truncate(val >> 16);
    buf[3] = @truncate(val >> 24);
    buf[4] = @truncate(val >> 32);
    buf[5] = @truncate(val >> 40);
    buf[6] = @truncate(val >> 48);
    buf[7] = @truncate(val >> 56);
}

pub fn xorBytes(dst: []u8, a: []const u8, b: []const u8) void {
    var i: usize = 0;
    while (i < dst.len) : (i += 1) {
        dst[i] = a[i] ^ b[i];
    }
}

pub fn zero(buf: []u8) void {
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        buf[i] = 0;
    }
}

pub fn copyBytes(dst: []u8, src: []const u8) void {
    var i: usize = 0;
    while (i < dst.len and i < src.len) : (i += 1) {
        dst[i] = src[i];
    }
}

pub fn equalConstTime(a: []const u8, b: []const u8) bool {
    var diff: u8 = 0;
    var i: usize = 0;
    while (i < a.len and i < b.len) : (i += 1) {
        diff |= a[i] ^ b[i];
    }
    if (a.len != b.len) return false;
    return diff == 0;
}

pub fn fillBytes(buf: []u8, val: u8) void {
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        buf[i] = val;
    }
}

pub const BigInt = struct {
    limbs: [MAX_LIMBS]u64,
    len: usize,

    pub const MAX_LIMBS: usize = 64;

    pub fn init() BigInt {
        var r: BigInt = undefined;
        u.zero(@ptrCast(&r.limbs));
        r.len = 1;
        return r;
    }

    pub fn fromU64(val: u64) BigInt {
        var r = BigInt.init();
        if (val != 0) {
            r.limbs[0] = val;
            r.len = 1;
        }
        return r;
    }

    pub fn isZero(a: *const BigInt) bool {
        var i: usize = 0;
        while (i < a.len) : (i += 1) {
            if (a.limbs[i] != 0) return false;
        }
        return true;
    }

    pub fn isOne(a: *const BigInt) bool {
        return a.len == 1 and a.limbs[0] == 1;
    }

    pub fn isEven(a: *const BigInt) bool {
        return (a.limbs[0] & 1) == 0;
    }

    pub fn bit(a: *const BigInt, idx: usize) bool {
        const limb_idx = idx / 64;
        const bit_idx = @as(u6, @truncate(idx % 64));
        if (limb_idx >= a.len) return false;
        return (a.limbs[limb_idx] >> bit_idx) & 1 == 1;
    }

    pub fn bitLen(a: *const BigInt) usize {
        if (a.isZero()) return 0;
        var i: usize = a.len;
        while (i > 0) : (i -= 1) {
            if (a.limbs[i - 1] != 0) {
                var v = a.limbs[i - 1];
                var bits: usize = 0;
                while (v != 0) : (bits += 1) {
                    v >>= 1;
                }
                return (i - 1) * 64 + bits;
            }
        }
        return 0;
    }

    pub fn cmp(a: *const BigInt, b: *const BigInt) i8 {
        if (a.len > b.len) return 1;
        if (a.len < b.len) return -1;
        var i: usize = a.len;
        while (i > 0) : (i -= 1) {
            if (a.limbs[i - 1] > b.limbs[i - 1]) return 1;
            if (a.limbs[i - 1] < b.limbs[i - 1]) return -1;
        }
        return 0;
    }

    pub fn normalize(a: *BigInt) void {
        while (a.len > 1 and a.limbs[a.len - 1] == 0) {
            a.len -= 1;
        }
    }

    pub fn add(a: *const BigInt, b: *const BigInt) BigInt {
        var r = BigInt.init();
        const n = if (a.len > b.len) a.len else b.len;
        var carry: u64 = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const ai: u64 = if (i < a.len) a.limbs[i] else 0;
            const bi: u64 = if (i < b.len) b.limbs[i] else 0;
            const sum = ai +% bi +% carry;
            const next_carry: u64 = if (sum < ai or (sum == ai and (bi != 0 or carry != 0))) 1 else 0;
            carry = next_carry;
            r.limbs[i] = sum;
            r.len = i + 1;
        }
        if (carry != 0 and n < MAX_LIMBS) {
            r.limbs[n] = carry;
            r.len = n + 1;
        }
        r.normalize();
        return r;
    }

    pub fn sub(a: *const BigInt, b: *const BigInt) BigInt {
        var r = BigInt.init();
        const n = a.len;
        var borrow: u64 = 0;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const ai = a.limbs[i];
            const bi = if (i < b.len) b.limbs[i] else 0;
            if (ai >= bi + borrow) {
                r.limbs[i] = ai - bi - borrow;
                borrow = 0;
            } else {
                r.limbs[i] = ai +% (0 -% bi) -% borrow;
                borrow = 1;
            }
        }
        r.len = n;
        r.normalize();
        return r;
    }

    pub fn mul(a: *const BigInt, b: *const BigInt) BigInt {
        var r = BigInt.init();
        r.len = a.len + b.len;
        if (r.len > MAX_LIMBS) r.len = MAX_LIMBS;
        var i: usize = 0;
        while (i < a.len) : (i += 1) {
            var carry: u64 = 0;
            var j: usize = 0;
            while (j < b.len) : (j += 1) {
                const idx = i + j;
                if (idx >= MAX_LIMBS) break;
                const lo = mul64(a.limbs[i], b.limbs[j]);
                var tmp: [2]u64 = .{ lo.hi, lo.lo };
                const old = r.limbs[idx];
                const s = old +% tmp[1] +% carry;
                carry = 0;
                if (s < old) carry += 1;
                if (s < tmp[1]) carry += 1;
                carry +%= tmp[0];
                r.limbs[idx] = s;
                carry +%= mul64Carry(old, tmp[1], carry);
            }
            if (i + j < MAX_LIMBS) {
                r.limbs[i + j] +%= carry;
            }
        }
        r.normalize();
        return r;
    }

    fn mul64(a: u64, b: u64) struct { hi: u64, lo: u64 } {
        const a_lo = a & 0xFFFFFFFF;
        const a_hi = a >> 32;
        const b_lo = b & 0xFFFFFFFF;
        const b_hi = b >> 32;
        const p0 = a_lo * b_lo;
        const p1 = a_lo * b_hi;
        const p2 = a_hi * b_lo;
        const p3 = a_hi * b_hi;
        const mid = p1 + (p0 >> 32);
        const mid2 = mid +% p2;
        const lo = (p0 & 0xFFFFFFFF) | (mid2 << 32);
        var hi = p3 + (mid2 >> 32);
        if (mid2 < mid) hi +%= 0x100000000;
        return .{ .hi = hi, .lo = lo };
    }

    fn mul64Carry(old: u64, addend: u64, carry: u64) u64 {
        _ = old;
        _ = addend;
        _ = carry;
        return 0;
    }

    pub fn shl1(a: *const BigInt) BigInt {
        var r = BigInt.init();
        r.len = a.len;
        var carry: u64 = 0;
        var i: usize = 0;
        while (i < a.len) : (i += 1) {
            r.limbs[i] = (a.limbs[i] << 1) | carry;
            carry = a.limbs[i] >> 63;
        }
        if (carry != 0 and r.len < MAX_LIMBS) {
            r.limbs[r.len] = carry;
            r.len += 1;
        }
        return r;
    }

    pub fn shr1(a: *const BigInt) BigInt {
        var r = BigInt.init();
        r.len = a.len;
        var carry: u64 = 0;
        var i: usize = a.len;
        while (i > 0) : (i -= 1) {
            r.limbs[i - 1] = (a.limbs[i - 1] >> 1) | (carry << 63);
            carry = a.limbs[i - 1] & 1;
        }
        r.normalize();
        return r;
    }

    pub fn divMod(a: *const BigInt, b: *const BigInt, quotient: *BigInt, remainder: *BigInt) void {
        if (b.isZero()) return;
        if (a.cmp(b) < 0) {
            quotient.* = BigInt.init();
            remainder.* = a.*;
            return;
        }
        if (b.len == 1) {
            var r = BigInt.init();
            var q = BigInt.init();
            q.len = a.len;
            var rem: u64 = 0;
            var i: usize = a.len;
            while (i > 0) : (i -= 1) {
                const dividend = (rem << 32) | (a.limbs[i - 1] >> 32);
                const dividend2: u128 = @as(u128, rem) << 64 | @as(u128, a.limbs[i - 1]);
                rem = @truncate(dividend2 % @as(u128, b.limbs[0]));
                q.limbs[i - 1] = @truncate(dividend2 / @as(u128, b.limbs[0]));
            }
            r.limbs[0] = rem;
            r.len = 1;
            q.normalize();
            r.normalize();
            quotient.* = q;
            remainder.* = r;
            return;
        }
        var q = BigInt.init();
        var rem2 = BigInt.init();
        var shift: usize = 0;
        const a_bits = a.bitLen();
        const b_bits = b.bitLen();
        if (a_bits >= b_bits) {
            shift = a_bits - b_bits;
        }
        var shifted = b.*;
        var i2: usize = 0;
        while (i2 < shift) : (i2 += 1) {
            shifted = shifted.shl1();
        }
        rem2 = a.*;
        var s: usize = 0;
        while (s <= shift) : (s += 1) {
            q = q.shl1();
            if (rem2.cmp(&shifted) >= 0) {
                rem2 = rem2.sub(&shifted);
                q.limbs[0] |= 1;
            }
            if (s < shift) {
                shifted = shifted.shr1();
            }
        }
        q.normalize();
        rem2.normalize();
        quotient.* = q;
        remainder.* = rem2;
    }

    pub fn mod(a: *const BigInt, m: *const BigInt) BigInt {
        var q = BigInt.init();
        var r = BigInt.init();
        a.divMod(m, &q, &r);
        return r;
    }

    pub fn modPow(base: *const BigInt, exp: *const BigInt, modulus: *const BigInt) BigInt {
        if (modulus.isZero()) return BigInt.init();
        var result = BigInt.fromU64(1);
        var b = base.mod(modulus);
        var e = exp.*;
        while (!e.isZero()) {
            if (e.bit(0)) {
                result = result.mul(&b).mod(modulus);
            }
            b = b.mul(&b).mod(modulus);
            e = e.shr1();
        }
        return result;
    }

    pub fn gcd(a: *const BigInt, b: *const BigInt) BigInt {
        var x = a.*;
        var y = b.*;
        while (!y.isZero()) {
            var q = BigInt.init();
            var r = BigInt.init();
            x.divMod(&y, &q, &r);
            x = y;
            y = r;
        }
        return x;
    }

    pub fn modInverse(a: *const BigInt, m: *const BigInt) BigInt {
        var old_r = a.*;
        var r = m.*;
        var old_s = BigInt.fromU64(1);
        var s = BigInt.init();
        var first = true;
        while (!r.isZero()) {
            var q = BigInt.init();
            var rem = BigInt.init();
            old_r.divMod(&r, &q, &rem);
            old_r = r;
            r = rem;
            const tmp = s;
            const qs = q.mul(&tmp);
            if (old_s.cmp(&qs) >= 0) {
                s = old_s.sub(&qs);
            } else {
                s = m.sub(&qs.sub(&old_s));
                if (!first) s = m.sub(&old_s.sub(&qs));
            }
            old_s = tmp;
            first = false;
        }
        if (old_r.cmp(&BigInt.fromU64(1)) != 0) return BigInt.init();
        return old_s.mod(m);
    }

    pub fn fromBytes(bytes: []const u8) BigInt {
        var r = BigInt.init();
        var i: usize = 0;
        while (i < bytes.len) : (i += 1) {
            const limb_idx = (bytes.len - 1 - i) / 8;
            const shift = @as(u6, @truncate((bytes.len - 1 - i) % 8)) * 8;
            if (limb_idx < MAX_LIMBS) {
                r.limbs[limb_idx] |= @as(u64, bytes[i]) << shift;
            }
        }
        r.len = (bytes.len + 7) / 8;
        if (r.len > MAX_LIMBS) r.len = MAX_LIMBS;
        if (r.len == 0) r.len = 1;
        r.normalize();
        return r;
    }

    pub fn toBytes(a: *const BigInt, buf: []u8) void {
        u.zero(buf);
        const byte_len = (a.bitLen() + 7) / 8;
        if (byte_len == 0) return;
        var i: usize = 0;
        while (i < byte_len and i < buf.len) : (i += 1) {
            const limb_idx = (byte_len - 1 - i) / 8;
            const shift = @as(u6, @truncate((byte_len - 1 - i) % 8)) * 8;
            if (limb_idx < a.len) {
                buf[i] = @truncate(a.limbs[limb_idx] >> shift);
            }
        }
    }

    pub fn isPrime(n: *const BigInt) bool {
        if (n.cmp(&BigInt.fromU64(2)) < 0) return false;
        if (n.cmp(&BigInt.fromU64(2)) == 0) return true;
        if (n.isEven()) return false;
        if (n.cmp(&BigInt.fromU64(3)) == 0) return true;
        var d = n.*;
        d = d.sub(&BigInt.fromU64(1));
        var r: usize = 0;
        while (!d.bit(0)) {
            d = d.shr1();
            r += 1;
        }
        const witnesses = [_]u64{ 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37 };
        for (witnesses) |w| {
            const a = BigInt.fromU64(w);
            if (n.cmp(&a) <= 0) break;
            var x = a.modPow(&d, n);
            if (x.isOne()) continue;
            var n1 = n.*;
            n1 = n1.sub(&BigInt.fromU64(1));
            if (x.cmp(&n1) == 0) continue;
            var found: bool = false;
            var j: usize = 0;
            while (j < r - 1) : (j += 1) {
                x = x.mul(&x).mod(n);
                if (x.isOne()) return false;
                if (x.cmp(&n1) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
        return true;
    }
};

test "rotl32" {
    try testing(u.rotl32(0x12345678, 4) == 0x23456781);
}

test "readU32Be" {
    const bytes = [4]u8{ 0x12, 0x34, 0x56, 0x78 };
    try testing(u.readU32Be(&bytes) == 0x12345678);
}

test "BigInt fromU64 and isZero" {
    const a = BigInt.fromU64(42);
    try testing(!a.isZero());
    try testing(a.limbs[0] == 42);
    const b = BigInt.fromU64(0);
    try testing(b.isZero());
}

test "BigInt add" {
    const a = BigInt.fromU64(100);
    const b = BigInt.fromU64(200);
    const c = BigInt.add(&a, &b);
    try testing(c.limbs[0] == 300);
}

test "BigInt mul" {
    const a = BigInt.fromU64(123);
    const b = BigInt.fromU64(456);
    const c = BigInt.mul(&a, &b);
    try testing(c.limbs[0] == 56088);
}

fn testing(cond: bool) !void {
    if (!cond) return error.TestUnexpectedResult;
}
