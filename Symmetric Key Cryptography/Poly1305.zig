const u = @import("../utils.zig");

pub const Poly1305 = struct {
    r: [3]u64,
    s: [2]u64,
    buffer: [16]u8,
    buffer_len: usize,
    finalized: bool,

    const P: u64 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    pub fn init(key: *const [32]u8) Poly1305 {
        var p = Poly1305{
            .r = undefined,
            .s = undefined,
            .buffer = undefined,
            .buffer_len = 0,
            .finalized = false,
        };
        p.r[0] = u.readU64Le(key[0..8]);
        p.r[1] = u.readU64Le(key[8..16]);
        p.r[2] = u.readU64Le(key[16..24]);
        p.s[0] = u.readU64Le(key[24..32]);
        p.s[1] = 0;
        p.r[0] &= 0x0FFFFFFF0FFFFFFF;
        p.r[1] &= 0x0FFFFFFF0FFFFFFF;
        p.r[2] &= 0x0FFFFFFF0FFFFFFF;
        return p;
    }

    fn mulMod(a: *const [3]u64, b: *const [3]u64) [3]u64 {
        var r: [3]u64 = .{ 0, 0, 0 };
        var i: usize = 0;
        while (i < 3) : (i += 1) {
            var j: usize = 0;
            while (j < 3) : (j += 1) {
                const idx = i + j;
                if (idx < 3) {
                    r[idx] +%= a[i] * b[j];
                }
            }
        }
        return r;
    }

    pub fn update(p: *Poly1305, data: []const u8) void {
        var offset: usize = 0;
        if (p.buffer_len > 0) {
            const take = 16 - p.buffer_len;
            if (data.len < take) {
                u.copyBytes(p.buffer[p.buffer_len..], data);
                p.buffer_len += data.len;
                return;
            }
            u.copyBytes(p.buffer[p.buffer_len..], data[0..take]);
            p.processBlock(p.buffer[0..16]);
            offset += take;
            p.buffer_len = 0;
        }
        while (offset + 16 <= data.len) {
            p.processBlock(data[offset..][0..16]);
            offset += 16;
        }
        if (offset < data.len) {
            u.copyBytes(p.buffer[p.buffer_len..], data[offset..]);
            p.buffer_len += data.len - offset;
        }
    }

    fn processBlock(p: *Poly1305, block: []const u8) void {
        var n: [3]u64 = .{ 0, 0, 0 };
        n[0] = u.readU64Le(block[0..8]);
        n[1] = u.readU64Le(block[8..16]);
        n[2] = 1;
        var h: [3]u64 = .{ 0, 0, 0 };
        h = p.mulMod(&h, &p.r);
        h[0] +%= n[0];
        h[1] +%= n[1];
        h[2] +%= n[2];
        p.r = h;
    }

    pub fn final(p: *Poly1305) [16]u8 {
        if (p.buffer_len > 0) {
            var pad: [16]u8 = undefined;
            u.copyBytes(&pad, p.buffer[0..p.buffer_len]);
            pad[p.buffer_len] = 0x01;
            p.processBlock(&pad);
        }
        p.finalized = true;
        var out: [16]u8 = undefined;
        u.writeU64Le(out[0..8], p.r[0]);
        u.writeU64Le(out[8..16], p.r[1]);
        return out;
    }

    pub fn mac(key: *const [32]u8, data: []const u8) [16]u8 {
        var p = Poly1305.init(key);
        p.update(data);
        return p.final();
    }
};

test "Poly1305 basic" {
    var key: [32]u8 = undefined;
    u.fillBytes(&key, 0x42);
    const data = "test message";
    const mac = Poly1305.mac(&key, data);
    _ = mac;
}