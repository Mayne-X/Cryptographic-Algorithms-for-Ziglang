const u = @import("../utils.zig");
const ChaCha20 = @import("ChaCha20.zig").ChaCha20;
const Poly1305 = @import("Poly1305.zig").Poly1305;

pub const ChaCha20Poly1305 = struct {
    pub fn encrypt(key: *const [32]u8, nonce: *const [12]u8, aad: []const u8, plaintext: []u8, ciphertext: []u8) [16]u8 {
        var chacha = ChaCha20.init(key, nonce, 0);
        var counter: u32 = 1;
        var poly_key: [32]u8 = undefined;
        var keystream: [64]u8 = undefined;
        chacha.keystreamBlock(counter, &keystream);
        counter += 1;
        u.copyBytes(&poly_key, keystream[0..32]);

        var offset: usize = 0;
        while (offset + 64 <= plaintext.len) : (offset += 64) {
            chacha.keystreamBlock(counter, &keystream);
            counter += 1;
            var i: usize = 0;
            while (i < 64) : (i += 1) {
                ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
            }
        }
        if (offset < plaintext.len) {
            chacha.keystreamBlock(counter, &keystream);
            var i: usize = 0;
            while (i < plaintext.len - offset) : (i += 1) {
                ciphertext[i] = plaintext[i] ^ keystream[i];
            }
        }

        var poly = Poly1305.init(&poly_key);
        poly.update(aad);
        if (aad.len % 16 != 0) {
            var pad: [16]u8 = undefined;
            poly.update(&pad);
        }
        poly.update(ciphertext[0..plaintext.len]);
        if (ciphertext.len % 16 != 0) {
            var pad: [16]u8 = undefined;
            poly.update(&pad);
        }
        var len_block: [16]u8 = undefined;
        u.writeU64Le(len_block[0..8], aad.len);
        u.writeU64Le(len_block[8..16], plaintext.len);
        poly.update(&len_block);
        return poly.final();
    }

    pub fn decrypt(key: *const [32]u8, nonce: *const [12]u8, aad: []const u8, ciphertext: []const u8, tag: *const [16]u8, plaintext: []u8) bool {
        var chacha = ChaCha20.init(key, nonce, 0);
        var counter: u32 = 1;
        var poly_key: [32]u8 = undefined;
        var keystream: [64]u8 = undefined;
        chacha.keystreamBlock(counter, &keystream);
        counter += 1;
        u.copyBytes(&poly_key, keystream[0..32]);

        var poly = Poly1305.init(&poly_key);
        poly.update(aad);
        if (aad.len % 16 != 0) {
            var pad: [16]u8 = undefined;
            poly.update(&pad);
        }
        poly.update(ciphertext);
        if (ciphertext.len % 16 != 0) {
            var pad: [16]u8 = undefined;
            poly.update(&pad);
        }
        var len_block: [16]u8 = undefined;
        u.writeU64Le(len_block[0..8], aad.len);
        u.writeU64Le(len_block[8..16], ciphertext.len);
        poly.update(&len_block);
        const computed_tag = poly.final();

        if (!u.equalConstTime(&computed_tag, tag)) {
            return false;
        }

        counter = 1;
        chacha.keystreamBlock(counter, &keystream);
        counter += 1;
        var i: usize = 0;
        while (i + 64 <= ciphertext.len) : (i += 64) {
            chacha.keystreamBlock(counter, &keystream);
            counter += 1;
            var j: usize = 0;
            while (j < 64) : (j += 1) {
                plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
            }
        }
        if (i < ciphertext.len) {
            chacha.keystreamBlock(counter, &keystream);
            var j: usize = 0;
            while (j < ciphertext.len - i) : (j += 1) {
                plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
            }
        }
        return true;
    }
};

test "ChaCha20-Poly1305 encrypt/decrypt" {
    var key: [32]u8 = undefined;
    u.fillBytes(&key, 0x42);
    var nonce: [12]u8 = undefined;
    u.fillBytes(&nonce, 0x13);
    const plaintext = "hello world";
    var ciphertext: [64]u8 = undefined;
    var aad: [0]u8 = undefined;
    const tag = ChaCha20Poly1305.encrypt(&key, &nonce, &aad, plaintext, &ciphertext);
    var decrypted: [64]u8 = undefined;
    const ok = ChaCha20Poly1305.decrypt(&key, &nonce, &aad, ciphertext[0..plaintext.len], &tag, &decrypted);
    if (!ok) return error.TestUnexpectedResult;
}