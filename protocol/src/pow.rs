//! SHA-256, and the proof of work built on it.
//!
//! # Why this is here and not a crate
//!
//! The client half of this protocol compiles to WebAssembly inside
//! `synx-core`, which has no dependencies at all - the whole point of that
//! crate is that it is a plain `cdylib` with a hand-written C ABI and no build
//! step. Pulling `sha2` in would add a dependency tree to the game's
//! simulation core so that a registration screen can hash sixty-five thousand
//! strings once.
//!
//! So the hash lives here, in the `no_std` crate both halves already share.
//! The server uses it for the same proof of work, which means there is exactly
//! one implementation and the two ends cannot disagree about what a valid
//! solution is. It is checked against the NIST vectors below, and the server
//! additionally checks it against `sha2` - so "our SHA-256 is subtly wrong"
//! fails a test rather than becoming a registration nobody can complete.
//!
//! This is NOT a general-purpose crypto primitive and should not be used as
//! one. It hashes a short, server-issued challenge and a counter. The thing
//! that actually needs to be unforgeable - the session token - is an HMAC the
//! server computes with an audited implementation, and the client never
//! verifies it.
//!
//! # What the proof of work buys
//!
//! Not security: a determined attacker can spend the CPU. What it buys is
//! COST. Registering an identity stops being free, so churning through them to
//! evade a kick scales with how hard somebody is willing to work, which is the
//! only lever available when every fact a client reports about itself can be
//! made up. Sixteen bits is about 65,000 hashes: a few milliseconds in
//! WebAssembly, and a real bill for anybody wanting ten thousand identities.

/// The standard round constants.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// An incremental SHA-256.
///
/// Incremental rather than one-shot because the proof-of-work loop hashes
/// `challenge || ':' || nonce` sixty-five thousand times with only the last few
/// bytes changing, and being able to keep the message in one buffer rather
/// than rebuilding it is most of the difference in how long that takes.
pub struct Sha256 {
    h: [u32; 8],
    block: [u8; 64],
    used: usize,
    len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256::new()
    }
}

impl Sha256 {
    pub fn new() -> Sha256 {
        Sha256 { h: INIT, block: [0u8; 64], used: 0, len: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.used > 0 {
            let take = (64 - self.used).min(data.len());
            self.block[self.used..self.used + take].copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used == 64 {
                let b = self.block;
                self.compress(&b);
                self.used = 0;
            }
        }
        while data.len() >= 64 {
            let mut b = [0u8; 64];
            b.copy_from_slice(&data[..64]);
            self.compress(&b);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.block[..data.len()].copy_from_slice(data);
            self.used = data.len();
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bits = self.len.wrapping_mul(8);
        self.update(&[0x80]);
        // pad to 56 mod 64, then the length
        while self.used != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        debug_assert_eq!(self.used, 0);
        let mut out = [0u8; 32];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = self.h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (i, v) in [a, b, c, d, e, f, g, hh].into_iter().enumerate() {
            self.h[i] = self.h[i].wrapping_add(v);
        }
    }
}

/// One-shot.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finish()
}

/// Leading zero bits of a digest.
pub fn leading_zeros(digest: &[u8]) -> u32 {
    let mut n = 0;
    for b in digest {
        n += b.leading_zeros();
        if *b != 0 {
            break;
        }
    }
    n
}

/// Does `nonce` solve `challenge` at `bits`?
///
/// The message is `challenge || ':' || nonce`, which is what the server checks
/// and therefore what this must produce. Written once, here, rather than twice.
pub fn solves(challenge: &[u8], nonce: &[u8], bits: u32) -> bool {
    let mut h = Sha256::new();
    h.update(challenge);
    h.update(b":");
    h.update(nonce);
    leading_zeros(&h.finish()) >= bits
}

/// Search for a nonce, up to `limit` attempts. Returns the nonce as a decimal
/// counter, or `None` if the budget ran out.
///
/// The counter is decimal ASCII rather than a raw integer because it travels
/// through JSON, and a decimal string is the one encoding both ends agree on
/// without a discussion about endianness.
pub fn solve(challenge: &[u8], bits: u32, start: u64, limit: u64) -> Option<u64> {
    if bits == 0 {
        return Some(start);
    }
    let mut buf = [0u8; 24];
    for i in 0..limit {
        let n = start.wrapping_add(i);
        let text = decimal(n, &mut buf);
        if solves(challenge, text, bits) {
            return Some(n);
        }
    }
    None
}

/// Write `n` as decimal ASCII into `buf`, returning the slice used.
fn decimal(mut n: u64, buf: &mut [u8; 24]) -> &[u8] {
    if n == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[i..]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8]) -> alloc_string {
        let mut s = alloc_string::new();
        for b in d {
            s.push_hex(*b);
        }
        s
    }

    /// A tiny fixed-size hex buffer, so these tests do not need `alloc`.
    struct alloc_string {
        buf: [u8; 64],
        n: usize,
    }

    impl alloc_string {
        fn new() -> Self {
            alloc_string { buf: [0; 64], n: 0 }
        }
        fn push_hex(&mut self, b: u8) {
            const H: &[u8; 16] = b"0123456789abcdef";
            self.buf[self.n] = H[(b >> 4) as usize];
            self.buf[self.n + 1] = H[(b & 15) as usize];
            self.n += 2;
        }
        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.n]).unwrap()
        }
    }

    /// The published vectors. If this fails, nothing else in the file matters.
    #[test]
    fn matches_the_published_vectors() {
        assert_eq!(
            hex(&sha256(b"")).as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")).as_str(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).as_str(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    /// Every buffering path: a block boundary is where an incremental hash
    /// goes wrong, and it goes wrong silently.
    #[test]
    fn incremental_agrees_with_one_shot_at_every_length() {
        let data: [u8; 200] = core::array::from_fn(|i| (i * 7 + 3) as u8);
        for len in 0..data.len() {
            let one = sha256(&data[..len]);
            for chunk in [1usize, 7, 31, 55, 56, 57, 63, 64, 65, 128] {
                let mut h = Sha256::new();
                let mut at = 0;
                while at < len {
                    let take = chunk.min(len - at);
                    h.update(&data[at..at + take]);
                    at += take;
                }
                assert_eq!(h.finish(), one, "len {len} in chunks of {chunk}");
            }
        }
    }

    #[test]
    fn decimal_is_decimal() {
        let mut b = [0u8; 24];
        assert_eq!(decimal(0, &mut b), b"0");
        assert_eq!(decimal(7, &mut b), b"7");
        assert_eq!(decimal(1234567890, &mut b), b"1234567890");
        assert_eq!(decimal(u64::MAX, &mut b), b"18446744073709551615");
    }

    #[test]
    fn a_solution_solves_and_a_wrong_one_does_not() {
        let challenge = b"a-server-issued-challenge";
        let n = solve(challenge, 12, 0, 1_000_000).expect("12 bits is always findable");
        let mut buf = [0u8; 24];
        let text = decimal(n, &mut buf);
        assert!(solves(challenge, text, 12));
        // ...and it does not solve a different challenge
        assert!(!solves(b"a-different-challenge", text, 20));
        // zero bits is free by definition
        assert_eq!(solve(challenge, 0, 42, 1), Some(42));
        // and an impossible budget gives up rather than looping
        assert_eq!(solve(challenge, 32, 0, 64), None);
    }

    #[test]
    fn leading_zeros_counts_bits_not_bytes() {
        assert_eq!(leading_zeros(&[0xff]), 0);
        assert_eq!(leading_zeros(&[0x0f]), 4);
        assert_eq!(leading_zeros(&[0x00, 0x0f]), 12);
        assert_eq!(leading_zeros(&[0x00, 0x00, 0x80]), 16);
    }
}
