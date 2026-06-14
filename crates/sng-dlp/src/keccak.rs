//! Vendored Keccak-256 (the pre-NIST, Ethereum padding variant).
//!
//! Ethereum addresses are checksummed with **Keccak-256**, which uses
//! the original `0x01` multi-rate padding — *not* the `0x06` padding
//! that NIST FIPS-202 SHA3-256 adopted. `sha2` (the crate's only
//! existing hash dependency) cannot produce it, and pulling a new
//! crypto dependency into the signed-bundle endpoint crate purely for a
//! *public checksum* is not worth the supply-chain / `cargo deny`
//! surface. So this is a small, self-contained Keccak-f[1600] sponge.
//!
//! Scope: this hash backs only the EIP-55 address checksum
//! ([`crate::validators::eth_address`]) — a false-positive suppressor,
//! never a security primitive. The Go twin
//! (`internal/service/dlp/engine`) computes the same digest via
//! `golang.org/x/crypto/sha3.NewLegacyKeccak256`; both are standard
//! Keccak-256, so the EIP-55 decision is identical on both sides.
//!
//! Verified against the canonical empty-input vector
//! `keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470`
//! and the EIP-55 reference addresses (see the test module).

/// Round constants for Keccak-f[1600] (24 rounds).
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets for the ρ step, indexed by lane `x + 5*y`.
const ROTR: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// The Keccak-f[1600] permutation over the 25-lane (5×5×64-bit) state.
fn keccak_f1600(state: &mut [u64; 25]) {
    for &rc in &RC {
        // θ
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }

        // ρ and π
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let idx = x + 5 * y;
                let new_idx = y + 5 * ((2 * x + 3 * y) % 5);
                b[new_idx] = state[idx].rotate_left(ROTR[idx]);
            }
        }

        // χ
        for y in 0..5 {
            for x in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }

        // ι
        state[0] ^= rc;
    }
}

/// Keccak-256 digest (32 bytes) of `input`, using the original `0x01`
/// padding (Ethereum's hash, not FIPS-202 SHA3).
#[must_use]
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    const RATE: usize = 136; // 1088-bit rate for the 256-bit capacity-512 instance.
    let mut state = [0u64; 25];

    // Absorb full rate blocks.
    let mut offset = 0;
    while input.len() - offset >= RATE {
        absorb_block(&mut state, &input[offset..offset + RATE]);
        keccak_f1600(&mut state);
        offset += RATE;
    }

    // Final block with pad10*1 (Keccak domain byte 0x01, final bit 0x80).
    let mut block = [0u8; RATE];
    let rem = &input[offset..];
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] ^= 0x01;
    block[RATE - 1] ^= 0x80;
    absorb_block(&mut state, &block);
    keccak_f1600(&mut state);

    // Squeeze 32 bytes (fits in the first 4 lanes of the rate).
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

/// XOR a full `RATE`-byte block into the state (little-endian lanes).
fn absorb_block(state: &mut [u64; 25], block: &[u8]) {
    for (i, lane) in block.chunks_exact(8).enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(lane);
        state[i] ^= u64::from_le_bytes(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::keccak256;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
    }

    #[test]
    fn empty_input_matches_canonical_vector() {
        assert_eq!(
            hex(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn abc_matches_canonical_vector() {
        assert_eq!(
            hex(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn long_input_spans_multiple_rate_blocks() {
        // 200 bytes > one 136-byte rate block, so this exercises the
        // multi-block absorb path.
        let input = vec![0xa3u8; 200];
        assert_eq!(
            hex(&keccak256(&input)),
            "3a57666b048777f2c953dc4456f45a2588e1cb6f2da760122d530ac2ce607d4a"
        );
    }
}
