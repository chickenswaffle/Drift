//! Fuzzy Message Detection (FMD2), matching `drift.crypto.fmd`.
//!
//! A detection keypair of `n` ed25519 sub-keys (native false-positive rate
//! `2^-n`). A sender attaches a per-message flag; a detector (or a downgraded
//! relay key) tests it. This crate ports key derivation and the test path (all
//! the vectors need); flag *generation* needs a CSPRNG and is not part of the
//! deterministic vector contract. Group ops go through libsodium (`crate::sodium`).

use sha2::{Digest, Sha256, Sha512};

use crate::sodium;

const H_BIT_TAG: &[u8] = b"drift-fmd-v1-bit";
const H_SCALAR_TAG: &[u8] = b"drift-fmd-v1-scalar";
const SUBKEY_DERIVE_TAG: &[u8] = b"drift-fmd-subkey-v1";

/// An FMD detection keypair: parallel lists of secret scalars and public points.
pub struct FmdKeypair {
    pub secret_keys: Vec<[u8; 32]>,
    pub public_keys: Vec<[u8; 32]>,
}

/// Deterministically derive an `n`-sub-key detection keypair from `seed`
/// (`x_i = scalar_reduce(SHA512(tag || seed || i)); X_i = x_i·B`). Sub-keys are
/// indexed, so a coarser key is a prefix of a finer one.
pub fn derive_fmd_key(seed: &[u8], n: usize) -> FmdKeypair {
    let mut secret_keys = Vec::with_capacity(n);
    let mut public_keys = Vec::with_capacity(n);
    for i in 0..n {
        let mut hasher = Sha512::new();
        hasher.update(SUBKEY_DERIVE_TAG);
        hasher.update(seed);
        hasher.update((i as u32).to_be_bytes());
        let wide: [u8; 64] = hasher.finalize().into();
        let x = sodium::scalar_reduce(&wide);
        public_keys.push(sodium::base_mul_noclamp(&x));
        secret_keys.push(x);
    }
    FmdKeypair {
        secret_keys,
        public_keys,
    }
}

fn h_bit(u: &[u8; 32], shared: &[u8; 32], w: &[u8; 32]) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(H_BIT_TAG);
    hasher.update(u);
    hasher.update(shared);
    hasher.update(w);
    hasher.finalize()[0] & 1
}

fn h_scalar(message: &[u8], u: &[u8; 32], flag_bits: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(H_SCALAR_TAG);
    hasher.update(u);
    hasher.update(flag_bits);
    hasher.update(message);
    let wide: [u8; 64] = hasher.finalize().into();
    sodium::scalar_reduce(&wide)
}

/// Test whether `flag` might be addressed to `key` (checking each of its
/// sub-keys). Always true for the genuine recipient; true with probability
/// `2^-k` for anyone else, where `k = key.secret_keys.len()`.
pub fn fmd_test(flag: &[u8], key: &FmdKeypair, message: &[u8]) -> bool {
    let k = key.secret_keys.len();
    if k == 0 {
        return false;
    }
    if flag.len() < 64 + k.div_ceil(8) {
        return false;
    }
    let u: [u8; 32] = flag[..32].try_into().unwrap();
    let y: [u8; 32] = flag[32..64].try_into().unwrap();
    let flag_bits = &flag[64..];

    let m = h_scalar(message, &u, flag_bits);
    // Reconstruct the sender's w = m·B + y·u.
    let m_b = sodium::base_mul_noclamp(&m);
    let y_u = match sodium::point_mul_noclamp(&y, &u) {
        Some(p) => p,
        None => return false,
    };
    let w = sodium::point_add(&m_b, &y_u);

    for (i, x_priv) in key.secret_keys.iter().enumerate() {
        let c_i = (flag_bits[i >> 3] >> (i & 7)) & 1;
        let shared = match sodium::point_mul_noclamp(x_priv, &u) {
            Some(p) => p,
            None => return false,
        };
        let k_i = h_bit(&u, &shared, &w);
        if (k_i ^ c_i) != 1 {
            return false;
        }
    }
    true
}
