//! HKDF-SHA256 derivations, matching `drift.crypto.derive_message_key` and the
//! two ratchet KDFs. `cryptography`'s `HKDF(salt=None)` uses a hash-length block
//! of zero salt (RFC 5869 §2.2); `hkdf::Hkdf::new(None, ..)` does the same, so
//! the outputs are identical.

use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF-SHA256 → 32 bytes. `salt = None` matches the reference default (a
/// zero-filled salt of the hash output length).
pub fn derive_message_key(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 is a valid HKDF length");
    okm
}

/// HKDF-SHA256 → 64 bytes, split into two 32-byte halves (the ratchet KDFs).
fn derive64(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; 64];
    hk.expand(info, &mut okm)
        .expect("64 is a valid HKDF length");
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&okm[..32]);
    b.copy_from_slice(&okm[32..]);
    (a, b)
}

/// Root KDF (`_kdf_rk`): salt = root key, IKM = DH output → (new_root, chain).
pub fn kdf_rk(root_key: &[u8], dh_out: &[u8]) -> ([u8; 32], [u8; 32]) {
    derive64(dh_out, Some(root_key), b"drift-ratchet-v1-rk")
}

/// Chain KDF (`_kdf_ck`): one HKDF step over the chain key → (next_ck, msg_key).
pub fn kdf_ck(chain_key: &[u8]) -> ([u8; 32], [u8; 32]) {
    derive64(chain_key, None, b"drift-ratchet-v1-ck")
}
