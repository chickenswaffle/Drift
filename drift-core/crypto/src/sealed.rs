//! Sealed sender, matching `drift.crypto.sealed`.
//!
//! Folds everything except the recipient's one-time address into one opaque
//! blob: `R(32) || u16(len) || sealed_header || ratchet_ciphertext`. The header
//! is sealed under `HKDF(stealth_key, "drift-sealed-sender-v1")` with the
//! recipient one-time address bound as AEAD associated data.

use zeroize::Zeroize;

use crate::aead::{decrypt, encrypt_with_nonce};
use crate::kdf::derive_message_key;
use crate::{Error, Result};

const SEAL_INFO: &[u8] = b"drift-sealed-sender-v1";
const EPK_LEN: usize = 32;

fn seal_key(stealth_key: &[u8]) -> [u8; 32] {
    derive_message_key(stealth_key, None, SEAL_INFO)
}

/// Build the opaque sealed-sender blob. `nonce` is supplied so a vector can be
/// reproduced; production draws it from the OS CSPRNG (see [`seal`]).
pub fn seal_with_nonce(
    stealth_key: &[u8],
    nonce: &[u8; 24],
    ephemeral_pub: &[u8; 32],
    ratchet_header: &[u8],
    ratchet_ciphertext: &[u8],
    address: &[u8],
) -> Vec<u8> {
    let mut key = seal_key(stealth_key);
    let sealed_header = encrypt_with_nonce(&key, nonce, ratchet_header, address);
    key.zeroize();
    let mut out = Vec::with_capacity(EPK_LEN + 2 + sealed_header.len() + ratchet_ciphertext.len());
    out.extend_from_slice(ephemeral_pub);
    out.extend_from_slice(&(sealed_header.len() as u16).to_be_bytes());
    out.extend_from_slice(&sealed_header);
    out.extend_from_slice(ratchet_ciphertext);
    out
}

/// Build a sealed blob with a fresh random AEAD nonce.
pub fn seal(
    stealth_key: &[u8],
    ephemeral_pub: &[u8; 32],
    ratchet_header: &[u8],
    ratchet_ciphertext: &[u8],
    address: &[u8],
) -> Vec<u8> {
    use rand_core::{OsRng, RngCore};
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    seal_with_nonce(
        stealth_key,
        &nonce,
        ephemeral_pub,
        ratchet_header,
        ratchet_ciphertext,
        address,
    )
}

/// Split a blob into `(ephemeral_pub, sealed_header, ratchet_ciphertext)`. Pure
/// framing — no key needed (the recipient needs R out before deriving anything).
pub fn parse(blob: &[u8]) -> Result<([u8; 32], &[u8], &[u8])> {
    if blob.len() < EPK_LEN + 2 {
        return Err(Error::Malformed("sealed blob too short for header"));
    }
    let mut ephemeral_pub = [0u8; 32];
    ephemeral_pub.copy_from_slice(&blob[..EPK_LEN]);
    let slen = u16::from_be_bytes([blob[EPK_LEN], blob[EPK_LEN + 1]]) as usize;
    let start = EPK_LEN + 2;
    let end = start + slen;
    if end > blob.len() {
        return Err(Error::Malformed("sealed blob truncated"));
    }
    Ok((ephemeral_pub, &blob[start..end], &blob[end..]))
}

/// Decrypt a sealed ratchet header. `Error::InvalidTag` on tampering.
pub fn open_header(stealth_key: &[u8], sealed_header: &[u8], address: &[u8]) -> Result<Vec<u8>> {
    let mut key = seal_key(stealth_key);
    let out = decrypt(&key, sealed_header, address);
    key.zeroize();
    out
}
