//! XChaCha20-Poly1305 AEAD envelope, matching `drift.crypto.encrypt`/`decrypt`.
//!
//! Wire format: `nonce (24 bytes) || ciphertext+tag`. The nonce is 24 bytes
//! (XChaCha), so random generation is collision-safe. `decrypt` returns
//! `Error::InvalidTag` on any authentication failure — the caller must let it
//! propagate (the iron rule), never treat a tampered message as empty.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::{Error, Result};

pub const NONCE_SIZE: usize = 24;

/// Encrypt with a caller-supplied nonce (used for deterministic vector replay).
/// Production code should draw the nonce from the OS CSPRNG via [`encrypt`].
pub fn encrypt_with_nonce(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .expect("XChaCha20-Poly1305 encryption is infallible for valid inputs");
    let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    out
}

/// Encrypt with a fresh random 24-byte nonce.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8], associated_data: &[u8]) -> Vec<u8> {
    use rand_core::{OsRng, RngCore};
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    encrypt_with_nonce(key, &nonce, plaintext, associated_data)
}

/// Decrypt a `nonce || ct+tag` payload. `Error::InvalidTag` on any failure.
pub fn decrypt(key: &[u8; 32], data: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_SIZE {
        return Err(Error::Malformed("aead payload shorter than nonce"));
    }
    let (nonce, ct) = data.split_at(NONCE_SIZE);
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: associated_data,
            },
        )
        .map_err(|_| Error::InvalidTag)
}
