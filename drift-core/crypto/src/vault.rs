//! The Argon2id panic/duress vault, matching `drift.crypto.panic`.
//!
//! A two-slot vault: `MAGIC || version || params || slot1 || slot2`, each slot
//! `salt(16) || nonce(24) || ct+tag`. Both slots are always derived and tried in
//! fixed order with no early return, so real / duress / wrong passphrases do
//! identical work. This crate ports the read path (`derive_unlock_key`,
//! `try_unlock`); the two-slot *layout* is the reference's and is verified by
//! opening committed vault blobs.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use crate::aead::decrypt;

const MAGIC: &[u8] = b"DRIFTVLT";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const PAYLOAD_SIZE: usize = 16384;
const LEN_PREFIX: usize = 4;
/// salt || nonce(24) || payload || poly1305 tag(16).
const SLOT_SIZE: usize = SALT_LEN + 24 + PAYLOAD_SIZE + 16;

/// Argon2id cost parameters (stored non-secret in the vault header).
#[derive(Clone, Copy)]
pub struct KdfParams {
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
}

/// Derive the 32-byte unlock key from a passphrase with Argon2id.
pub fn derive_unlock_key(passphrase: &str, salt: &[u8], params: &KdfParams) -> [u8; 32] {
    let p = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(32),
    )
    .expect("valid Argon2 params");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .expect("Argon2id hashing succeeds for valid params");
    out
}

fn unpad(block: &[u8]) -> Option<Vec<u8>> {
    if block.len() < LEN_PREFIX {
        return None;
    }
    let n = u32::from_be_bytes(block[..LEN_PREFIX].try_into().unwrap()) as usize;
    if n > PAYLOAD_SIZE - LEN_PREFIX {
        return None;
    }
    Some(block[LEN_PREFIX..LEN_PREFIX + n].to_vec())
}

fn open_slot(passphrase: &str, slot: &[u8], params: &KdfParams) -> Option<Vec<u8>> {
    let (salt, sealed) = slot.split_at(SALT_LEN);
    let mut key = derive_unlock_key(passphrase, salt, params);
    let decrypted = decrypt(&key, sealed, b"");
    key.zeroize();
    let mut padded = decrypted.ok()?;
    let out = unpad(&padded);
    padded.zeroize();
    out
}

fn parse_vault(vault: &[u8]) -> Option<(KdfParams, &[u8], &[u8])> {
    if vault.len() < MAGIC.len() + 1 + 12 + 2 * SLOT_SIZE {
        return None;
    }
    if &vault[..MAGIC.len()] != MAGIC {
        return None;
    }
    let mut off = MAGIC.len();
    if vault[off] != VERSION {
        return None;
    }
    off += 1;
    let time_cost = u32::from_be_bytes(vault[off..off + 4].try_into().unwrap());
    let memory_cost = u32::from_be_bytes(vault[off + 4..off + 8].try_into().unwrap());
    let parallelism = u32::from_be_bytes(vault[off + 8..off + 12].try_into().unwrap());
    off += 12;
    let slot1 = &vault[off..off + SLOT_SIZE];
    let slot2 = &vault[off + SLOT_SIZE..off + 2 * SLOT_SIZE];
    Some((
        KdfParams {
            time_cost,
            memory_cost,
            parallelism,
        },
        slot1,
        slot2,
    ))
}

/// Open a vault with a passphrase, returning the payload of whichever slot it
/// unlocks (or `None`). Both slots are always derived and tried — constant work.
pub fn try_unlock(vault: &[u8], passphrase: &str) -> Option<Vec<u8>> {
    let (params, slot1, slot2) = parse_vault(vault)?;
    let r1 = open_slot(passphrase, slot1, &params);
    let r2 = open_slot(passphrase, slot2, &params);
    r1.or(r2)
}
