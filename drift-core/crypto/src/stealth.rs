//! Rotating stealth addresses, matching `drift.crypto.stealth`.
//!
//! Monero-style: `A_once = B + SHA256(s_scan)·G` where `B = from_uniform(
//! SHA256(tag || spend_pub))`. Detection uses the scan key; decryption folds a
//! second DH against the spend key into the message key (audit M1), so a
//! scan-only delegate can filter mail but not read it. All group ops go through
//! libsodium (`crate::sodium`) so addresses match the reference byte-for-byte.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::identity::Keypair;
use crate::kdf::derive_message_key;
use crate::sodium;

const SPEND_POINT_TAG: &[u8] = b"drift-stealth-v1-spend-point";
const MSG_KEY_INFO: &[u8] = b"drift-v2-msg";

fn ecdh(private_bytes: &[u8; 32], public_bytes: &[u8; 32]) -> [u8; 32] {
    Keypair::from_private_bytes(private_bytes).ecdh(public_bytes)
}

/// Map a recipient's X25519 spend pub to the fixed ed25519 point `B`.
fn spend_point(spend_pub: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SPEND_POINT_TAG);
    hasher.update(spend_pub);
    let seed: [u8; 32] = hasher.finalize().into();
    sodium::ed25519_from_uniform(&seed)
}

/// `A_once = B + SHA256(s)·G` for a given ECDH secret `s`.
fn address_from_secret(shared_secret: &[u8; 32], spend_pub: &[u8; 32]) -> [u8; 32] {
    let digest: [u8; 32] = Sha256::digest(shared_secret).into();
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&digest);
    let scalar = sodium::scalar_reduce(&wide);
    let h_g = sodium::base_mul_noclamp(&scalar);
    sodium::point_add(&spend_point(spend_pub), &h_g)
}

/// Sender side: `(one_time_address, message_key)`. The address is derived from
/// the scan DH alone (so a scan-only receiver detects it); the message key also
/// folds in the spend DH, so only the private spend key decrypts.
pub fn derive_one_time_address(
    ephemeral_priv: &[u8; 32],
    recipient_scan_pub: &[u8; 32],
    recipient_spend_pub: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let s_scan = ecdh(ephemeral_priv, recipient_scan_pub);
    let s_spend = ecdh(ephemeral_priv, recipient_spend_pub);
    let one_time_addr = address_from_secret(&s_scan, recipient_spend_pub);
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&s_scan);
    ikm[32..].copy_from_slice(&s_spend);
    let message_key = derive_message_key(&ikm, None, MSG_KEY_INFO);
    (one_time_addr, message_key)
}

/// A confirmed scan-key-only detection. Insufficient to decrypt: the message key
/// additionally needs the private spend key (see [`derive_message_key_with_spend`]).
pub struct ScanResult {
    pub ephemeral_pub: [u8; 32],
    pub scan_secret: [u8; 32],
}

/// Receiver step 1 (scan key): is this envelope addressed to us? Constant-time
/// address compare so scanning leaks nothing via timing.
pub fn scan_for_message(
    ephemeral_pub: &[u8; 32],
    one_time_addr: &[u8; 32],
    my_scan_priv: &[u8; 32],
    my_spend_pub: &[u8; 32],
) -> Option<ScanResult> {
    let s_scan = ecdh(my_scan_priv, ephemeral_pub);
    let candidate = address_from_secret(&s_scan, my_spend_pub);
    if candidate.ct_eq(one_time_addr).into() {
        Some(ScanResult {
            ephemeral_pub: *ephemeral_pub,
            scan_secret: s_scan,
        })
    } else {
        None
    }
}

/// Receiver step 2 (spend key required): turn a [`ScanResult`] into the message
/// key. `msg_key = HKDF(scan_secret || ECDH(spend_priv, R), "drift-v2-msg")`.
pub fn derive_message_key_with_spend(
    scan_result: &ScanResult,
    my_spend_priv: &[u8; 32],
) -> [u8; 32] {
    let s_spend = ecdh(my_spend_priv, &scan_result.ephemeral_pub);
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&scan_result.scan_secret);
    ikm[32..].copy_from_slice(&s_spend);
    derive_message_key(&ikm, None, MSG_KEY_INFO)
}
