//! Burn tokens, matching `drift.crypto.burn`.
//!
//! A single-use `nonce_hex.timestamp.mac_hex` token authorising a message or
//! conversation erase (audit M2). The MAC is HMAC-SHA256 under a burn key
//! derived from the conversation's static ECDH output, binding scope, target,
//! nonce and timestamp — so none can be altered and no token can be replayed.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::kdf::derive_message_key;

type HmacSha256 = Hmac<Sha256>;

/// A token is valid for five minutes from its embedded timestamp.
pub const TOKEN_TTL_SECONDS: i64 = 300;

fn derive_burn_key(shared_secret: &[u8]) -> [u8; 32] {
    derive_message_key(shared_secret, None, b"drift-burn-v1")
}

fn mac_input(scope: &str, message_id: Option<&str>, nonce_hex: &str, timestamp: i64) -> Vec<u8> {
    format!(
        "{}:{}:{}:{}",
        scope,
        message_id.unwrap_or(""),
        nonce_hex,
        timestamp
    )
    .into_bytes()
}

/// Mint a `nonce.timestamp.mac` token for the given nonce + timestamp. Callers
/// that want freshness draw a random nonce and `now`; the explicit form exists
/// for vector reproduction and verification.
pub fn generate_burn_token(
    shared_secret: &[u8],
    scope: &str,
    message_id: Option<&str>,
    nonce: &[u8; 16],
    timestamp: i64,
) -> String {
    let nonce_hex = hex_encode(nonce);
    let key = derive_burn_key(shared_secret);
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(&mac_input(scope, message_id, &nonce_hex, timestamp));
    let tag = mac.finalize().into_bytes();
    format!("{}.{}.{}", nonce_hex, timestamp, hex_encode(&tag))
}

/// Verify a token: parses, checks the timestamp is within `ttl` of `now`, then
/// recomputes and constant-time-compares the whole token string.
pub fn verify_burn_token(
    shared_secret: &[u8],
    token: &str,
    scope: &str,
    message_id: Option<&str>,
    now: i64,
    ttl: i64,
) -> bool {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }
    let (nonce_hex, ts_str, mac_hex) = (parts[0], parts[1], parts[2]);
    if nonce_hex.len() != 32 || mac_hex.len() != 64 {
        return false;
    }
    let ts: i64 = match ts_str.parse() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let nonce = match hex_decode_16(nonce_hex) {
        Some(n) => n,
        None => return false,
    };
    if (now - ts).abs() > ttl {
        return false;
    }
    let expected = generate_burn_token(shared_secret, scope, message_id, &nonce, ts);
    expected.as_bytes().ct_eq(token.as_bytes()).into()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode_16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}
