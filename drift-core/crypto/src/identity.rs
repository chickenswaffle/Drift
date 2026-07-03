//! Identity + keypairs, matching `drift.crypto.Keypair` / `Identity`.
//!
//! A DRIFT identity is a scan X25519 keypair + a spend X25519 keypair. The
//! Ed25519 signing key is *derived* from the spend key via a domain-separated
//! HKDF (`drift-identity-sign-v1`) — there is no fourth stored key. RFC 8032 is
//! byte-identical across libraries, so the Ed25519 key `ed25519-dalek` builds
//! from that seed matches the one PyNaCl/`cryptography` build on the Python side.

use ed25519_dalek::{Signature, Signer, SigningKey};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::base58;
use crate::kdf::derive_message_key;

/// An X25519 keypair. `private_bytes` returns the raw stored scalar (clamping is
/// applied at DH time, exactly as `cryptography.X25519PrivateKey` does).
#[derive(Clone)]
pub struct Keypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl Keypair {
    pub fn from_private_bytes(priv_bytes: &[u8; 32]) -> Self {
        let secret = StaticSecret::from(*priv_bytes);
        let public = PublicKey::from(&secret);
        Keypair { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    pub fn private_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// X25519 ECDH → raw 32-byte shared secret.
    pub fn ecdh(&self, their_public: &[u8; 32]) -> [u8; 32] {
        self.secret
            .diffie_hellman(&PublicKey::from(*their_public))
            .to_bytes()
    }

    pub fn public_b58(&self) -> String {
        base58::encode(&self.public_bytes())
    }
}

/// A DRIFT identity: scan + spend keypairs, and the derived Ed25519 anchor.
#[derive(Clone)]
pub struct Identity {
    pub scan: Keypair,
    pub spend: Keypair,
}

impl Identity {
    pub fn from_private_bytes(scan_priv: &[u8; 32], spend_priv: &[u8; 32]) -> Self {
        Identity {
            scan: Keypair::from_private_bytes(scan_priv),
            spend: Keypair::from_private_bytes(spend_priv),
        }
    }

    /// `drift:<scan>.<spend>` (FMD off — the 2-segment default).
    pub fn contact_code(&self) -> String {
        format!(
            "drift:{}.{}",
            self.scan.public_b58(),
            self.spend.public_b58()
        )
    }

    /// The 32-byte Ed25519 seed: `HKDF(spend_priv, info="drift-identity-sign-v1")`.
    pub fn signing_seed(&self) -> [u8; 32] {
        derive_message_key(&self.spend.private_bytes(), None, b"drift-identity-sign-v1")
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.signing_seed())
    }

    /// The public Ed25519 verify key (the bundle's `identity_key`).
    pub fn verify_key_bytes(&self) -> [u8; 32] {
        self.signing_key().verifying_key().to_bytes()
    }

    /// Sign a message with the identity's Ed25519 key (used for beacons / X3DH
    /// signed prekeys).
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let sig: Signature = self.signing_key().sign(message);
        sig.to_bytes()
    }
}
