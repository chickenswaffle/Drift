//! Entropy source for the ratchet: ratchet keypairs and AEAD nonces.
//!
//! The Double Ratchet draws fresh randomness in two places — a new ratchet
//! keypair on each DH turn, and a fresh AEAD nonce per message. Threading those
//! through a trait lets production use the OS CSPRNG while tests inject the
//! *recorded tapes* from a vector, so a transcript replays bit-for-bit.

use rand_core::{OsRng, RngCore};

use crate::identity::Keypair;

pub trait Entropy {
    /// A fresh ratchet keypair (DH turn).
    fn ratchet_keypair(&mut self) -> Keypair;
    /// A fresh 24-byte XChaCha nonce.
    fn aead_nonce(&mut self) -> [u8; 24];
}

/// Production entropy: everything from the OS CSPRNG.
pub struct OsEntropy;

impl Entropy for OsEntropy {
    fn ratchet_keypair(&mut self) -> Keypair {
        let mut priv_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut priv_bytes);
        Keypair::from_private_bytes(&priv_bytes)
    }

    fn aead_nonce(&mut self) -> [u8; 24] {
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }
}

/// Deterministic entropy driven by recorded tapes (test-only replay of a
/// vector). Panics if a tape runs dry — a drained-tape assertion is exactly how
/// a replay proves it consumed the same amount of randomness as the reference.
pub struct TapeEntropy {
    pub keypairs: std::collections::VecDeque<[u8; 32]>,
    pub nonces: std::collections::VecDeque<[u8; 24]>,
}

impl TapeEntropy {
    pub fn new(keypairs: Vec<[u8; 32]>, nonces: Vec<[u8; 24]>) -> Self {
        TapeEntropy {
            keypairs: keypairs.into(),
            nonces: nonces.into(),
        }
    }

    pub fn drained(&self) -> bool {
        self.keypairs.is_empty() && self.nonces.is_empty()
    }
}

impl Entropy for TapeEntropy {
    fn ratchet_keypair(&mut self) -> Keypair {
        let priv_bytes = self
            .keypairs
            .pop_front()
            .expect("ratchet keypair tape drained");
        Keypair::from_private_bytes(&priv_bytes)
    }

    fn aead_nonce(&mut self) -> [u8; 24] {
        self.nonces.pop_front().expect("aead nonce tape drained")
    }
}
