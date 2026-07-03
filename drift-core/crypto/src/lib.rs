//! `drift-crypto` — the Rust port of DRIFT's `drift.crypto` reference package
//! (Phase 13a). Every construction here mirrors the Python module of the same
//! name and is pinned to the shared vectors in `../../tests/vectors` (see the
//! `tests/` directory). The iron rule holds: this crate *composes* vetted
//! crates (dalek, RustCrypto, argon2) and never hand-rolls a primitive.
//!
//! Parity scope: base58, HKDF derivations, the XChaCha20-Poly1305 envelope,
//! identity keys / Ed25519 / X25519 ECDH, X3DH, the Double Ratchet, sealed
//! sender, burn tokens, the Argon2id panic vault, **stealth addressing, and
//! FMD** — every construction pinned to the shared vectors. Stealth and FMD need
//! libsodium's exact ed25519 group ops (`crypto_core_ed25519_from_uniform` /
//! Elligator 2, point add, scalar arithmetic), which have no bit-identical
//! pure-Rust equivalent, so [`sodium`] binds the same C library the Python
//! reference uses through PyNaCl — composing the vetted primitive, not
//! reimplementing curve math.

pub mod aead;
pub mod base58;
pub mod burn;
pub mod entropy;
pub mod fmd;
pub mod identity;
pub mod kdf;
pub mod ratchet;
pub mod sealed;
pub mod sodium;
pub mod stealth;
pub mod vault;
pub mod x3dh;

/// Errors that cross the crate boundary. Kept small and explicit — a decrypt
/// failure is `InvalidTag`, exactly as the Python side lets `InvalidTag`
/// propagate rather than swallowing it (the iron rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// AEAD authentication failed — tampered or wrong-key ciphertext.
    InvalidTag,
    /// A wire/blob structure was malformed (bad length, bad framing).
    Malformed(&'static str),
    /// A ratchet protocol violation (e.g. too many skipped messages).
    Ratchet(&'static str),
    /// An X3DH handshake problem (bad signature, unknown/consumed prekey).
    X3dh(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidTag => write!(f, "InvalidTag"),
            Error::Malformed(m) => write!(f, "malformed: {m}"),
            Error::Ratchet(m) => write!(f, "ratchet: {m}"),
            Error::X3dh(m) => write!(f, "x3dh: {m}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

pub use identity::{Identity, Keypair};
