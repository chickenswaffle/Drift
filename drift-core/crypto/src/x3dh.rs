//! X3DH asynchronous key agreement, matching `drift.crypto.x3dh`.
//!
//! IK (the DH identity) is the X25519 **spend** key; the signing identity is the
//! derived Ed25519 key. `SK = HKDF(F || DH1||DH2||DH3[||DH4])` with `F = 0xff*32`,
//! a 32-zero salt, and info `drift-x3dh-v1`. The signed prekey becomes the
//! initial Double Ratchet key.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use zeroize::Zeroize;

use crate::identity::{Identity, Keypair};
use crate::kdf::derive_message_key;
use crate::{Error, Result};

const F: [u8; 32] = [0xff; 32];
const HKDF_SALT: [u8; 32] = [0u8; 32];
const X3DH_INFO: &[u8] = b"drift-x3dh-v1";

/// The publishable bundle a sender fetches and runs X3DH against.
pub struct PreKeyBundle {
    pub identity_key: [u8; 32],    // Ed25519 verify key
    pub identity_dh_key: [u8; 32], // X25519 spend pub (IK_B)
    pub signed_prekey: [u8; 32],
    pub signed_prekey_sig: [u8; 64],
    pub signed_prekey_id: u32,
    pub one_time_prekey: Option<[u8; 32]>,
    pub one_time_prekey_id: Option<u32>,
}

/// The handshake header carried (sealed) on each bootstrap-chain message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X3DHHeader {
    pub ik_a: [u8; 32],
    pub ek_a: [u8; 32],
    pub signed_prekey_id: u32,
    pub one_time_prekey_id: Option<u32>,
}

impl X3DHHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 * 32 + 4 + 1 + 4);
        out.extend_from_slice(&self.ik_a);
        out.extend_from_slice(&self.ek_a);
        out.extend_from_slice(&self.signed_prekey_id.to_be_bytes());
        let flag = if self.one_time_prekey_id.is_some() {
            1u8
        } else {
            0u8
        };
        out.push(flag);
        out.extend_from_slice(&self.one_time_prekey_id.unwrap_or(0).to_be_bytes());
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<X3DHHeader> {
        let expected = 2 * 32 + 4 + 1 + 4;
        if raw.len() != expected {
            return Err(Error::X3dh("x3dh header wrong length"));
        }
        let mut ik_a = [0u8; 32];
        let mut ek_a = [0u8; 32];
        ik_a.copy_from_slice(&raw[..32]);
        ek_a.copy_from_slice(&raw[32..64]);
        let spk_id = u32::from_be_bytes(raw[64..68].try_into().unwrap());
        let otpk_flag = raw[68];
        let otpk_id = u32::from_be_bytes(raw[69..73].try_into().unwrap());
        Ok(X3DHHeader {
            ik_a,
            ek_a,
            signed_prekey_id: spk_id,
            one_time_prekey_id: if otpk_flag != 0 { Some(otpk_id) } else { None },
        })
    }
}

/// The local private prekey halves the receiver needs to answer a handshake.
pub struct PreKeyPrivates {
    pub signed_prekey: Keypair,
    pub signed_prekey_id: u32,
    /// `(id, keypair)` of unconsumed one-time prekeys.
    pub one_time: Vec<(u32, Keypair)>,
}

impl PreKeyPrivates {
    fn one_time_private(&self, id: u32) -> Result<&Keypair> {
        self.one_time
            .iter()
            .find(|(pid, _)| *pid == id)
            .map(|(_, kp)| kp)
            .ok_or(Error::X3dh("unknown or consumed one-time prekey"))
    }
}

fn kdf_master(dh_concat: &[u8]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32 + dh_concat.len());
    ikm.extend_from_slice(&F);
    ikm.extend_from_slice(dh_concat);
    let master = derive_message_key(&ikm, Some(&HKDF_SALT), X3DH_INFO);
    ikm.zeroize();
    master
}

/// Verify the Ed25519 signature on the bundle's signed prekey.
pub fn verify_prekey_bundle(bundle: &PreKeyBundle) -> bool {
    let vk = match VerifyingKey::from_bytes(&bundle.identity_key) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&bundle.signed_prekey_sig);
    vk.verify(&bundle.signed_prekey, &sig).is_ok()
}

/// Sender side. Verifies the bundle, uses the supplied single-use ephemeral
/// `EK_A`, computes DH1–DH4 and the master secret. (`ek` is passed in rather
/// than generated so a vector can be replayed; production draws it fresh and
/// discards the private half immediately.)
pub fn x3dh_send(
    my_identity: &Identity,
    their_bundle: &PreKeyBundle,
    ek: &Keypair,
) -> Result<(X3DHHeader, [u8; 32])> {
    if !verify_prekey_bundle(their_bundle) {
        return Err(Error::X3dh("prekey bundle signature invalid"));
    }
    let ik_a = &my_identity.spend;
    let mut dh1 = ik_a.ecdh(&their_bundle.signed_prekey);
    let mut dh2 = ek.ecdh(&their_bundle.identity_dh_key);
    let mut dh3 = ek.ecdh(&their_bundle.signed_prekey);
    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);
    dh1.zeroize();
    dh2.zeroize();
    dh3.zeroize();

    let mut otpk_id = None;
    if let Some(otpk) = their_bundle.one_time_prekey {
        let mut dh4 = ek.ecdh(&otpk);
        dh_concat.extend_from_slice(&dh4);
        dh4.zeroize();
        otpk_id = their_bundle.one_time_prekey_id;
    }

    let master = kdf_master(&dh_concat);
    dh_concat.zeroize();
    let header = X3DHHeader {
        ik_a: ik_a.public_bytes(),
        ek_a: ek.public_bytes(),
        signed_prekey_id: their_bundle.signed_prekey_id,
        one_time_prekey_id: otpk_id,
    };
    Ok((header, master))
}

/// Receiver side: recompute the same DH1–DH4 and derive the master secret. Does
/// not consume the OTPK (the session does that only after the message
/// authenticates — the H1 guarantee).
pub fn derive_master_secret_recv(
    my_identity: &Identity,
    privates: &PreKeyPrivates,
    header: &X3DHHeader,
) -> Result<[u8; 32]> {
    if header.signed_prekey_id != privates.signed_prekey_id {
        return Err(Error::X3dh("unknown signed prekey id"));
    }
    let spk = &privates.signed_prekey;
    let ik_b = &my_identity.spend;
    let mut dh1 = spk.ecdh(&header.ik_a);
    let mut dh2 = ik_b.ecdh(&header.ek_a);
    let mut dh3 = spk.ecdh(&header.ek_a);
    let mut dh_concat = Vec::new();
    dh_concat.extend_from_slice(&dh1);
    dh_concat.extend_from_slice(&dh2);
    dh_concat.extend_from_slice(&dh3);
    dh1.zeroize();
    dh2.zeroize();
    dh3.zeroize();

    if let Some(otpk_id) = header.one_time_prekey_id {
        let otpk = privates.one_time_private(otpk_id)?;
        let mut dh4 = otpk.ecdh(&header.ek_a);
        dh_concat.extend_from_slice(&dh4);
        dh4.zeroize();
    }

    let master = kdf_master(&dh_concat);
    dh_concat.zeroize();
    Ok(master)
}
