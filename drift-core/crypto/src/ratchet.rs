//! The Signal Double Ratchet, matching `drift.crypto.ratchet`.
//!
//! Forward secrecy + post-compromise security over the AEAD/KDF building blocks.
//! The decrypt path is *transactional* (audit H1): it runs on a snapshot and
//! commits back to the live state only after the message authenticates, so a
//! forged header naming a new DH key can drive the trial DH-ratchet without ever
//! corrupting a live session. `Error::InvalidTag` always propagates.

use std::collections::HashMap;

use crate::aead::{decrypt, encrypt_with_nonce};
use crate::entropy::Entropy;
use crate::identity::Keypair;
use crate::kdf::{derive_message_key, kdf_ck, kdf_rk};
use crate::{Error, Result};

/// Cap on skipped-and-cached message keys within a chain (flood bound).
pub const MAX_SKIP: u32 = 1000;

/// Domain separation for the bootstrap forward-secrecy secret (audit H3).
const FS_BOOTSTRAP_INFO: &[u8] = b"drift-ratchet-v1-fs-bootstrap";

const DH_PUB_LEN: usize = 32;
const COUNTER_LEN: usize = 4;
const HEADER_LEN: usize = DH_PUB_LEN + 2 * COUNTER_LEN;

/// Per-message ratchet header: `dh(32) || pn(4 BE) || n(4 BE)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub dh: [u8; 32],
    pub pn: u32,
    pub n: u32,
}

impl Header {
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..DH_PUB_LEN].copy_from_slice(&self.dh);
        out[DH_PUB_LEN..DH_PUB_LEN + COUNTER_LEN].copy_from_slice(&self.pn.to_be_bytes());
        out[DH_PUB_LEN + COUNTER_LEN..].copy_from_slice(&self.n.to_be_bytes());
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Header> {
        if raw.len() != HEADER_LEN {
            return Err(Error::Malformed("ratchet header wrong length"));
        }
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&raw[..DH_PUB_LEN]);
        let pn = u32::from_be_bytes(
            raw[DH_PUB_LEN..DH_PUB_LEN + COUNTER_LEN]
                .try_into()
                .unwrap(),
        );
        let n = u32::from_be_bytes(raw[DH_PUB_LEN + COUNTER_LEN..].try_into().unwrap());
        Ok(Header { dh, pn, n })
    }
}

/// One party's full Double Ratchet state.
#[derive(Clone)]
pub struct RatchetState {
    pub root_key: [u8; 32],
    pub sending_chain_key: Option<[u8; 32]>,
    pub receiving_chain_key: Option<[u8; 32]>,
    pub ratchet_keypair: Keypair,
    pub their_ratchet_pub: Option<[u8; 32]>,
    pub send_count: u32,
    pub recv_count: u32,
    pub prev_send_count: u32,
    pub message_keys: HashMap<([u8; 32], u32), [u8; 32]>,
}

/// Initialise the initiator ("Alice"): generate a ratchet keypair and turn the
/// root ratchet against the peer's initial ratchet public key, ready to send.
pub fn init_sender(
    shared_secret: &[u8; 32],
    their_ratchet_pub: &[u8; 32],
    entropy: &mut impl Entropy,
) -> RatchetState {
    let dhs = entropy.ratchet_keypair();
    let dh_out = dhs.ecdh(their_ratchet_pub);
    let (root_key, sending_chain_key) = kdf_rk(shared_secret, &dh_out);
    RatchetState {
        root_key,
        sending_chain_key: Some(sending_chain_key),
        receiving_chain_key: None,
        ratchet_keypair: dhs,
        their_ratchet_pub: Some(*their_ratchet_pub),
        send_count: 0,
        recv_count: 0,
        prev_send_count: 0,
        message_keys: HashMap::new(),
    }
}

/// Initialise the responder ("Bob"): holds the ratchet keypair whose public half
/// the initiator bootstrapped against; no sending chain until it receives.
pub fn init_receiver(shared_secret: &[u8; 32], our_ratchet_keypair: Keypair) -> RatchetState {
    RatchetState {
        root_key: *shared_secret,
        sending_chain_key: None,
        receiving_chain_key: None,
        ratchet_keypair: our_ratchet_keypair,
        their_ratchet_pub: None,
        send_count: 0,
        recv_count: 0,
        prev_send_count: 0,
        message_keys: HashMap::new(),
    }
}

/// Advance the sending chain and encrypt one message.
pub fn ratchet_encrypt(
    state: &mut RatchetState,
    plaintext: &[u8],
    entropy: &mut impl Entropy,
) -> Result<(Header, Vec<u8>)> {
    let ck = state.sending_chain_key.ok_or(Error::Ratchet(
        "no sending chain yet — receive a message before sending",
    ))?;
    let (next_ck, message_key) = kdf_ck(&ck);
    state.sending_chain_key = Some(next_ck);
    let header = Header {
        dh: state.ratchet_keypair.public_bytes(),
        pn: state.prev_send_count,
        n: state.send_count,
    };
    state.send_count += 1;
    let nonce = entropy.aead_nonce();
    let ct = encrypt_with_nonce(&message_key, &nonce, plaintext, &header.to_bytes());
    Ok((header, ct))
}

/// Decrypt one message, turning ratchets as needed. Transactional: mutates a
/// clone and commits only on a successful authenticated decrypt (audit H1).
pub fn ratchet_decrypt(
    state: &mut RatchetState,
    header: &Header,
    ciphertext: &[u8],
    root_mix: Option<&[u8]>,
    entropy: &mut impl Entropy,
) -> Result<Vec<u8>> {
    let mut trial = state.clone();
    let plaintext = decrypt_into(&mut trial, header, ciphertext, root_mix, entropy)?;
    *state = trial;
    Ok(plaintext)
}

fn decrypt_into(
    state: &mut RatchetState,
    header: &Header,
    ciphertext: &[u8],
    root_mix: Option<&[u8]>,
    entropy: &mut impl Entropy,
) -> Result<Vec<u8>> {
    // 1. A message we already skipped and cached.
    if let Some(pt) = try_skipped_keys(state, header, ciphertext)? {
        return Ok(pt);
    }

    // 2. New peer ratchet key → skip the rest of the old chain, then DH ratchet.
    if Some(header.dh) != state.their_ratchet_pub {
        if let Some(mix) = root_mix {
            if state.their_ratchet_pub.is_none() {
                // Bootstrap-only forward-secrecy fold (audit H3).
                state.root_key = derive_message_key(mix, Some(&state.root_key), FS_BOOTSTRAP_INFO);
            }
        }
        skip_message_keys(state, header.pn)?;
        dh_ratchet(state, header, entropy);
    }

    // 3. Skip up to this message's number in the current receiving chain.
    skip_message_keys(state, header.n)?;

    // 4. Derive this message's key and decrypt.
    let rck = state.receiving_chain_key.ok_or(Error::Ratchet(
        "no receiving chain key — message is unrecoverable",
    ))?;
    let (next_rck, message_key) = kdf_ck(&rck);
    state.receiving_chain_key = Some(next_rck);
    state.recv_count += 1;
    decrypt(&message_key, ciphertext, &header.to_bytes())
}

fn try_skipped_keys(
    state: &mut RatchetState,
    header: &Header,
    ciphertext: &[u8],
) -> Result<Option<Vec<u8>>> {
    let key = (header.dh, header.n);
    match state.message_keys.remove(&key) {
        Some(mk) => Ok(Some(decrypt(&mk, ciphertext, &header.to_bytes())?)),
        None => Ok(None),
    }
}

fn skip_message_keys(state: &mut RatchetState, until: u32) -> Result<()> {
    if state.recv_count + MAX_SKIP < until {
        return Err(Error::Ratchet("too many skipped messages"));
    }
    let their = match state.their_ratchet_pub {
        Some(t) => t,
        None => return Ok(()),
    };
    let mut rck = match state.receiving_chain_key {
        Some(c) => c,
        None => return Ok(()),
    };
    while state.recv_count < until {
        let (next_rck, message_key) = kdf_ck(&rck);
        rck = next_rck;
        state
            .message_keys
            .insert((their, state.recv_count), message_key);
        state.recv_count += 1;
    }
    state.receiving_chain_key = Some(rck);
    Ok(())
}

fn dh_ratchet(state: &mut RatchetState, header: &Header, entropy: &mut impl Entropy) {
    state.prev_send_count = state.send_count;
    state.send_count = 0;
    state.recv_count = 0;
    state.their_ratchet_pub = Some(header.dh);

    let dh_out = state.ratchet_keypair.ecdh(&header.dh);
    let (root_key, receiving_chain_key) = kdf_rk(&state.root_key, &dh_out);
    state.root_key = root_key;
    state.receiving_chain_key = Some(receiving_chain_key);

    state.ratchet_keypair = entropy.ratchet_keypair();
    let dh_out2 = state.ratchet_keypair.ecdh(&header.dh);
    let (root_key2, sending_chain_key) = kdf_rk(&state.root_key, &dh_out2);
    state.root_key = root_key2;
    state.sending_chain_key = Some(sending_chain_key);
}
