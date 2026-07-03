//! Cross-implementation vector conformance (Phase 13a).
//!
//! Loads the shared vectors in `../../tests/vectors` (exported from the Python
//! reference by `scripts/export_vectors.py`) and asserts `drift-crypto`
//! reproduces every one bit-for-bit. This is the Rust half of the parity gate in
//! `docs/app-plan.md` §6; the Python half is `tests/unit/test_vectors.py`.

use std::fs;
use std::path::PathBuf;

use serde_json::Value;

use drift_crypto::aead::{decrypt, encrypt_with_nonce, NONCE_SIZE};
use drift_crypto::base58;
use drift_crypto::burn::{generate_burn_token, verify_burn_token};
use drift_crypto::entropy::TapeEntropy;
use drift_crypto::identity::{Identity, Keypair};
use drift_crypto::kdf::{derive_message_key, kdf_ck, kdf_rk};
use drift_crypto::ratchet::{init_receiver, init_sender, ratchet_decrypt, ratchet_encrypt, Header};
use drift_crypto::sealed::{open_header, parse};
use drift_crypto::vault::{derive_unlock_key, try_unlock, KdfParams};
use drift_crypto::x3dh::{
    derive_master_secret_recv, verify_prekey_bundle, PreKeyBundle, PreKeyPrivates, X3DHHeader,
};

// --------------------------------------------------------------------------- //
// Helpers
// --------------------------------------------------------------------------- //

fn load(name: &str) -> Value {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "..",
        "tests",
        "vectors",
        &format!("{name}.json"),
    ]
    .iter()
    .collect();
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("valid JSON vector")
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

fn a32(v: &Value) -> [u8; 32] {
    hx(v).try_into().expect("32 bytes")
}

fn a16(v: &Value) -> [u8; 16] {
    hx(v).try_into().expect("16 bytes")
}

fn a24(v: &Value) -> [u8; 24] {
    hx(v).try_into().expect("24 bytes")
}

fn keypair(priv_hex: &Value) -> Keypair {
    Keypair::from_private_bytes(&a32(priv_hex))
}

// --------------------------------------------------------------------------- //

#[test]
fn base58_vectors() {
    for v in load("base58")["vectors"].as_array().unwrap() {
        assert_eq!(base58::encode(&hx(&v["raw"])), v["b58"].as_str().unwrap());
        assert_eq!(
            base58::decode(v["b58"].as_str().unwrap()).unwrap(),
            hx(&v["raw"])
        );
    }
}

#[test]
fn kdf_vectors() {
    for v in load("kdf")["vectors"].as_array().unwrap() {
        if let Some(kind) = v.get("kind").and_then(|k| k.as_str()) {
            match kind {
                "ratchet-rk" => {
                    let (rk, ck) = kdf_rk(&hx(&v["root_key"]), &hx(&v["dh_out"]));
                    assert_eq!(hex::encode(rk), v["new_root_key"].as_str().unwrap());
                    assert_eq!(hex::encode(ck), v["chain_key"].as_str().unwrap());
                }
                "ratchet-ck" => {
                    let (nck, mk) = kdf_ck(&hx(&v["chain_key"]));
                    assert_eq!(hex::encode(nck), v["next_chain_key"].as_str().unwrap());
                    assert_eq!(hex::encode(mk), v["message_key"].as_str().unwrap());
                }
                other => panic!("unknown kdf kind {other}"),
            }
            continue;
        }
        let salt = v["salt"].as_str().map(|s| hex::decode(s).unwrap());
        let out = derive_message_key(
            &hx(&v["ikm"]),
            salt.as_deref(),
            v["info"].as_str().unwrap().as_bytes(),
        );
        assert_eq!(hex::encode(out), v["okm"].as_str().unwrap());
    }
}

#[test]
fn aead_vectors() {
    for v in load("aead")["vectors"].as_array().unwrap() {
        let key = a32(&v["key"]);
        let ad = hx(&v["associated_data"]);
        let ct = hx(&v["ciphertext"]);
        // Decrypt direction: the recorded ciphertext must open to the plaintext.
        assert_eq!(decrypt(&key, &ct, &ad).unwrap(), hx(&v["plaintext"]));
        // Re-encrypt with the recorded nonce reproduces the ciphertext exactly.
        let nonce: [u8; NONCE_SIZE] = ct[..NONCE_SIZE].try_into().unwrap();
        let reenc = encrypt_with_nonce(&key, &nonce, &hx(&v["plaintext"]), &ad);
        assert_eq!(reenc, ct);
    }
}

#[test]
fn identity_vectors() {
    let v = load("identity");
    let idn = Identity::from_private_bytes(&a32(&v["scan_priv"]), &a32(&v["spend_priv"]));
    assert_eq!(
        hex::encode(idn.scan.public_bytes()),
        v["scan_pub"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(idn.spend.public_bytes()),
        v["spend_pub"].as_str().unwrap()
    );
    assert_eq!(idn.contact_code(), v["contact_code"].as_str().unwrap());
    assert_eq!(
        hex::encode(idn.signing_seed()),
        v["signing_seed"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(idn.verify_key_bytes()),
        v["verify_key"].as_str().unwrap()
    );
    let sig = idn.sign(&hx(&v["signed_message"]));
    assert_eq!(hex::encode(sig), v["signature"].as_str().unwrap());
    let shared = idn.scan.ecdh(&a32(&v["ecdh"]["their_pub"]));
    assert_eq!(
        hex::encode(shared),
        v["ecdh"]["shared_secret"].as_str().unwrap()
    );
}

#[test]
fn sealed_vectors() {
    let v = load("sealed");
    let blob = hx(&v["blob"]);
    let (eph, sealed_header, ct) = parse(&blob).unwrap();
    assert_eq!(hex::encode(eph), v["ephemeral_pub"].as_str().unwrap());
    assert_eq!(hex::encode(ct), v["ratchet_ciphertext"].as_str().unwrap());
    let header = open_header(&hx(&v["stealth_key"]), sealed_header, &hx(&v["address"])).unwrap();
    assert_eq!(hex::encode(header), v["ratchet_header"].as_str().unwrap());
}

#[test]
fn ratchet_transcript_replays_bit_for_bit() {
    let v = load("ratchet");
    let key_tape: Vec<[u8; 32]> = v["generated_ratchet_privs"]
        .as_array()
        .unwrap()
        .iter()
        .map(a32)
        .collect();
    let nonce_tape: Vec<[u8; 24]> = v["aead_nonces"]
        .as_array()
        .unwrap()
        .iter()
        .map(a24)
        .collect();
    let mut entropy = TapeEntropy::new(key_tape, nonce_tape);

    let shared = a32(&v["shared_secret"]);
    let bob_init = keypair(&v["bob_initial_ratchet_priv"]);
    let mut alice = init_sender(&shared, &bob_init.public_bytes(), &mut entropy);
    let mut bob = init_receiver(&shared, bob_init);

    // Index messages by id.
    let mut by_id = std::collections::HashMap::new();
    for m in v["messages"].as_array().unwrap() {
        by_id.insert(m["id"].as_str().unwrap().to_string(), m.clone());
    }
    let mut produced: std::collections::HashMap<String, (Header, Vec<u8>)> =
        std::collections::HashMap::new();

    for event in v["events"].as_array().unwrap() {
        let id = event["id"].as_str().unwrap();
        let m = &by_id[id];
        let sender = m["sender"].as_str().unwrap();
        match event["type"].as_str().unwrap() {
            "send" => {
                let state = if sender == "alice" {
                    &mut alice
                } else {
                    &mut bob
                };
                let (header, ct) =
                    ratchet_encrypt(state, &hx(&m["plaintext"]), &mut entropy).unwrap();
                assert_eq!(
                    hex::encode(header.to_bytes()),
                    m["header"].as_str().unwrap(),
                    "{id}"
                );
                assert_eq!(hex::encode(&ct), m["ciphertext"].as_str().unwrap(), "{id}");
                produced.insert(id.to_string(), (header, ct));
            }
            "recv" => {
                let receiver = if sender == "alice" {
                    &mut bob
                } else {
                    &mut alice
                };
                let (header, ct) = produced.remove(id).expect("received before sent");
                let pt = ratchet_decrypt(receiver, &header, &ct, None, &mut entropy).unwrap();
                assert_eq!(hex::encode(pt), m["plaintext"].as_str().unwrap(), "{id}");
            }
            other => panic!("unknown event type {other}"),
        }
    }

    assert!(entropy.drained(), "key/nonce tapes must be fully consumed");
}

fn build_privates(case: &Value) -> PreKeyPrivates {
    let mut one_time = Vec::new();
    if let Some(otpk) = case.get("one_time_prekey_priv") {
        one_time.push((
            case["one_time_prekey_id"].as_u64().unwrap() as u32,
            keypair(otpk),
        ));
    }
    PreKeyPrivates {
        signed_prekey: keypair(&case["bob_signed_prekey_priv"]),
        signed_prekey_id: case["signed_prekey_id"].as_u64().unwrap() as u32,
        one_time,
    }
}

#[test]
fn x3dh_vectors() {
    let v = load("x3dh");
    let bob = Identity::from_private_bytes(&a32(&v["bob_scan_priv"]), &a32(&v["bob_spend_priv"]));

    for case in v["cases"].as_array().unwrap() {
        let privates = build_privates(case);
        let header = X3DHHeader::from_bytes(&hx(&case["header"])).unwrap();
        let master = derive_master_secret_recv(&bob, &privates, &header).unwrap();
        assert_eq!(hex::encode(master), case["master_secret"].as_str().unwrap());

        // The signed prekey signature verifies under Bob's identity key.
        let bundle = PreKeyBundle {
            identity_key: bob.verify_key_bytes(),
            identity_dh_key: bob.spend.public_bytes(),
            signed_prekey: privates.signed_prekey.public_bytes(),
            signed_prekey_sig: hx(&case["signed_prekey_sig"]).try_into().unwrap(),
            signed_prekey_id: privates.signed_prekey_id,
            one_time_prekey: None,
            one_time_prekey_id: None,
        };
        assert!(verify_prekey_bundle(&bundle));
    }
}

#[test]
fn x3dh_handoff_first_message_decrypts() {
    let v = load("x3dh");
    let h = &v["handoff"];
    let bob = Identity::from_private_bytes(&a32(&v["bob_scan_priv"]), &a32(&v["bob_spend_priv"]));
    let privates = build_privates(h);

    let header = X3DHHeader::from_bytes(&hx(&h["x3dh_header"])).unwrap();
    let master = derive_master_secret_recv(&bob, &privates, &header).unwrap();
    assert_eq!(hex::encode(master), h["master_secret"].as_str().unwrap());

    // Bob's receive side: the DH-ratchet keypair Bob generates here does not
    // affect decryption of this first message, so any entropy source works.
    let mut entropy = TapeEntropy::new(vec![[7u8; 32]], vec![]);
    let mut bob_state = init_receiver(&master, privates.signed_prekey);
    let ratchet_header = Header::from_bytes(&hx(&h["ratchet_header"])).unwrap();
    let pt = ratchet_decrypt(
        &mut bob_state,
        &ratchet_header,
        &hx(&h["ciphertext"]),
        None,
        &mut entropy,
    )
    .unwrap();
    assert_eq!(hex::encode(pt), h["plaintext"].as_str().unwrap());
}

#[test]
fn burn_vectors() {
    for v in load("burn")["vectors"].as_array().unwrap() {
        let shared = hx(&v["shared_secret"]);
        let scope = v["scope"].as_str().unwrap();
        let message_id = v["message_id"].as_str();
        let nonce = a16(&v["nonce"]);
        let ts = v["timestamp"].as_i64().unwrap();
        let token = generate_burn_token(&shared, scope, message_id, &nonce, ts);
        assert_eq!(token, v["token"].as_str().unwrap());
        assert!(verify_burn_token(
            &shared, &token, scope, message_id, ts, 300
        ));
    }
}

#[test]
fn vault_kdf_pin() {
    let k = &load("vault")["kdf"];
    let params = KdfParams {
        time_cost: k["time_cost"].as_u64().unwrap() as u32,
        memory_cost: k["memory_cost"].as_u64().unwrap() as u32,
        parallelism: k["parallelism"].as_u64().unwrap() as u32,
    };
    let key = derive_unlock_key(k["passphrase"].as_str().unwrap(), &hx(&k["salt"]), &params);
    assert_eq!(hex::encode(key), k["unlock_key"].as_str().unwrap());
}

#[test]
fn vault_unlocks() {
    for vault in load("vault")["vaults"].as_array().unwrap() {
        let blob = hx(&vault["blob"]);
        for case in vault["unlocks"].as_array().unwrap() {
            let got = try_unlock(&blob, case["passphrase"].as_str().unwrap());
            match case["payload"].as_str() {
                Some(expected) => assert_eq!(hex::encode(got.unwrap()), expected),
                None => assert!(got.is_none()),
            }
        }
    }
}
