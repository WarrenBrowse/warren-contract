//! Replays the shared golden vector `vectors/route_kem_signature_v1.json`.
//!
//! The API signs the route KEM key it serves in the token directory, and every
//! client verifies that signature before sealing an anchor to the key
//! (warren-core doc 107 section 6.5). The file was signed with the Python
//! `cryptography` package and is recomputed by a standard-library Ed25519 in
//! the vectors repo, independently of this crate: a mismatch here is a wire
//! regression in this code, never a reason to edit the vector.

use ed25519_dalek::SigningKey;
use warren_contract::dto::{RouteAdmissionInfo, RouteKemSignature};
use warren_contract::route_kem::{
    DOMAIN, MESSAGE_LEN, RouteKemSignatureError, sign, signed_message, verify,
};

#[derive(serde::Deserialize)]
struct Vector {
    version: u32,
    domain_utf8: String,
    message_len: usize,
    signer: Signer,
    kem_key: KemKey,
    valid_until: u64,
    verify_at: u64,
    message_hex: String,
    signature_hex: String,
    route_admission_json: String,
    invalid: Vec<Invalid>,
}

#[derive(serde::Deserialize)]
struct Signer {
    signing_seed_hex: String,
    server_pubkey_hex: String,
}

#[derive(serde::Deserialize)]
struct KemKey {
    key_id: u8,
    pk_hex: String,
}

#[derive(serde::Deserialize)]
struct Invalid {
    name: String,
    now: u64,
    block: serde_json::Value,
    expect: String,
}

fn vector() -> Vector {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/route_kem_signature_v1.json"
    );
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path} ({e}); run `git submodule update --init vectors`"));
    serde_json::from_str(&raw).expect("route_kem_signature_v1.json parses")
}

fn bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    hex::decode(hex_str)
        .expect("vector hex")
        .try_into()
        .expect("vector field length")
}

fn outcome(e: &RouteKemSignatureError) -> &'static str {
    match e {
        RouteKemSignatureError::Unsigned => "unsigned",
        RouteKemSignatureError::Malformed => "malformed",
        RouteKemSignatureError::Expired => "expired",
        RouteKemSignatureError::BadSignature => "bad_signature",
        other => panic!("no vector outcome for {other:?}"),
    }
}

fn served(v: &Vector) -> RouteAdmissionInfo {
    serde_json::from_str(&v.route_admission_json).expect("the served block parses")
}

#[test]
fn constants_match_the_frozen_layout() {
    let v = vector();
    assert_eq!(v.version, 1);
    assert_eq!(DOMAIN, v.domain_utf8.as_bytes(), "the signing domain");
    assert_eq!(MESSAGE_LEN, v.message_len);
}

#[test]
fn the_signed_message_matches_the_vector() {
    let v = vector();
    let message = signed_message(
        1,
        v.kem_key.key_id,
        &bytes(&v.kem_key.pk_hex),
        v.valid_until,
    );
    assert_eq!(hex::encode(message), v.message_hex);
}

#[test]
fn signing_the_served_key_reproduces_the_vector_signature_and_block() {
    let v = vector();
    let key = SigningKey::from_bytes(&bytes(&v.signer.signing_seed_hex));
    assert_eq!(
        hex::encode(key.verifying_key().as_bytes()),
        v.signer.server_pubkey_hex
    );
    let mut info = served(&v);
    info.kem_signature = None;

    let signature = sign(&info, &key, v.valid_until);

    assert_eq!(
        signature,
        RouteKemSignature {
            valid_until: v.valid_until,
            signature_hex: v.signature_hex.clone(),
        }
    );
    info.kem_signature = Some(signature);
    assert_eq!(
        serde_json::to_string(&info).unwrap(),
        v.route_admission_json,
        "the served block, field for field and in order"
    );
}

#[test]
fn the_served_block_verifies_under_the_pinned_server_key() {
    let v = vector();
    assert_eq!(
        verify(
            &served(&v),
            &[v.signer.server_pubkey_hex.as_str()],
            v.verify_at
        ),
        Ok(())
    );
}

#[test]
fn every_invalid_block_is_refused_with_its_outcome() {
    let v = vector();
    for case in &v.invalid {
        let info: RouteAdmissionInfo = serde_json::from_value(case.block.clone())
            .unwrap_or_else(|e| panic!("{}: block parses ({e})", case.name));
        let err =
            verify(&info, &[v.signer.server_pubkey_hex.as_str()], case.now).expect_err(&case.name);
        assert_eq!(outcome(&err), case.expect, "{}", case.name);
    }
}

#[test]
fn a_block_is_refused_when_no_server_key_is_pinned() {
    let v = vector();
    assert_eq!(
        verify(&served(&v), &[], v.verify_at),
        Err(RouteKemSignatureError::NoPinnedKey),
        "an empty pin set must never read as trust on first use"
    );
}

#[test]
fn any_pinned_server_key_may_vouch_for_the_block() {
    let v = vector();
    let other = hex::encode(
        SigningKey::from_bytes(&[0x09; 32])
            .verifying_key()
            .as_bytes(),
    );
    let pins = [
        other.as_str(),
        "not hex",
        v.signer.server_pubkey_hex.as_str(),
    ];
    assert_eq!(verify(&served(&v), &pins, v.verify_at), Ok(()));
    assert_eq!(
        verify(&served(&v), &pins[..2], v.verify_at),
        Err(RouteKemSignatureError::BadSignature)
    );
}
