//! Replays the shared golden vector `vectors/device_revocation_v1.json`.
//!
//! A wallet holder revoking one of its devices signs the revocation with the
//! wallet key; the API stores the statement and returns it in the 403
//! `device_revoked` body, and the revoked device verifies it before it erases
//! anything (warren-core doc 115, audit finding X-01). The file was signed with
//! the Python `cryptography` package and is recomputed by a standard-library
//! Ed25519 in the vectors repo, independently of this crate: a mismatch here
//! is a wire regression in this code, never a reason to edit the vector.

use ed25519_dalek::SigningKey;
use warren_contract::device_revocation::{
    DOMAIN, DeviceRevocationError, MESSAGE_LEN, sign, signed_message, verify_refusal,
};
use warren_contract::dto::{DeviceId, DeviceRefusal, DeviceRevocation};

#[derive(serde::Deserialize)]
struct Vector {
    version: u32,
    domain_utf8: String,
    message_len: usize,
    wallet: Wallet,
    device_id: DeviceIdCase,
    revoked_at_unix_secs: u64,
    message_hex: String,
    signature_hex: String,
    revocation_request_json: String,
    refusal_json: String,
    invalid: Vec<Invalid>,
}

#[derive(serde::Deserialize)]
struct Wallet {
    signing_seed_hex: String,
    pubkey_hex: String,
}

#[derive(serde::Deserialize)]
struct DeviceIdCase {
    b64url: String,
    bytes_hex: String,
}

#[derive(serde::Deserialize)]
struct Invalid {
    name: String,
    refusal_json: String,
    expect: String,
}

fn vector() -> Vector {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/vectors/device_revocation_v1.json"
    );
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path} ({e}); run `git submodule update --init vectors`"));
    serde_json::from_str(&raw).expect("device_revocation_v1.json parses")
}

fn wallet(v: &Vector) -> SigningKey {
    let mut seed = [0u8; 32];
    hex::decode_to_slice(&v.wallet.signing_seed_hex, &mut seed).expect("seed hex");
    SigningKey::from_bytes(&seed)
}

fn device(v: &Vector) -> DeviceId {
    let id: DeviceId =
        serde_json::from_value(serde_json::Value::String(v.device_id.b64url.clone()))
            .expect("device id parses");
    assert_eq!(hex::encode(id.as_bytes()), v.device_id.bytes_hex);
    id
}

#[test]
fn the_message_layout_is_frozen() {
    let v = vector();
    assert_eq!(v.version, 1);
    assert_eq!(DOMAIN, v.domain_utf8.as_bytes());
    assert_eq!(MESSAGE_LEN, v.message_len);
    let key = wallet(&v);
    assert_eq!(
        hex::encode(key.verifying_key().as_bytes()),
        v.wallet.pubkey_hex
    );
    let message = signed_message(&key.verifying_key(), &device(&v), v.revoked_at_unix_secs);
    assert_eq!(hex::encode(message), v.message_hex);
}

#[test]
fn the_wallet_signs_the_statement_byte_for_byte() {
    let v = vector();
    let statement = sign(&wallet(&v), &device(&v), v.revoked_at_unix_secs);
    assert_eq!(statement.signature_hex, v.signature_hex);
    assert_eq!(
        serde_json::to_string(&statement).expect("serializes"),
        v.revocation_request_json
    );
    let parsed: DeviceRevocation =
        serde_json::from_str(&v.revocation_request_json).expect("request parses");
    assert_eq!(parsed, statement);
}

#[test]
fn the_refusal_carries_the_statement_and_keeps_its_error_string() {
    let v = vector();
    let refusal =
        DeviceRefusal::revoked(Some(sign(&wallet(&v), &device(&v), v.revoked_at_unix_secs)));
    assert_eq!(
        serde_json::to_string(&refusal).expect("serializes"),
        v.refusal_json
    );
    let bare = DeviceRefusal::revoked(None);
    assert_eq!(
        serde_json::to_string(&bare).expect("serializes"),
        r#"{"error":"device_revoked"}"#
    );
}

#[test]
fn the_revoked_device_accepts_the_genuine_statement() {
    let v = vector();
    let refusal: DeviceRefusal = serde_json::from_str(&v.refusal_json).expect("refusal parses");
    assert_eq!(
        verify_refusal(&refusal, &wallet(&v).verifying_key(), &device(&v)),
        Ok(())
    );
}

#[test]
fn every_invalid_refusal_keeps_the_identity_with_its_outcome() {
    let v = vector();
    let key = wallet(&v).verifying_key();
    let id = device(&v);
    assert!(!v.invalid.is_empty());
    for case in &v.invalid {
        let refusal: DeviceRefusal = serde_json::from_str(&case.refusal_json)
            .unwrap_or_else(|e| panic!("{}: refusal parses ({e})", case.name));
        let expected = match case.expect.as_str() {
            "unsigned" => DeviceRevocationError::Unsigned,
            "malformed" => DeviceRevocationError::Malformed,
            "bad_signature" => DeviceRevocationError::BadSignature,
            other => panic!("{}: unknown outcome {other}", case.name),
        };
        assert_eq!(
            verify_refusal(&refusal, &key, &id),
            Err(expected),
            "{}",
            case.name
        );
    }
}
