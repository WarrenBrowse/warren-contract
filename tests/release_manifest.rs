//! Signed exit-release manifest: sign/verify contract + golden vector.
//!
//! The manifest is the exit fleet's update authority (doc 52): it is
//! signed OFFLINE with the admin roster key and verified independently
//! by warren-api (upload), warren-exit (staging) and warren-updater
//! (install). These tests freeze the canonical preimage so a silent
//! field reorder/rename cannot split "what was signed" from "what is
//! verified" between those three consumers.

use ed25519_dalek::SigningKey;
use warren_contract::release::{
    RELEASE_MANIFEST_VERSION, ReleaseError, sign_release_manifest, verify_release_manifest,
};

fn seeded_key() -> SigningKey {
    SigningKey::from_bytes(&[0xab; 32])
}

fn sample_signed() -> warren_contract::release::SignedReleaseManifest {
    sign_release_manifest(
        "v0.7.0-3-gabc1234",
        "stable",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        42_000_000,
        7,
        1_700_000_000,
        1_700_086_400,
        &seeded_key(),
    )
}

#[test]
fn sign_then_verify_returns_the_release_fields() {
    let signed = sample_signed();
    let json = serde_json::to_string(&signed).unwrap();
    let pin = hex::encode(seeded_key().verifying_key().as_bytes());

    let v = verify_release_manifest(&json, &pin).expect("self-signed manifest must verify");

    assert_eq!(v.release_version, "v0.7.0-3-gabc1234");
    assert_eq!(v.channel, "stable");
    assert_eq!(
        v.binary_sha256_hex,
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    );
    assert_eq!(v.binary_size, 42_000_000);
    assert_eq!(v.generation, 7);
    assert_eq!(v.expires_at, 1_700_086_400);
}

#[test]
fn tampered_binary_hash_fails_signature() {
    // The whole point of the manifest: a compromised warren-api cannot
    // swap the binary hash under an already-signed manifest.
    let mut signed = sample_signed();
    signed.binary_sha256_hex = "00".repeat(32);
    let json = serde_json::to_string(&signed).unwrap();
    let pin = hex::encode(seeded_key().verifying_key().as_bytes());

    let err = verify_release_manifest(&json, &pin).unwrap_err();
    assert!(
        matches!(err, ReleaseError::BadSignature),
        "hash tamper must be a signature failure, got {err:?}"
    );
}

#[test]
fn wrong_pinned_signer_is_rejected() {
    let signed = sample_signed();
    let json = serde_json::to_string(&signed).unwrap();
    let other_pin = hex::encode(
        SigningKey::from_bytes(&[0x01; 32])
            .verifying_key()
            .as_bytes(),
    );

    let err = verify_release_manifest(&json, &other_pin).unwrap_err();
    assert!(
        matches!(err, ReleaseError::SignerPubkeyMismatch { .. }),
        "a manifest signed by another key must be rejected by the pin, got {err:?}"
    );
}

#[test]
fn signer_mismatch_error_redacts_the_keys() {
    // No-log discipline: the error must never echo a full pubkey.
    let signed = sample_signed();
    let json = serde_json::to_string(&signed).unwrap();
    let other_pin = hex::encode(
        SigningKey::from_bytes(&[0x01; 32])
            .verifying_key()
            .as_bytes(),
    );

    let msg = verify_release_manifest(&json, &other_pin)
        .unwrap_err()
        .to_string();
    let full_signer = hex::encode(seeded_key().verifying_key().as_bytes());
    assert!(
        !msg.contains(&full_signer) && !msg.contains(&other_pin),
        "error message must redact both pubkeys: {msg}"
    );
}

#[test]
fn unsupported_manifest_version_is_rejected() {
    let mut signed = sample_signed();
    signed.version = RELEASE_MANIFEST_VERSION + 1;
    let json = serde_json::to_string(&signed).unwrap();
    let pin = hex::encode(seeded_key().verifying_key().as_bytes());

    let err = verify_release_manifest(&json, &pin).unwrap_err();
    assert!(
        matches!(err, ReleaseError::UnsupportedVersion { got } if got == RELEASE_MANIFEST_VERSION + 1),
        "future format versions must be rejected, got {err:?}"
    );
}

#[test]
fn verified_release_expiry_boundary() {
    let signed = sample_signed();
    let json = serde_json::to_string(&signed).unwrap();
    let pin = hex::encode(seeded_key().verifying_key().as_bytes());
    let v = verify_release_manifest(&json, &pin).unwrap();

    assert!(!v.is_expired(1_700_086_399), "one second before expiry");
    assert!(v.is_expired(1_700_086_400), "expiry instant is stale");
}

#[test]
fn golden_vector_canonical_json_and_signature_are_frozen() {
    // Wire vector (rule 40): the exact signed JSON produced from a
    // deterministic key. If this changes, deployed exits stop
    // verifying manifests produced by newer signers: bump the format
    // version instead of mutating it.
    let signed = sample_signed();
    let json = serde_json::to_string(&signed).unwrap();

    let expected = concat!(
        "{\"version\":1,",
        "\"release_version\":\"v0.7.0-3-gabc1234\",",
        "\"channel\":\"stable\",",
        "\"binary_sha256_hex\":\"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\",",
        "\"binary_size\":42000000,",
        "\"generation\":7,",
        "\"signed_at\":1700000000,",
        "\"expires_at\":1700086400,",
        "\"signer_pubkey_hex\":\"248acbdbaf9e050196de704bea2d68770e519150d103b587dae2d9cad53dd930\",",
        "\"signature_hex\":\"d53ea6dc30bb6f6f585f8b7f54ac3aba266d54e0c5499b8c4aa2133e38",
        "0847a567d1d55b4689f1831464db204fbdc0452892ba9445d32605c4b2345eabf0ae08\"}",
    );
    assert_eq!(
        json, expected,
        "canonical signed-manifest JSON drifted (wire break: bump the format version)"
    );

    let pin = hex::encode(seeded_key().verifying_key().as_bytes());
    verify_release_manifest(&json, &pin).expect("frozen vector must keep verifying");
}
