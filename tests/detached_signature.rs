//! The detached Ed25519 canonical-preimage recipe every signed Warren
//! artifact shares (release manifest, node-agent bundle index). One home:
//! consumers must not re-derive hex/curve/strictness handling.

use ed25519_dalek::SigningKey;
use warren_contract::release::{
    DetachedSignatureError, sign_canonical_preimage, verify_canonical_preimage,
};

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

#[test]
fn round_trip_verifies() {
    let preimage = br#"{"version":1,"payload":"x"}"#;
    let (pubkey_hex, sig_hex) = sign_canonical_preimage(preimage, &signer());
    verify_canonical_preimage(preimage, &pubkey_hex, &sig_hex)
        .expect("a signature must verify against its own preimage");
}

#[test]
fn tampered_preimage_is_rejected() {
    let (pubkey_hex, sig_hex) = sign_canonical_preimage(b"payload-a", &signer());
    let err = verify_canonical_preimage(b"payload-b", &pubkey_hex, &sig_hex)
        .expect_err("a different preimage must not verify");
    assert!(matches!(err, DetachedSignatureError::BadSignature));
}

#[test]
fn malformed_hex_is_rejected_before_any_crypto() {
    let (pubkey_hex, sig_hex) = sign_canonical_preimage(b"p", &signer());
    for (pk, sig) in [
        ("zz", sig_hex.as_str()),
        (pubkey_hex.as_str(), "zz"),
        ("abcd", sig_hex.as_str()),
        (pubkey_hex.as_str(), "abcd"),
    ] {
        let err =
            verify_canonical_preimage(b"p", pk, sig).expect_err("malformed hex must be rejected");
        assert!(matches!(err, DetachedSignatureError::InvalidHex));
    }
}

#[test]
fn off_curve_pubkey_is_rejected() {
    let (_, sig_hex) = sign_canonical_preimage(b"p", &signer());
    // y = 2 is not on the curve (x^2 has no square root).
    let off_curve = format!("02{}", "00".repeat(31));
    let err = verify_canonical_preimage(b"p", &off_curve, &sig_hex)
        .expect_err("an off-curve pubkey must be rejected");
    assert!(matches!(err, DetachedSignatureError::PubkeyNotOnCurve));
}

#[test]
fn foreign_key_signature_is_rejected() {
    let (_, sig_hex) = sign_canonical_preimage(b"p", &signer());
    let other = SigningKey::from_bytes(&[9u8; 32]);
    let other_pub = hex::encode(other.verifying_key().as_bytes());
    let err = verify_canonical_preimage(b"p", &other_pub, &sig_hex)
        .expect_err("a signature by another key must not verify");
    assert!(matches!(err, DetachedSignatureError::BadSignature));
}
