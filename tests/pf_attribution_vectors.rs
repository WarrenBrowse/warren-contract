//! Replays the shared golden vector `vectors/pf_attribution.json`.
//!
//! The attribution tag is minted by warren-api, verified by every exit and
//! carried by every client inside the entitlement envelope, so its layout is
//! pinned in the cross-language corpus. The file was produced with libsodium,
//! independently of this crate: a mismatch here is a wire regression in this
//! code, never a reason to edit the vector.

use ed25519_dalek::{SigningKey, VerifyingKey};
use warren_contract::pf_attribution::{
    AttributionTag, AttributionTagError, DOMAIN, ENVELOPE_LEN, EntitlementEnvelope, EnvelopeError,
    HKDF_INFO_AEAD, HKDF_INFO_SIGN, TAG_LEN, TOKEN_LEN, aad, signing_preimage,
};

#[derive(serde::Deserialize)]
struct Vector {
    version: u32,
    domain_utf8: String,
    hkdf_info_aead_utf8: String,
    hkdf_info_sign_utf8: String,
    tag_len: usize,
    token_len: usize,
    envelope_len: usize,
    keys: Keys,
    tag: Tag,
    envelope: Envelope,
    invalid_tags: Vec<InvalidTag>,
    invalid_envelopes: Vec<InvalidEnvelope>,
    // Read only by the `seal` replays below.
    #[cfg_attr(not(feature = "seal"), allow(dead_code))]
    wrong_k_enc_hex: String,
}

#[derive(serde::Deserialize)]
struct Keys {
    // Read only by the `seal` replays below.
    #[cfg_attr(not(feature = "seal"), allow(dead_code))]
    k_enc_hex: String,
    k_sign_seed_hex: String,
    verifying_key_hex: String,
}

#[derive(serde::Deserialize)]
struct Tag {
    version: u8,
    epoch: u64,
    nonce_hex: String,
    // Read only by the `seal` replays below.
    #[cfg_attr(not(feature = "seal"), allow(dead_code))]
    account_pubkey_hex: String,
    aad_hex: String,
    ciphertext_hex: String,
    signing_preimage_hex: String,
    signature_hex: String,
    tag_hex: String,
}

#[derive(serde::Deserialize)]
struct Envelope {
    version: u8,
    token_hex: String,
    envelope_hex: String,
}

#[derive(serde::Deserialize)]
struct InvalidTag {
    name: String,
    tag_hex: String,
    verifying_key_hex: String,
    expect: String,
}

#[derive(serde::Deserialize)]
struct InvalidEnvelope {
    name: String,
    envelope_hex: String,
    expect: String,
}

fn vector() -> Vector {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/pf_attribution.json");
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path} ({e}); run `git submodule update --init vectors`"));
    serde_json::from_str(&raw).expect("pf_attribution.json parses")
}

fn bytes<const N: usize>(hex_str: &str) -> [u8; N] {
    hex::decode(hex_str)
        .expect("vector hex")
        .try_into()
        .expect("vector field length")
}

fn verifying_key(hex_str: &str) -> VerifyingKey {
    VerifyingKey::from_bytes(&bytes(hex_str)).expect("vector verifying key")
}

fn tag_error_name(e: &AttributionTagError) -> &'static str {
    match e {
        AttributionTagError::WrongLength { .. } => "wrong_length",
        AttributionTagError::UnsupportedVersion(_) => "unsupported_version",
        AttributionTagError::BadSignature => "bad_signature",
        other => panic!("no vector outcome for {other:?}"),
    }
}

fn envelope_error_name(e: &EnvelopeError) -> &'static str {
    match e {
        EnvelopeError::WrongLength { .. } => "wrong_length",
        EnvelopeError::UnsupportedVersion(_) => "unsupported_version",
        EnvelopeError::Tag(AttributionTagError::UnsupportedVersion(_)) => "unsupported_tag_version",
        other => panic!("no vector outcome for {other:?}"),
    }
}

#[test]
fn constants_match_the_frozen_layout() {
    let v = vector();
    assert_eq!(v.version, 1);
    assert_eq!(DOMAIN, v.domain_utf8.as_bytes(), "the signing domain");
    assert_eq!(HKDF_INFO_AEAD, v.hkdf_info_aead_utf8.as_bytes());
    assert_eq!(HKDF_INFO_SIGN, v.hkdf_info_sign_utf8.as_bytes());
    assert_eq!(TAG_LEN, v.tag_len);
    assert_eq!(TOKEN_LEN, v.token_len);
    assert_eq!(ENVELOPE_LEN, v.envelope_len);
}

#[test]
fn envelope_token_length_is_the_engine_privacy_pass_token_length() {
    assert_eq!(
        TOKEN_LEN,
        warrenguard_token::TOKEN_LEN,
        "the envelope carries exactly one engine token; a new token size is a new envelope version"
    );
}

#[test]
fn signing_preimage_and_aad_match_the_vector() {
    let v = vector();
    let nonce = bytes(&v.tag.nonce_hex);
    let ciphertext = bytes(&v.tag.ciphertext_hex);
    assert_eq!(
        hex::encode(aad(v.tag.epoch)),
        v.tag.aad_hex,
        "the AEAD aad binds the ciphertext to its version and epoch"
    );
    assert_eq!(
        hex::encode(signing_preimage(v.tag.epoch, &nonce, &ciphertext)),
        v.tag.signing_preimage_hex,
        "the preimage the API signs and every exit verifies"
    );
}

#[test]
fn vector_tag_parses_into_its_fields_and_verifies() {
    let v = vector();
    let raw: [u8; TAG_LEN] = bytes(&v.tag.tag_hex);
    let tag = AttributionTag::from_bytes(&raw).expect("the vector tag parses");
    assert_eq!(tag.version(), v.tag.version);
    assert_eq!(tag.epoch(), v.tag.epoch);
    assert_eq!(hex::encode(tag.nonce()), v.tag.nonce_hex);
    assert_eq!(hex::encode(tag.ciphertext()), v.tag.ciphertext_hex);
    assert_eq!(hex::encode(tag.signature()), v.tag.signature_hex);
    assert_eq!(
        hex::encode(tag.signing_preimage()),
        v.tag.signing_preimage_hex
    );
    assert_eq!(tag.as_bytes(), &raw, "parsing is lossless");
    tag.verify(&verifying_key(&v.keys.verifying_key_hex))
        .expect("a tag minted by the vector key verifies under its public key");
}

#[test]
fn vector_verifying_key_is_the_one_the_signing_seed_derives() {
    let v = vector();
    let signing = SigningKey::from_bytes(&bytes(&v.keys.k_sign_seed_hex));
    assert_eq!(
        hex::encode(signing.verifying_key().as_bytes()),
        v.keys.verifying_key_hex
    );
}

#[test]
fn every_invalid_tag_is_refused_with_its_pinned_outcome() {
    let v = vector();
    for case in &v.invalid_tags {
        let raw = hex::decode(&case.tag_hex).expect("vector hex");
        let outcome = AttributionTag::from_bytes(&raw)
            .and_then(|tag| tag.verify(&verifying_key(&case.verifying_key_hex)));
        let err = outcome.expect_err(&format!("{} must be refused", case.name));
        assert_eq!(tag_error_name(&err), case.expect, "case {}", case.name);
    }
}

#[test]
fn vector_envelope_parses_into_token_and_tag_and_encodes_back() {
    let v = vector();
    let raw = hex::decode(&v.envelope.envelope_hex).expect("vector hex");
    let envelope = EntitlementEnvelope::parse(&raw).expect("the vector envelope parses");
    assert_eq!(hex::encode(envelope.token()), v.envelope.token_hex);
    assert_eq!(hex::encode(envelope.tag().as_bytes()), v.tag.tag_hex);
    assert_eq!(raw[0], v.envelope.version);
    assert_eq!(
        envelope.encode().as_slice(),
        raw.as_slice(),
        "encode is the exact inverse of parse"
    );

    let tag = AttributionTag::from_bytes(&bytes::<TAG_LEN>(&v.tag.tag_hex)).expect("tag");
    let token = hex::decode(&v.envelope.token_hex).expect("vector hex");
    let built = EntitlementEnvelope::new(&token, tag).expect("a full-length token is accepted");
    assert_eq!(
        built.encode().as_slice(),
        raw.as_slice(),
        "the client composes the same bytes the exit parses"
    );
}

#[test]
fn every_invalid_envelope_is_refused_with_its_pinned_outcome() {
    let v = vector();
    for case in &v.invalid_envelopes {
        let raw = hex::decode(&case.envelope_hex).expect("vector hex");
        let err =
            EntitlementEnvelope::parse(&raw).expect_err(&format!("{} must be refused", case.name));
        assert_eq!(envelope_error_name(&err), case.expect, "case {}", case.name);
    }
}

#[test]
fn envelope_fits_the_natpmp_credential_trailer() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/natpmp.json");
    let raw = std::fs::read_to_string(path).expect("read natpmp.json");
    let natpmp: serde_json::Value = serde_json::from_str(&raw).expect("natpmp.json parses");
    let cap = natpmp["max_credential_len"]
        .as_u64()
        .expect("natpmp.json pins max_credential_len");
    assert!(
        ENVELOPE_LEN as u64 <= cap,
        "an envelope longer than the trailer cap is silently dropped by the client, \
         which then forwards nothing at all: {ENVELOPE_LEN} > {cap}"
    );
}

#[cfg(feature = "seal")]
mod seal {
    use super::*;
    use warren_contract::pf_attribution::{ACCOUNT_PUBKEY_LEN, seal, seal_with_nonce};

    #[test]
    fn sealing_the_vector_inputs_reproduces_the_vector_tag() {
        let v = vector();
        let signing = SigningKey::from_bytes(&bytes(&v.keys.k_sign_seed_hex));
        let tag = seal_with_nonce(
            &bytes(&v.keys.k_enc_hex),
            &signing,
            v.tag.epoch,
            &bytes(&v.tag.nonce_hex),
            &bytes::<ACCOUNT_PUBKEY_LEN>(&v.tag.account_pubkey_hex),
        );
        assert_eq!(
            hex::encode(tag.as_bytes()),
            v.tag.tag_hex,
            "the API must mint exactly the bytes libsodium produced"
        );
    }

    #[test]
    fn seal_draws_a_fresh_nonce_for_every_tag() {
        let v = vector();
        let signing = SigningKey::from_bytes(&bytes(&v.keys.k_sign_seed_hex));
        let k_enc = bytes(&v.keys.k_enc_hex);
        let account = bytes::<ACCOUNT_PUBKEY_LEN>(&v.tag.account_pubkey_hex);
        let first = seal(&k_enc, &signing, v.tag.epoch, &account);
        let second = seal(&k_enc, &signing, v.tag.epoch, &account);
        assert_ne!(
            first.nonce(),
            second.nonce(),
            "a reused nonce makes two tags of one account linkable by any exit"
        );
        assert_ne!(first.ciphertext(), second.ciphertext());
        for tag in [&first, &second] {
            tag.verify(&signing.verifying_key()).expect("verifies");
            assert_eq!(*tag.open(&k_enc).expect("opens"), account);
        }
    }

    #[test]
    fn opening_the_vector_tag_recovers_the_account_pubkey() {
        let v = vector();
        let tag = AttributionTag::from_bytes(&bytes::<TAG_LEN>(&v.tag.tag_hex)).expect("tag");
        let pubkey = tag
            .open(&bytes(&v.keys.k_enc_hex))
            .expect("the vector k_enc opens the vector tag");
        assert_eq!(hex::encode(*pubkey), v.tag.account_pubkey_hex);
    }

    #[test]
    fn opening_under_a_foreign_key_is_refused() {
        let v = vector();
        let tag = AttributionTag::from_bytes(&bytes::<TAG_LEN>(&v.tag.tag_hex)).expect("tag");
        let err = tag
            .open(&bytes(&v.wrong_k_enc_hex))
            .expect_err("a key other than k_enc must not open the tag");
        assert!(matches!(err, AttributionTagError::Undecryptable), "{err:?}");
    }
}
