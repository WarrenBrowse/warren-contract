//! Replays the shared golden vector `vectors/announcements_v1.json`.
//!
//! The announcement envelope is a new wire that three client families and
//! the backend will implement separately, so the canonical preimage is
//! pinned in the cross-language corpus rather than only in this crate's
//! own frozen-signature test: a sibling SDK that composes the preimage
//! differently has to fail here, not in production on a user's home
//! screen. Every value in the file is synthetic.

use ed25519_dalek::{Signer, SigningKey};
use warren_discovery_core::{
    ANNOUNCEMENTS_VERSION, Announcement, sign_announcements, verify_signed_announcements,
};

#[derive(serde::Deserialize)]
struct Vector {
    version: u32,
    signer: VectorSigner,
    envelope: Envelope,
    announcements: Vec<Announcement>,
    canonical_preimage_utf8: String,
    signature_hex: String,
    signed_json: String,
}

#[derive(serde::Deserialize)]
struct VectorSigner {
    signing_key_hex: String,
    server_pubkey_hex: String,
}

#[derive(serde::Deserialize)]
struct Envelope {
    generation: u64,
    signed_at: u64,
    expires_at: u64,
}

fn vector() -> Vector {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vectors/announcements_v1.json"
    );
    let raw = std::fs::read_to_string(path).expect(
        "read vectors/announcements_v1.json (run `git submodule update --init vectors` once)",
    );
    serde_json::from_str(&raw).expect("parse vectors/announcements_v1.json")
}

fn signing_key(hex_str: &str) -> SigningKey {
    let bytes: [u8; 32] = hex::decode(hex_str)
        .expect("signing key hex")
        .try_into()
        .expect("32 bytes");
    SigningKey::from_bytes(&bytes)
}

#[test]
fn the_pinned_preimage_is_what_the_pinned_signature_covers() {
    let v = vector();
    assert_eq!(v.version, ANNOUNCEMENTS_VERSION, "vector envelope version");
    let key = signing_key(&v.signer.signing_key_hex);
    assert_eq!(
        hex::encode(key.verifying_key().as_bytes()),
        v.signer.server_pubkey_hex,
        "the pinned pubkey must be the one the pinned signing key produces"
    );

    // A sibling SDK builds this exact string and signs it. Pinning the
    // bytes AND the signature over them is what makes a field reorder in
    // another language fail here rather than on a user's screen.
    let signature = key.sign(v.canonical_preimage_utf8.as_bytes());
    assert_eq!(
        hex::encode(signature.to_bytes()),
        v.signature_hex,
        "the canonical preimage string is the signed message"
    );
}

#[test]
fn signing_the_pinned_announcements_reproduces_the_pinned_document() {
    let v = vector();
    let key = signing_key(&v.signer.signing_key_hex);

    let signed = sign_announcements(
        v.announcements,
        &key,
        v.envelope.generation,
        v.envelope.signed_at,
        v.envelope.expires_at,
    );

    assert_eq!(
        signed.signature_hex, v.signature_hex,
        "this crate must sign the corpus announcements byte-identically"
    );
    assert_eq!(
        serde_json::to_string(&signed).expect("serialize"),
        v.signed_json,
        "the published document is frozen field for field, nulls included"
    );
}

#[test]
fn the_pinned_document_verifies_and_renders_what_the_vector_declares() {
    let v = vector();

    let verified = verify_signed_announcements(&v.signed_json, Some(&v.signer.server_pubkey_hex))
        .expect("the corpus document must verify against its own pinned key");

    assert_eq!(verified.generation, v.envelope.generation);
    assert_eq!(verified.announcements, v.announcements);

    let active = verified.active_for(v.envelope.signed_at, Some("1.2.0"));
    assert_eq!(
        active.len(),
        3,
        "every pinned announcement targets a 1.2.0 client"
    );
    assert_eq!(
        active[0].displayable_cta().map(|c| c.url.as_str()),
        Some("https://download.example.test/warren"),
        "the pinned CTA is an https link with no credentials, so it stays clickable"
    );
    assert_eq!(
        active[0].voucher_campaign_id.as_deref(),
        Some("prod-launch"),
        "the campaign id IS the offer, so the client knows which voucher to go and claim"
    );
    assert!(
        active[1].displayable_cta().is_none(),
        "the pinned minimal announcement carries no CTA"
    );
    assert!(
        !active[1].offers_voucher(),
        "no campaign id is no offer, with no second state to disagree with it"
    );
    assert_eq!(
        active[2].displayable_cta().map(|c| c.url.as_str()),
        Some("https://download.example.test/terms?a=1&b=2"),
        "a CTA carrying two query parameters keeps its ampersand and stays clickable"
    );

    assert!(
        verified
            .active_for(v.envelope.expires_at, Some("1.2.0"))
            .is_empty(),
        "anti-freeze: at the pinned expiry the corpus document shows nothing"
    );
}

/// The corpus body is deliberately hostile to a naive JSON encoder. This
/// asserts the bytes an implementation has to reproduce, so a language
/// whose encoder escapes `&`, `<`, `>` or non-ASCII by default fails with
/// the reason in front of it rather than with a bare `BadSignature`.
#[test]
fn the_signed_bytes_carry_raw_utf8_and_unescaped_html_characters() {
    let v = vector();
    let body = &v.announcements[2].body;

    assert!(
        body.contains('&') && body.contains('<') && body.contains('>'),
        "Go's encoding/json escapes these three by default: the corpus must carry them"
    );
    assert!(
        !body.is_ascii(),
        "Python json.dumps and Jackson's ESCAPE_NON_ASCII emit \\uXXXX here: the corpus \
         must carry a character that exposes it"
    );
    assert!(
        !v.canonical_preimage_utf8.contains("\\u"),
        "the canonical preimage is raw UTF-8: not one character is \\uXXXX-escaped"
    );
    assert!(
        v.canonical_preimage_utf8.contains(body.as_str()),
        "the signed preimage embeds the body byte for byte, unescaped"
    );
}
