//! Server-signed **forum activity digest**: one unread count per forum
//! account, broadcast to every client as a single artefact.
//!
//! **Threat addressed**: telling a user "you have a reply on the forum"
//! must not require asking the server about that user. A per-account
//! query would hand the backend a presence signal keyed to a wallet, and
//! it would let anyone able to answer for the API host raise a badge that
//! lures a click. So the server publishes ONE document, identical for
//! every client, and each client reads its own slot out of it: the server
//! learns nothing about who is asking about whom, because nobody asks
//! about anybody.
//!
//! A slot index is assigned at random by the forum-identity provider when
//! an account first logs in, and only that account's device knows it. The
//! published document is therefore an anonymous array of counts: holding
//! all of it, plus the whole public forum, still does not say which slot
//! belongs to which forum name.
//!
//! Counts are packed one per lowercase hex character, so the string is
//! its own length prefix and a slot is a single index. A count at or
//! above [`UNREAD_SATURATED`] is clamped to it, which bounds the document
//! and is all a badge needs.
//!
//! The freshness properties are the ones [`crate::SignedNotices`] already
//! rests on, for the same reasons: `generation` is monotonic so a
//! captured older document cannot resurrect counts the user has already
//! cleared, and `expires_at` is signed and short so blocking the refresh
//! drops the badge instead of freezing one on screen.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};

use crate::envelope;

/// Current forum-digest envelope version. Bumping = incompatible rotation.
pub const FORUM_DIGEST_VERSION: u32 = 1;

/// Count meaning "this many or more". One hex character holds 0..=15, and
/// a badge stops being informative long before that, so the top value is
/// a saturating bucket rather than an exact figure.
pub const UNREAD_SATURATED: u8 = 15;

/// Server-signed forum digest (full wire form).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedForumDigest {
    /// Must equal [`FORUM_DIGEST_VERSION`].
    pub version: u32,
    /// One lowercase hex character per slot: the unread count for that
    /// slot, `f` meaning [`UNREAD_SATURATED`] or more. The length is the
    /// number of published slots.
    pub counts_hex: String,
    /// Monotonic content version (anti-rollback high-water mark).
    pub generation: u64,
    /// Unix epoch seconds the document was signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which the document is stale. Short: this
    /// is the ceiling on how long a blocked refresh can keep showing a
    /// badge the user has already cleared.
    pub expires_at: u64,
    /// 64-char hex of the **server** verifying key.
    pub server_pubkey_hex: String,
    /// 128-char hex Ed25519 signature over the canonical bytes.
    pub signature_hex: String,
}

/// Canonical signing preimage. Field order is frozen; any mutation = v2.
#[derive(Debug, Serialize)]
struct UnsignedForumDigest<'a> {
    version: u32,
    counts_hex: &'a str,
    generation: u64,
    signed_at: u64,
    expires_at: u64,
    server_pubkey_hex: &'a str,
}

/// Errors specific to the forum-digest envelope.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ForumDigestError {
    /// Invalid JSON or unexpected structure.
    #[error("invalid signed forum digest: {0}")]
    Json(#[from] serde_json::Error),
    /// `version != FORUM_DIGEST_VERSION`.
    #[error(
        "unsupported forum digest version: {got} (expected {})",
        FORUM_DIGEST_VERSION
    )]
    UnsupportedVersion {
        /// Version actually received in the JSON.
        got: u32,
    },
    /// The declared server pubkey does not match the client's pin.
    #[error("server pubkey mismatch: got {got}, expected {expected}")]
    ServerPubkeyMismatch {
        /// Redacted prefix of the pubkey hex announced in the JSON
        /// (no-log discipline: never the full key).
        got: String,
        /// Redacted prefix of the pubkey hex pinned on the client.
        expected: String,
    },
    /// Invalid hex for `server_pubkey_hex` or `signature_hex`.
    #[error("invalid hex encoding")]
    InvalidHex,
    /// Received pubkey is not a valid Ed25519 point.
    #[error("server pubkey is not a valid Ed25519 point")]
    PubkeyNotOnCurve,
    /// Signature does not verify against `(server_pubkey, canonical_bytes)`.
    #[error("signature verification failed")]
    BadSignature,
    /// `counts_hex` carries a character outside `0-9a-f`. Only reachable
    /// on a correctly signed document, so it means the server emitted
    /// something malformed rather than that anyone tampered.
    #[error("counts field is not lowercase hex")]
    InvalidCounts,
    /// The input exceeds the crate's pre-authentication size gate,
    /// rejected before parsing to bound the allocation an untrusted
    /// payload can force.
    #[error("input exceeds the maximum allowed size")]
    InputTooLarge,
}

impl From<envelope::DecodeError> for ForumDigestError {
    fn from(e: envelope::DecodeError) -> Self {
        match e {
            envelope::DecodeError::InvalidHex => Self::InvalidHex,
            envelope::DecodeError::PubkeyNotOnCurve => Self::PubkeyNotOnCurve,
        }
    }
}

/// A verified digest: the published counts plus the freshness metadata
/// the caller enforces (monotonic `generation`, `expires_at`).
#[derive(Debug, Clone)]
pub struct VerifiedForumDigest {
    counts_hex: String,
    /// Monotonic content version.
    pub generation: u64,
    /// Unix epoch seconds signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which stale.
    pub expires_at: u64,
}

impl VerifiedForumDigest {
    /// True if `now_unix_secs` is at or past the signed expiry.
    #[must_use]
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.expires_at
    }

    /// Number of slots the server published.
    #[must_use]
    pub fn slots(&self) -> usize {
        self.counts_hex.len()
    }

    /// Unread count for `slot`, capped at [`UNREAD_SATURATED`].
    ///
    /// Zero once the document is stale (anti-freeze), and zero for a slot
    /// the server has not published yet, which is the normal state of an
    /// account that registered since the last rebuild.
    #[must_use]
    pub fn unread_for(&self, now_unix_secs: u64, slot: u32) -> u8 {
        if self.is_expired(now_unix_secs) {
            return 0;
        }
        let Ok(index) = usize::try_from(slot) else {
            return 0;
        };
        self.counts_hex
            .as_bytes()
            .get(index)
            .and_then(|c| char::from(*c).to_digit(16))
            .and_then(|d| u8::try_from(d).ok())
            .unwrap_or(0)
    }
}

/// Packs one unread count per slot into the wire form, clamping each to
/// [`UNREAD_SATURATED`]. Slot `i` is character `i`.
#[must_use]
pub fn pack_unread_counts(counts: &[u32]) -> String {
    counts
        .iter()
        .map(|c| {
            let clamped = (*c).min(u32::from(UNREAD_SATURATED));
            char::from_digit(clamped, 16).unwrap_or('0')
        })
        .collect()
}

/// Signs a forum digest with warren-api's **online server key**.
///
/// # Panics
/// Panics only if `serde_json::to_vec(&UnsignedForumDigest)` fails, which
/// is infallible for this scalar/owned-string schema.
#[must_use]
pub fn sign_forum_digest(
    counts_hex: String,
    server_key: &SigningKey,
    generation: u64,
    signed_at: u64,
    expires_at: u64,
) -> SignedForumDigest {
    let server_pubkey_hex = hex::encode(server_key.verifying_key().as_bytes());
    let unsigned = UnsignedForumDigest {
        version: FORUM_DIGEST_VERSION,
        counts_hex: &counts_hex,
        generation,
        signed_at,
        expires_at,
        server_pubkey_hex: &server_pubkey_hex,
    };
    let canonical = serde_json::to_vec(&unsigned)
        .expect("UnsignedForumDigest JSON serialization is infallible");
    let signature = server_key.sign(&canonical);
    SignedForumDigest {
        version: FORUM_DIGEST_VERSION,
        counts_hex,
        generation,
        signed_at,
        expires_at,
        server_pubkey_hex,
        signature_hex: hex::encode(signature.to_bytes()),
    }
}

/// Verifies a digest's signature against the pinned **server** pubkey.
///
/// # Errors
/// - [`ForumDigestError::InputTooLarge`]: `s` exceeds the
///   pre-authentication size gate.
/// - [`ForumDigestError::Json`]: invalid JSON.
/// - [`ForumDigestError::UnsupportedVersion`]: version mismatch.
/// - [`ForumDigestError::ServerPubkeyMismatch`]: server pubkey not pinned.
/// - [`ForumDigestError::InvalidHex`] /
///   [`ForumDigestError::PubkeyNotOnCurve`] /
///   [`ForumDigestError::BadSignature`]: malformed or invalid signature.
/// - [`ForumDigestError::InvalidCounts`]: signed but malformed counts.
pub fn verify_forum_digest(
    s: &str,
    expected_server_pubkey: Option<&str>,
) -> Result<VerifiedForumDigest, ForumDigestError> {
    match expected_server_pubkey {
        Some(p) => verify_forum_digest_any(s, &[p]),
        None => verify_forum_digest_any(s, &[]),
    }
}

/// Multi-key variant of [`verify_forum_digest`] for pinned-key rotation:
/// accepts the document if signed by **any** of
/// `expected_server_pubkeys`. Empty slice = TOFU.
///
/// # Errors
/// Same as [`verify_forum_digest`].
pub fn verify_forum_digest_any(
    s: &str,
    expected_server_pubkeys: &[&str],
) -> Result<VerifiedForumDigest, ForumDigestError> {
    if s.len() > envelope::MAX_VERIFY_INPUT_LEN {
        return Err(ForumDigestError::InputTooLarge);
    }
    let signed: SignedForumDigest = serde_json::from_str(s)?;
    if signed.version != FORUM_DIGEST_VERSION {
        return Err(ForumDigestError::UnsupportedVersion {
            got: signed.version,
        });
    }
    if !envelope::pin_allows(expected_server_pubkeys, &signed.server_pubkey_hex) {
        let (got, expected) =
            envelope::redact_pin_mismatch(expected_server_pubkeys, &signed.server_pubkey_hex);
        return Err(ForumDigestError::ServerPubkeyMismatch { got, expected });
    }
    let server_pubkey = envelope::decode_verifying_key(&signed.server_pubkey_hex)?;
    let signature = envelope::decode_signature(&signed.signature_hex)?;

    let unsigned = UnsignedForumDigest {
        version: signed.version,
        counts_hex: &signed.counts_hex,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
        server_pubkey_hex: &signed.server_pubkey_hex,
    };
    let canonical = serde_json::to_vec(&unsigned).map_err(ForumDigestError::Json)?;
    // verify_strict: defense in depth, rejects small-order/non-canonical
    // signatures the basic verification equation would still accept.
    server_pubkey
        .verify_strict(&canonical, &signature)
        .map_err(|_| ForumDigestError::BadSignature)?;

    // Checked after the signature so a malformed field can only ever be
    // read as a server bug, never confused with tampering.
    if !signed
        .counts_hex
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ForumDigestError::InvalidCounts);
    }

    Ok(VerifiedForumDigest {
        counts_hex: signed.counts_hex,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNED_AT: u64 = 1_700_000_000;
    const EXPIRES_AT: u64 = 1_700_021_600;

    fn server_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    fn other_key() -> SigningKey {
        SigningKey::from_bytes(&[0x22; 32])
    }

    fn signed_json(counts: &[u32], generation: u64) -> String {
        let signed = sign_forum_digest(
            pack_unread_counts(counts),
            &server_key(),
            generation,
            SIGNED_AT,
            EXPIRES_AT,
        );
        serde_json::to_string(&signed).expect("serialize")
    }

    fn pin() -> String {
        hex::encode(server_key().verifying_key().as_bytes())
    }

    #[test]
    fn reads_the_count_of_the_slot_that_owns_it() {
        let json = signed_json(&[0, 3, 0, 7], 4);

        let verified = verify_forum_digest(&json, Some(&pin())).expect("must verify");

        assert_eq!(
            verified.unread_for(SIGNED_AT, 1),
            3,
            "a slot must read back the count published for it"
        );
        assert_eq!(
            verified.unread_for(SIGNED_AT, 0),
            0,
            "a neighbouring slot must not bleed into another account's badge"
        );
        assert_eq!(verified.slots(), 4, "the string length is the slot count");
    }

    #[test]
    fn rejects_a_digest_signed_by_an_unpinned_key() {
        let signed = sign_forum_digest(
            pack_unread_counts(&[9]),
            &other_key(),
            1,
            SIGNED_AT,
            EXPIRES_AT,
        );
        let json = serde_json::to_string(&signed).expect("serialize");

        let err = verify_forum_digest(&json, Some(&pin())).expect_err("must not verify");

        assert!(
            matches!(err, ForumDigestError::ServerPubkeyMismatch { .. }),
            "an unpinned key must not be able to raise a badge that lures a click: {err}"
        );
    }

    #[test]
    fn a_stale_document_shows_no_badge() {
        let json = signed_json(&[5], 1);

        let verified = verify_forum_digest(&json, Some(&pin())).expect("must verify");

        assert_eq!(
            verified.unread_for(EXPIRES_AT, 0),
            0,
            "blocking the refresh must drop the badge, never freeze one on screen"
        );
    }

    #[test]
    fn a_slot_beyond_the_published_range_reads_as_no_activity() {
        let json = signed_json(&[1, 2], 1);

        let verified = verify_forum_digest(&json, Some(&pin())).expect("must verify");

        assert_eq!(
            verified.unread_for(SIGNED_AT, 9),
            0,
            "an account registered since the last rebuild must read zero, not panic"
        );
    }

    #[test]
    fn a_count_above_the_ceiling_saturates() {
        let json = signed_json(&[400], 1);

        let verified = verify_forum_digest(&json, Some(&pin())).expect("must verify");

        assert_eq!(
            verified.unread_for(SIGNED_AT, 0),
            UNREAD_SATURATED,
            "the top value is a saturating bucket, so a busy account still fits one character"
        );
    }

    #[test]
    fn rejects_a_tampered_count_under_a_valid_signature_header() {
        let json = signed_json(&[0, 0], 1);
        let tampered = json.replace("\"counts_hex\":\"00\"", "\"counts_hex\":\"09\"");

        let err = verify_forum_digest(&tampered, Some(&pin())).expect_err("must not verify");

        assert!(
            matches!(err, ForumDigestError::BadSignature),
            "the counts are what the signature exists to protect: {err}"
        );
    }

    #[test]
    fn signature_covers_the_generation_so_a_rollback_cannot_be_forged() {
        let json = signed_json(&[1], 9);
        let rolled_back = json.replace("\"generation\":9", "\"generation\":2");

        let err = verify_forum_digest(&rolled_back, Some(&pin())).expect_err("must not verify");

        assert!(
            matches!(err, ForumDigestError::BadSignature),
            "anti-rollback rests on the generation being signed: {err}"
        );
    }

    #[test]
    fn rejects_an_unknown_envelope_version() {
        let json = signed_json(&[1], 1).replace("\"version\":1", "\"version\":2");

        let err = verify_forum_digest(&json, Some(&pin())).expect_err("must not verify");

        assert!(
            matches!(err, ForumDigestError::UnsupportedVersion { got: 2 }),
            "an unknown version must be refused rather than guessed at: {err}"
        );
    }

    #[test]
    fn rejects_a_signed_but_malformed_counts_field() {
        // Signed by the pinned key, so only the field itself is wrong.
        let signed = sign_forum_digest("0z".to_owned(), &server_key(), 1, SIGNED_AT, EXPIRES_AT);
        let json = serde_json::to_string(&signed).expect("serialize");

        let err = verify_forum_digest(&json, Some(&pin())).expect_err("must not verify");

        assert!(
            matches!(err, ForumDigestError::InvalidCounts),
            "a malformed field from our own server must be named as such: {err}"
        );
    }

    #[test]
    fn rejects_input_above_the_pre_auth_size_gate() {
        let oversized = "x".repeat(envelope::MAX_VERIFY_INPUT_LEN + 1);

        let err = verify_forum_digest(&oversized, Some(&pin())).expect_err("must not verify");

        assert!(
            matches!(err, ForumDigestError::InputTooLarge),
            "an unauthenticated payload must not force an unbounded parse: {err}"
        );
    }

    #[test]
    fn canonical_bytes_are_frozen() {
        // Pins the wire preimage: a field reorder or rename silently
        // invalidates every deployed client's verification, so the exact
        // signature over a fixed input is the regression alarm.
        let signed = sign_forum_digest(
            pack_unread_counts(&[0, 3, 15]),
            &server_key(),
            3,
            SIGNED_AT,
            EXPIRES_AT,
        );
        assert_eq!(signed.counts_hex, "03f", "one hex character per slot");
        assert_eq!(
            signed.signature_hex,
            "042fda7c698691b955117cd10da6826bc13ec45a0c93b15276b2392da499b97d\
             e13bf3a1e796082f12d81104aa44d0e1bcced51c772b2b854c4655791511b404",
            "frozen canonical signature"
        );
    }
}
