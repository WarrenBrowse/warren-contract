//! Server-signed **broadcast notices** shown in every client app.
//!
//! **Threat addressed**: a notice is operator-authored text rendered
//! verbatim in the app UI, which makes an unauthenticated channel a
//! ready-made phishing surface ("send your recovery phrase to ..."). A
//! plain JSON body from `GET /v1/notices` would let anything that can
//! answer for the API host, a TLS-terminating middlebox, a hostile
//! resolver, a captive portal, put words in the product's mouth. So the
//! envelope is signed by warren-api's **online** server key, the same key
//! the live relay list is signed with, and the client verifies it against
//! its build-time pin before the text reaches a screen.
//!
//! Two freshness properties make **erasure** real, which a bare list
//! cannot offer:
//!
//! - `generation` is monotonic, so a captured older envelope cannot
//!   resurrect a notice the operator has deleted (anti-rollback).
//! - `expires_at` is signed and short, so nothing can freeze a notice on
//!   a client by simply blocking the refresh (anti-freeze). A client cut
//!   off from the API drops the banner instead of displaying it forever.
//!
//! The offline-signed roster ([`crate::verify_roster`]) exists because a
//! compromised backend must not be able to introduce an exit. That
//! reasoning does not carry here: the operator has to be able to publish
//! and erase a message within minutes, and warren-api is the only thing
//! online at that cadence. A backend compromise can therefore display
//! arbitrary text, which is the accepted boundary, the same one that
//! already applies to the live relay list.

use core::cmp::Ordering;

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use warren_contract::dto::Notice;

use crate::envelope;

/// Current notices envelope version. Bumping = incompatible rotation.
pub const NOTICES_VERSION: u32 = 1;

/// Server-signed notice envelope (full wire form).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedNotices {
    /// Must equal [`NOTICES_VERSION`].
    pub version: u32,
    /// Notices the operator has published and not deleted.
    pub notices: Vec<Notice>,
    /// Monotonic content version (anti-rollback high-water mark). Bumped
    /// by every publish and every delete, so an erasure moves it too.
    pub generation: u64,
    /// Unix epoch seconds the envelope was signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which the envelope is stale. Short: this
    /// is the ceiling on how long a blocked refresh can keep showing a
    /// message the operator has deleted.
    pub expires_at: u64,
    /// 64-char hex of the **server** verifying key.
    pub server_pubkey_hex: String,
    /// 128-char hex Ed25519 signature over the canonical bytes.
    pub signature_hex: String,
}

/// Canonical signing preimage. Field order is frozen; any mutation = v2.
#[derive(Debug, Serialize)]
struct UnsignedNotices<'a> {
    version: u32,
    notices: &'a [Notice],
    generation: u64,
    signed_at: u64,
    expires_at: u64,
    server_pubkey_hex: &'a str,
}

/// Errors specific to the notices envelope.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NoticesError {
    /// Invalid JSON or unexpected structure.
    #[error("invalid signed notices: {0}")]
    Json(#[from] serde_json::Error),
    /// `version != NOTICES_VERSION`.
    #[error("unsupported notices version: {got} (expected {})", NOTICES_VERSION)]
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
    /// The input exceeds the crate's pre-authentication size gate,
    /// rejected before parsing to bound the allocation an untrusted
    /// payload can force.
    #[error("input exceeds the maximum allowed size")]
    InputTooLarge,
}

impl From<envelope::DecodeError> for NoticesError {
    fn from(e: envelope::DecodeError) -> Self {
        match e {
            envelope::DecodeError::InvalidHex => Self::InvalidHex,
            envelope::DecodeError::PubkeyNotOnCurve => Self::PubkeyNotOnCurve,
        }
    }
}

/// A verified envelope: the published notices plus the freshness metadata
/// the caller enforces (monotonic `generation`, `expires_at`).
#[derive(Debug, Clone)]
pub struct VerifiedNotices {
    /// Published notices, in publication order.
    pub notices: Vec<Notice>,
    /// Monotonic content version.
    pub generation: u64,
    /// Unix epoch seconds signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which stale.
    pub expires_at: u64,
}

impl VerifiedNotices {
    /// True if `now_unix_secs` is at or past the signed expiry.
    #[must_use]
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.expires_at
    }

    /// The notices a client should display right now: nothing once the
    /// envelope is stale (anti-freeze), then per-notice TTL and the
    /// declared client-version range.
    ///
    /// `client_version` is the app's own version string. A notice that
    /// declares a range is withheld when the version is absent or
    /// unparseable: a targeted message shown to an untargeted client is
    /// worse than one not shown.
    #[must_use]
    pub fn active_for(&self, now_unix_secs: u64, client_version: Option<&str>) -> Vec<&Notice> {
        if self.is_expired(now_unix_secs) {
            return Vec::new();
        }
        self.notices
            .iter()
            .filter(|n| n.expires_at.is_none_or(|exp| exp > now_unix_secs))
            .filter(|n| version_in_range(client_version, n))
            .collect()
    }
}

/// True if `client_version` satisfies the notice's optional
/// `min_client_version` / `max_client_version` bounds (both inclusive).
/// A notice with no bound at all applies to every client, including one
/// whose version is unknown.
fn version_in_range(client_version: Option<&str>, notice: &Notice) -> bool {
    let min = notice.min_client_version.as_deref();
    let max = notice.max_client_version.as_deref();
    if min.is_none() && max.is_none() {
        return true;
    }
    let Some(client) = client_version else {
        return false;
    };
    if let Some(min) = min
        && cmp_version(client, min).is_none_or(Ordering::is_lt)
    {
        return false;
    }
    if let Some(max) = max
        && cmp_version(client, max).is_none_or(Ordering::is_gt)
    {
        return false;
    }
    true
}

/// Compares two dotted numeric versions component-wise, so `1.11.0`
/// orders above `1.9.0` (a lexicographic compare gets that backwards).
/// A leading `v` and any pre-release suffix (`-beta1`, `+build`) are
/// ignored; missing trailing components read as 0, so `1.9` equals
/// `1.9.0`. `None` when either side carries no leading numeric
/// component, which callers treat as "cannot decide, do not show".
fn cmp_version(a: &str, b: &str) -> Option<Ordering> {
    let left = numeric_components(a)?;
    let right = numeric_components(b)?;
    let len = left.len().max(right.len());
    for i in 0..len {
        let l = left.get(i).copied().unwrap_or(0);
        let r = right.get(i).copied().unwrap_or(0);
        match l.cmp(&r) {
            Ordering::Equal => {}
            other => return Some(other),
        }
    }
    Some(Ordering::Equal)
}

/// Numeric components of a version string, stopping at the first
/// component that does not start with a digit. `None` when the very
/// first component is not numeric.
fn numeric_components(v: &str) -> Option<Vec<u64>> {
    let trimmed = v.trim().trim_start_matches(['v', 'V']);
    let mut out = Vec::new();
    for part in trimmed.split('.') {
        let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            break;
        }
        out.push(digits.parse::<u64>().ok()?);
        if digits.len() != part.len() {
            // Pre-release / build suffix: stop, the numeric prefix decides.
            break;
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Signs a notice envelope with warren-api's **online server key**.
///
/// # Panics
/// Panics only if `serde_json::to_vec(&UnsignedNotices)` fails, which is
/// infallible for this scalar/owned-string schema.
#[must_use]
pub fn sign_notices(
    notices: Vec<Notice>,
    server_key: &SigningKey,
    generation: u64,
    signed_at: u64,
    expires_at: u64,
) -> SignedNotices {
    let server_pubkey_hex = hex::encode(server_key.verifying_key().as_bytes());
    let unsigned = UnsignedNotices {
        version: NOTICES_VERSION,
        notices: &notices,
        generation,
        signed_at,
        expires_at,
        server_pubkey_hex: &server_pubkey_hex,
    };
    let canonical =
        serde_json::to_vec(&unsigned).expect("UnsignedNotices JSON serialization is infallible");
    let signature = server_key.sign(&canonical);
    SignedNotices {
        version: NOTICES_VERSION,
        notices,
        generation,
        signed_at,
        expires_at,
        server_pubkey_hex,
        signature_hex: hex::encode(signature.to_bytes()),
    }
}

/// Verifies an envelope's signature against the pinned **server** pubkey.
///
/// # Errors
/// - [`NoticesError::InputTooLarge`]: `s` exceeds the pre-authentication
///   size gate.
/// - [`NoticesError::Json`]: invalid JSON.
/// - [`NoticesError::UnsupportedVersion`]: `version != NOTICES_VERSION`.
/// - [`NoticesError::ServerPubkeyMismatch`]: server pubkey not pinned.
/// - [`NoticesError::InvalidHex`] / [`NoticesError::PubkeyNotOnCurve`] /
///   [`NoticesError::BadSignature`]: malformed or invalid signature.
pub fn verify_signed_notices(
    s: &str,
    expected_server_pubkey: Option<&str>,
) -> Result<VerifiedNotices, NoticesError> {
    match expected_server_pubkey {
        Some(p) => verify_signed_notices_any(s, &[p]),
        None => verify_signed_notices_any(s, &[]),
    }
}

/// Multi-key variant of [`verify_signed_notices`] for pinned-key
/// rotation: accepts the envelope if signed by **any** of
/// `expected_server_pubkeys`. Empty slice = TOFU.
///
/// # Errors
/// Same as [`verify_signed_notices`].
pub fn verify_signed_notices_any(
    s: &str,
    expected_server_pubkeys: &[&str],
) -> Result<VerifiedNotices, NoticesError> {
    if s.len() > envelope::MAX_VERIFY_INPUT_LEN {
        return Err(NoticesError::InputTooLarge);
    }
    let signed: SignedNotices = serde_json::from_str(s)?;
    if signed.version != NOTICES_VERSION {
        return Err(NoticesError::UnsupportedVersion {
            got: signed.version,
        });
    }
    if !envelope::pin_allows(expected_server_pubkeys, &signed.server_pubkey_hex) {
        let (got, expected) =
            envelope::redact_pin_mismatch(expected_server_pubkeys, &signed.server_pubkey_hex);
        return Err(NoticesError::ServerPubkeyMismatch { got, expected });
    }
    let server_pubkey = envelope::decode_verifying_key(&signed.server_pubkey_hex)?;
    let signature = envelope::decode_signature(&signed.signature_hex)?;

    let unsigned = UnsignedNotices {
        version: signed.version,
        notices: &signed.notices,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
        server_pubkey_hex: &signed.server_pubkey_hex,
    };
    let canonical = serde_json::to_vec(&unsigned).map_err(NoticesError::Json)?;
    // verify_strict: defense in depth, rejects small-order/non-canonical
    // signatures the basic verification equation would still accept.
    server_pubkey
        .verify_strict(&canonical, &signature)
        .map_err(|_| NoticesError::BadSignature)?;

    Ok(VerifiedNotices {
        notices: signed.notices,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use warren_contract::dto::NoticeLevel;

    fn server_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    fn other_key() -> SigningKey {
        SigningKey::from_bytes(&[0x22; 32])
    }

    fn notice(id: &str, message: &str) -> Notice {
        Notice {
            id: id.to_owned(),
            message: message.to_owned(),
            level: NoticeLevel::Info,
            min_client_version: None,
            max_client_version: None,
            expires_at: None,
        }
    }

    fn signed_json(notices: Vec<Notice>, generation: u64) -> String {
        let signed = sign_notices(
            notices,
            &server_key(),
            generation,
            1_700_000_000,
            1_700_021_600,
        );
        serde_json::to_string(&signed).expect("serialize")
    }

    #[test]
    fn verifies_a_freshly_signed_envelope_and_returns_its_notices() {
        let json = signed_json(vec![notice("a1", "scheduled maintenance tonight")], 7);
        let pin = hex::encode(server_key().verifying_key().as_bytes());

        let verified = verify_signed_notices(&json, Some(&pin)).expect("must verify");

        assert_eq!(
            verified.generation, 7,
            "generation must survive the round-trip"
        );
        assert_eq!(
            verified.notices.first().map(|n| n.message.as_str()),
            Some("scheduled maintenance tonight"),
            "the operator's text must reach the caller intact"
        );
    }

    #[test]
    fn rejects_an_envelope_signed_by_an_unpinned_key() {
        let signed = sign_notices(
            vec![notice("a1", "give us your recovery phrase")],
            &other_key(),
            1,
            1_700_000_000,
            1_700_021_600,
        );
        let json = serde_json::to_string(&signed).expect("serialize");
        let pin = hex::encode(server_key().verifying_key().as_bytes());

        let err = verify_signed_notices(&json, Some(&pin)).expect_err("must not verify");

        assert!(
            matches!(err, NoticesError::ServerPubkeyMismatch { .. }),
            "a foreign signer is the phishing case this format exists to block: {err}"
        );
    }

    #[test]
    fn rejects_a_tampered_message_under_a_valid_signature_header() {
        let json = signed_json(vec![notice("a1", "all good")], 1);
        let tampered = json.replace("all good", "all bad!");
        let pin = hex::encode(server_key().verifying_key().as_bytes());

        let err = verify_signed_notices(&tampered, Some(&pin)).expect_err("must not verify");

        assert!(
            matches!(err, NoticesError::BadSignature),
            "editing the text in flight must break the signature: {err}"
        );
    }

    #[test]
    fn rejects_an_unknown_envelope_version() {
        let json = signed_json(vec![], 1).replace("\"version\":1", "\"version\":2");
        let pin = hex::encode(server_key().verifying_key().as_bytes());

        let err = verify_signed_notices(&json, Some(&pin)).expect_err("must not verify");

        assert!(
            matches!(err, NoticesError::UnsupportedVersion { got: 2 }),
            "unknown version must be refused, not best-effort parsed: {err}"
        );
    }

    #[test]
    fn rejects_input_above_the_pre_auth_size_gate() {
        let oversized = "x".repeat(envelope::MAX_VERIFY_INPUT_LEN + 1);

        let err = verify_signed_notices(&oversized, None).expect_err("must not parse");

        assert!(
            matches!(err, NoticesError::InputTooLarge),
            "the size gate must fire before any parsing: {err}"
        );
    }

    #[test]
    fn a_stale_envelope_displays_nothing() {
        let verified = VerifiedNotices {
            notices: vec![notice("a1", "still showing?")],
            generation: 1,
            signed_at: 1_700_000_000,
            expires_at: 1_700_021_600,
        };

        assert!(
            verified.active_for(1_700_021_600, None).is_empty(),
            "anti-freeze: a blocked refresh must not keep a deleted notice on screen"
        );
        assert_eq!(
            verified.active_for(1_700_021_599, None).len(),
            1,
            "one second before expiry the notice still shows"
        );
    }

    #[test]
    fn a_notice_past_its_own_expiry_is_filtered_out() {
        let mut n = notice("a1", "ends at noon");
        n.expires_at = Some(1_700_010_000);
        let verified = VerifiedNotices {
            notices: vec![n],
            generation: 1,
            signed_at: 1_700_000_000,
            expires_at: 1_700_021_600,
        };

        assert!(
            verified.active_for(1_700_010_000, None).is_empty(),
            "the per-notice TTL must be enforced client-side too"
        );
    }

    #[test]
    fn version_bounds_target_the_intended_clients() {
        let mut n = notice("a1", "upgrade past 1.10");
        n.min_client_version = Some("1.10.0".to_owned());
        let verified = VerifiedNotices {
            notices: vec![n],
            generation: 1,
            signed_at: 1_700_000_000,
            expires_at: 1_700_021_600,
        };
        let now = 1_700_000_100;

        assert_eq!(
            verified.active_for(now, Some("1.11.0")).len(),
            1,
            "1.11.0 is above the 1.10.0 floor (a lexicographic compare gets this wrong)"
        );
        assert!(
            verified.active_for(now, Some("1.9.0")).is_empty(),
            "1.9.0 is below the floor"
        );
        assert!(
            verified.active_for(now, None).is_empty(),
            "a targeted notice must not leak to a client of unknown version"
        );
    }

    #[test]
    fn an_untargeted_notice_shows_even_without_a_client_version() {
        let verified = VerifiedNotices {
            notices: vec![notice("a1", "for everyone")],
            generation: 1,
            signed_at: 1_700_000_000,
            expires_at: 1_700_021_600,
        };

        assert_eq!(
            verified.active_for(1_700_000_100, None).len(),
            1,
            "no declared range means every client, whatever it reports"
        );
    }

    #[test]
    fn max_bound_is_inclusive_and_suffixed_versions_compare_on_their_numbers() {
        let mut n = notice("a1", "last call for 1.9");
        n.max_client_version = Some("1.9.0".to_owned());
        let verified = VerifiedNotices {
            notices: vec![n],
            generation: 1,
            signed_at: 1_700_000_000,
            expires_at: 1_700_021_600,
        };
        let now = 1_700_000_100;

        assert_eq!(
            verified.active_for(now, Some("1.9.0-beta2")).len(),
            1,
            "a pre-release suffix must not push the version past its own ceiling"
        );
        assert!(
            verified.active_for(now, Some("1.9.1")).is_empty(),
            "1.9.1 is above the 1.9.0 ceiling"
        );
    }

    #[test]
    fn signature_covers_the_generation_so_a_rollback_cannot_be_forged() {
        let json = signed_json(vec![notice("a1", "x")], 9);
        let rolled_back = json.replace("\"generation\":9", "\"generation\":2");
        let pin = hex::encode(server_key().verifying_key().as_bytes());

        let err = verify_signed_notices(&rolled_back, Some(&pin)).expect_err("must not verify");

        assert!(
            matches!(err, NoticesError::BadSignature),
            "anti-rollback rests on the generation being signed: {err}"
        );
    }

    #[test]
    fn canonical_bytes_are_frozen() {
        // Pins the wire preimage: a field reorder or rename silently
        // invalidates every deployed client's verification, so the exact
        // signature over a fixed input is the regression alarm.
        let signed = sign_notices(
            vec![notice("0000000000000001", "hello")],
            &server_key(),
            3,
            1_700_000_000,
            1_700_021_600,
        );
        assert_eq!(
            signed.signature_hex,
            "9c8312bd59c7caad5a80f76c07d4fdf194cda7f36672bdb3cf7ec03af3fce867\
             9a5426d6f23a1d23e44cfd35fd7d39db7fa9984b2e1fa57a931934680fcca900",
            "frozen canonical signature"
        );
    }
}
