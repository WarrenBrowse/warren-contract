//! Server-signed **launch announcements** rendered as a card in every
//! client app.
//!
//! A separate envelope from [`crate::SignedNotices`], and the separation
//! is the whole point. Notice verification rebuilds the canonical
//! preimage **from the client's own `Notice` struct**, so a field the
//! server signs and a deployed client does not know yields
//! `BadSignature` and that client then shows **nothing at all**, not
//! merely the new content. Bumping `NOTICES_VERSION` is no better: every
//! v1 client hits `UnsupportedVersion` and drops the whole set. Either
//! move takes the operator's ordinary broadcast channel offline for
//! everyone who has not updated, silently, with the failure looking
//! exactly like "nothing published". So an announcement rides its own
//! version constant, its own `Signed` / `Unsigned` / `Verified` triple
//! and its own endpoint, and deployed clients never see it.
//!
//! The threat model is the one notices already carry: an announcement is
//! operator-authored text rendered verbatim on the home screen, plus a
//! clickable link, which makes an unauthenticated channel a ready-made
//! phishing surface. The envelope is signed by warren-api's **online**
//! server key and verified against the client's build-time pin before a
//! character reaches a screen. The link is checked a second time, by
//! [`Announcement::displayable_cta`], because a signature proves who
//! wrote a URL and not that the URL is safe to click.
//!
//! Freshness is likewise the notices contract: `generation` is monotonic
//! so a captured older envelope cannot resurrect a withdrawn
//! announcement, and `expires_at` is signed and short so blocking the
//! refresh drops the card instead of freezing one on screen.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use warren_contract::dto::Announcement;

use crate::{envelope, version_range};

/// Current announcements envelope version. Bumping = incompatible
/// rotation, and every deployed client drops the whole document, so it
/// is a last resort rather than the way to add a field.
pub const ANNOUNCEMENTS_VERSION: u32 = 1;

/// Server-signed announcement envelope (full wire form).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedAnnouncements {
    /// Must equal [`ANNOUNCEMENTS_VERSION`].
    pub version: u32,
    /// Announcements the operator has published and not deleted.
    pub announcements: Vec<Announcement>,
    /// Monotonic content version (anti-rollback high-water mark). Bumped
    /// by every publish and every delete, so a withdrawal moves it too.
    pub generation: u64,
    /// Unix epoch seconds the envelope was signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which the envelope is stale. Short: this
    /// is the ceiling on how long a blocked refresh can keep showing a
    /// card the operator has withdrawn.
    pub expires_at: u64,
    /// 64-char hex of the **server** verifying key.
    pub server_pubkey_hex: String,
    /// 128-char hex Ed25519 signature over the canonical bytes.
    pub signature_hex: String,
}

/// Canonical signing preimage. Field order is frozen; any mutation = v2.
#[derive(Debug, Serialize)]
struct UnsignedAnnouncements<'a> {
    version: u32,
    announcements: &'a [Announcement],
    generation: u64,
    signed_at: u64,
    expires_at: u64,
    server_pubkey_hex: &'a str,
}

/// Errors specific to the announcements envelope.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AnnouncementsError {
    /// Invalid JSON or unexpected structure.
    #[error("invalid signed announcements: {0}")]
    Json(#[from] serde_json::Error),
    /// `version != ANNOUNCEMENTS_VERSION`.
    #[error(
        "unsupported announcements version: {got} (expected {})",
        ANNOUNCEMENTS_VERSION
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
    /// The input exceeds the crate's pre-authentication size gate,
    /// rejected before parsing to bound the allocation an untrusted
    /// payload can force.
    #[error("input exceeds the maximum allowed size")]
    InputTooLarge,
}

impl From<envelope::DecodeError> for AnnouncementsError {
    fn from(e: envelope::DecodeError) -> Self {
        match e {
            envelope::DecodeError::InvalidHex => Self::InvalidHex,
            envelope::DecodeError::PubkeyNotOnCurve => Self::PubkeyNotOnCurve,
        }
    }
}

/// A verified envelope: the published announcements plus the freshness
/// metadata the caller enforces (monotonic `generation`, `expires_at`).
#[derive(Debug, Clone)]
pub struct VerifiedAnnouncements {
    /// Published announcements, in publication order.
    pub announcements: Vec<Announcement>,
    /// Monotonic content version.
    pub generation: u64,
    /// Unix epoch seconds signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which stale.
    pub expires_at: u64,
}

impl VerifiedAnnouncements {
    /// True if `now_unix_secs` is at or past the signed expiry.
    #[must_use]
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.expires_at
    }

    /// The announcements a client should display right now: nothing once
    /// the envelope is stale (anti-freeze), then the per-announcement TTL
    /// and the declared client-version range.
    ///
    /// `client_version` is the app's own version string, and the
    /// targeting semantics are the ones notices already use: an
    /// announcement that declares a range is withheld when the version is
    /// absent or unparseable.
    #[must_use]
    pub fn active_for(
        &self,
        now_unix_secs: u64,
        client_version: Option<&str>,
    ) -> Vec<&Announcement> {
        if self.is_expired(now_unix_secs) {
            return Vec::new();
        }
        self.announcements
            .iter()
            .filter(|a| a.expires_at.is_none_or(|exp| exp > now_unix_secs))
            .filter(|a| {
                version_range::in_bounds(
                    client_version,
                    a.min_client_version.as_deref(),
                    a.max_client_version.as_deref(),
                )
            })
            .collect()
    }
}

/// Signs an announcement envelope with warren-api's **online server key**.
///
/// # Panics
/// Panics only if `serde_json::to_vec(&UnsignedAnnouncements)` fails,
/// which is infallible for this scalar/owned-string schema.
#[must_use]
pub fn sign_announcements(
    announcements: Vec<Announcement>,
    server_key: &SigningKey,
    generation: u64,
    signed_at: u64,
    expires_at: u64,
) -> SignedAnnouncements {
    let server_pubkey_hex = hex::encode(server_key.verifying_key().as_bytes());
    let unsigned = UnsignedAnnouncements {
        version: ANNOUNCEMENTS_VERSION,
        announcements: &announcements,
        generation,
        signed_at,
        expires_at,
        server_pubkey_hex: &server_pubkey_hex,
    };
    let canonical = serde_json::to_vec(&unsigned)
        .expect("UnsignedAnnouncements JSON serialization is infallible");
    let signature = server_key.sign(&canonical);
    SignedAnnouncements {
        version: ANNOUNCEMENTS_VERSION,
        announcements,
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
/// - [`AnnouncementsError::InputTooLarge`]: `s` exceeds the
///   pre-authentication size gate.
/// - [`AnnouncementsError::Json`]: invalid JSON.
/// - [`AnnouncementsError::UnsupportedVersion`]: version mismatch.
/// - [`AnnouncementsError::ServerPubkeyMismatch`]: server pubkey not pinned.
/// - [`AnnouncementsError::InvalidHex`] /
///   [`AnnouncementsError::PubkeyNotOnCurve`] /
///   [`AnnouncementsError::BadSignature`]: malformed or invalid signature.
pub fn verify_signed_announcements(
    s: &str,
    expected_server_pubkey: Option<&str>,
) -> Result<VerifiedAnnouncements, AnnouncementsError> {
    match expected_server_pubkey {
        Some(p) => verify_signed_announcements_any(s, &[p]),
        None => verify_signed_announcements_any(s, &[]),
    }
}

/// Multi-key variant of [`verify_signed_announcements`] for pinned-key
/// rotation: accepts the envelope if signed by **any** of
/// `expected_server_pubkeys`. Empty slice = TOFU.
///
/// # Errors
/// Same as [`verify_signed_announcements`].
pub fn verify_signed_announcements_any(
    s: &str,
    expected_server_pubkeys: &[&str],
) -> Result<VerifiedAnnouncements, AnnouncementsError> {
    if s.len() > envelope::MAX_VERIFY_INPUT_LEN {
        return Err(AnnouncementsError::InputTooLarge);
    }
    let signed: SignedAnnouncements = serde_json::from_str(s)?;
    if signed.version != ANNOUNCEMENTS_VERSION {
        return Err(AnnouncementsError::UnsupportedVersion {
            got: signed.version,
        });
    }
    if !envelope::pin_allows(expected_server_pubkeys, &signed.server_pubkey_hex) {
        let (got, expected) =
            envelope::redact_pin_mismatch(expected_server_pubkeys, &signed.server_pubkey_hex);
        return Err(AnnouncementsError::ServerPubkeyMismatch { got, expected });
    }
    let server_pubkey = envelope::decode_verifying_key(&signed.server_pubkey_hex)?;
    let signature = envelope::decode_signature(&signed.signature_hex)?;

    let unsigned = UnsignedAnnouncements {
        version: signed.version,
        announcements: &signed.announcements,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
        server_pubkey_hex: &signed.server_pubkey_hex,
    };
    let canonical = serde_json::to_vec(&unsigned).map_err(AnnouncementsError::Json)?;
    // verify_strict: defense in depth, rejects small-order/non-canonical
    // signatures the basic verification equation would still accept.
    server_pubkey
        .verify_strict(&canonical, &signature)
        .map_err(|_| AnnouncementsError::BadSignature)?;

    Ok(VerifiedAnnouncements {
        announcements: signed.announcements,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use warren_contract::dto::{AnnouncementCta, NoticeLevel};

    const SIGNED_AT: u64 = 1_700_000_000;
    const EXPIRES_AT: u64 = 1_700_021_600;

    fn server_key() -> SigningKey {
        SigningKey::from_bytes(&[0x11; 32])
    }

    fn other_key() -> SigningKey {
        SigningKey::from_bytes(&[0x22; 32])
    }

    fn pin() -> String {
        hex::encode(server_key().verifying_key().as_bytes())
    }

    fn announcement(id: &str, headline: &str) -> Announcement {
        Announcement {
            id: id.to_owned(),
            headline: headline.to_owned(),
            body: "body".to_owned(),
            level: NoticeLevel::Info,
            cta: None,
            campaign_id: None,
            voucher_offer: false,
            min_client_version: None,
            max_client_version: None,
            expires_at: None,
        }
    }

    fn verified(announcements: Vec<Announcement>) -> VerifiedAnnouncements {
        VerifiedAnnouncements {
            announcements,
            generation: 1,
            signed_at: SIGNED_AT,
            expires_at: EXPIRES_AT,
        }
    }

    fn signed_json(announcements: Vec<Announcement>, generation: u64) -> String {
        let signed = sign_announcements(
            announcements,
            &server_key(),
            generation,
            SIGNED_AT,
            EXPIRES_AT,
        );
        serde_json::to_string(&signed).expect("serialize")
    }

    #[test]
    fn verifies_a_freshly_signed_envelope_and_returns_its_announcements() {
        let mut a = announcement("a1", "Warren production is open");
        a.cta = Some(AnnouncementCta {
            label: "Download".to_owned(),
            url: "https://warren.ro/download".to_owned(),
        });
        a.campaign_id = Some("prod-launch".to_owned());
        a.voucher_offer = true;
        let json = signed_json(vec![a], 7);

        let verified = verify_signed_announcements(&json, Some(&pin())).expect("must verify");

        assert_eq!(
            verified.generation, 7,
            "generation must survive the round-trip"
        );
        let first = verified.announcements.first().expect("one announcement");
        assert_eq!(first.headline, "Warren production is open");
        assert!(
            first.voucher_offer,
            "the voucher flag drives the second, wallet-signed call"
        );
        assert_eq!(
            first.displayable_cta().map(|c| c.url.as_str()),
            Some("https://warren.ro/download"),
            "a safe CTA must reach the renderer intact"
        );
    }

    #[test]
    fn rejects_an_envelope_signed_by_an_unpinned_key() {
        let signed = sign_announcements(
            vec![announcement("a1", "give us your recovery phrase")],
            &other_key(),
            1,
            SIGNED_AT,
            EXPIRES_AT,
        );
        let json = serde_json::to_string(&signed).expect("serialize");

        let err = verify_signed_announcements(&json, Some(&pin())).expect_err("must not verify");

        assert!(
            matches!(err, AnnouncementsError::ServerPubkeyMismatch { .. }),
            "a foreign signer is the phishing case this format exists to block: {err}"
        );
    }

    #[test]
    fn rejects_a_tampered_cta_url_under_a_valid_signature_header() {
        let mut a = announcement("a1", "Warren production is open");
        a.cta = Some(AnnouncementCta {
            label: "Download".to_owned(),
            url: "https://warren.ro/download".to_owned(),
        });
        let json = signed_json(vec![a], 1);
        let tampered = json.replace("https://warren.ro/download", "https://warren.ro.evil/dl");

        let err =
            verify_signed_announcements(&tampered, Some(&pin())).expect_err("must not verify");

        assert!(
            matches!(err, AnnouncementsError::BadSignature),
            "the link is what the signature exists to protect: {err}"
        );
    }

    #[test]
    fn rejects_an_unknown_envelope_version() {
        let json = signed_json(vec![], 1).replace("\"version\":1", "\"version\":2");

        let err = verify_signed_announcements(&json, Some(&pin())).expect_err("must not verify");

        assert!(
            matches!(err, AnnouncementsError::UnsupportedVersion { got: 2 }),
            "unknown version must be refused, not best-effort parsed: {err}"
        );
    }

    #[test]
    fn rejects_input_above_the_pre_auth_size_gate() {
        let oversized = "x".repeat(envelope::MAX_VERIFY_INPUT_LEN + 1);

        let err = verify_signed_announcements(&oversized, None).expect_err("must not parse");

        assert!(
            matches!(err, AnnouncementsError::InputTooLarge),
            "the size gate must fire before any parsing: {err}"
        );
    }

    #[test]
    fn a_stale_envelope_displays_nothing() {
        let verified = verified(vec![announcement("a1", "still showing?")]);

        assert!(
            verified.active_for(EXPIRES_AT, None).is_empty(),
            "anti-freeze: a blocked refresh must not keep a withdrawn announcement on screen"
        );
        assert_eq!(
            verified.active_for(EXPIRES_AT - 1, None).len(),
            1,
            "one second before expiry the announcement still shows"
        );
    }

    #[test]
    fn an_announcement_past_its_own_expiry_is_filtered_out() {
        let mut a = announcement("a1", "offer ends at noon");
        a.expires_at = Some(1_700_010_000);

        assert!(
            verified(vec![a]).active_for(1_700_010_000, None).is_empty(),
            "the per-announcement TTL must be enforced client-side too"
        );
    }

    #[test]
    fn version_bounds_target_the_intended_clients() {
        let mut a = announcement("a1", "for 1.10 and up");
        a.min_client_version = Some("1.10.0".to_owned());
        let verified = verified(vec![a]);
        let now = SIGNED_AT + 100;

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
            "a targeted announcement must not leak to a client of unknown version"
        );
        assert!(
            verified.active_for(now, Some("nightly")).is_empty(),
            "an unparseable version cannot be judged, so the announcement is withheld"
        );
    }

    #[test]
    fn an_untargeted_announcement_shows_even_without_a_client_version() {
        assert_eq!(
            verified(vec![announcement("a1", "for everyone")])
                .active_for(SIGNED_AT + 100, None)
                .len(),
            1,
            "no declared range means every client, whatever it reports"
        );
    }

    #[test]
    fn signature_covers_the_generation_so_a_rollback_cannot_be_forged() {
        let json = signed_json(vec![announcement("a1", "x")], 9);
        let rolled_back = json.replace("\"generation\":9", "\"generation\":2");

        let err =
            verify_signed_announcements(&rolled_back, Some(&pin())).expect_err("must not verify");

        assert!(
            matches!(err, AnnouncementsError::BadSignature),
            "anti-rollback rests on the generation being signed: {err}"
        );
    }

    #[test]
    fn canonical_bytes_are_frozen() {
        // Pins the wire preimage: a field reorder or rename silently
        // invalidates every deployed client's verification, so the exact
        // signature over a fixed input is the regression alarm.
        let signed = sign_announcements(
            vec![announcement("0000000000000001", "hello")],
            &server_key(),
            3,
            SIGNED_AT,
            EXPIRES_AT,
        );
        assert_eq!(
            signed.signature_hex,
            "f0cce1529d9e4ecc499fd90b7609a2acee5f2207a70897336767d88291d5414c\
             b12c2a91f4bd8c0da2b9c0b2c3e0f7d27ae666ea13f0b955753fb792b69af80b",
            "frozen canonical signature"
        );
    }
}
