//! Offline-admin-signed **exit roster** (TUF "targets" role).
//!
//! **Threat addressed**: the live `/v1/exits` list is signed by
//! warren-api's **online** key. If that server is compromised, the
//! attacker can sign a list containing fake/malicious exits and the
//! client's server-pubkey pin cannot tell (same key). Per The Update
//! Framework, the authority over *which exits are legitimate* must come
//! from an **offline** key that the online server never holds.
//!
//! The roster is that authority: the operator's **offline admin key**
//! signs the set of authorized exits (stable `exit_id` + Ed25519
//! `endpoint_id` + advertised `country`/`city`). warren-api stores and
//! serves the roster as an opaque blob - it **cannot forge it** (no admin
//! key). The client cross-checks every relay from the (online-signed)
//! live list against the (offline-signed) roster and **drops any relay
//! not authorized by the offline key**. A compromised backend can thus
//! only deny/stale exits, never introduce one, relocate one to another
//! country, or swap its pubkey.
//!
//! Like the live list (signed v4), the roster carries a monotonic
//! `generation` (anti-rollback) and a signed `expires_at` (anti-freeze);
//! it changes rarely (only when an exit is added/removed/rotated), so its
//! expiry window is long.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use warrenguard_wire::ExitId;

use crate::signed::SignedError;
use crate::{WarrenRelay, WarrenRelayList};

/// Current roster format version. Bumping = incompatible rotation.
pub const ROSTER_VERSION: u32 = 1;

/// One authorized exit, as attested by the offline admin key. Binds the
/// stable operator identity (`exit_id`), the Ed25519 signing identity
/// (`endpoint_id`) and the advertised location. A live-list relay is
/// accepted only if **all** of these match a roster entry.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RosterEntry {
    /// 64-char hex (or `wb…` SS58) of the exit's Ed25519 pubkey, same
    /// encoding as the live list's `endpoint_id`.
    pub endpoint_id: String,
    /// Stable 16-byte operator identifier.
    pub exit_id: ExitId,
    /// ISO 3166-1 alpha-2 country the exit is authorized to advertise.
    pub country: String,
    /// City the exit is authorized to advertise.
    pub city: String,
}

/// Offline-admin-signed roster (full wire form).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedRoster {
    /// Must equal [`ROSTER_VERSION`].
    pub version: u32,
    /// Authorized exits.
    pub entries: Vec<RosterEntry>,
    /// Monotonic content version (anti-rollback high-water mark).
    pub generation: u64,
    /// Unix epoch seconds the roster was signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which the roster is stale (anti-freeze).
    /// Long window: the roster changes rarely.
    pub expires_at: u64,
    /// 64-char hex of the **admin** (offline) verifying key.
    pub admin_pubkey_hex: String,
    /// 128-char hex Ed25519 signature over the canonical bytes.
    pub signature_hex: String,
}

/// Canonical signing preimage. Field order is frozen; any mutation = v2.
#[derive(Debug, Serialize)]
struct UnsignedRoster<'a> {
    version: u32,
    entries: &'a [RosterEntry],
    generation: u64,
    signed_at: u64,
    expires_at: u64,
    admin_pubkey_hex: &'a str,
}

/// A verified roster: the authorized entries plus freshness metadata the
/// caller enforces (monotonic `generation`, `expires_at`).
#[derive(Debug, Clone)]
pub struct VerifiedRoster {
    /// Authorized exits.
    pub entries: Vec<RosterEntry>,
    /// Monotonic content version.
    pub generation: u64,
    /// Unix epoch seconds signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which stale.
    pub expires_at: u64,
}

impl VerifiedRoster {
    /// True if `now_unix_secs` is at or past the signed expiry.
    #[must_use]
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.expires_at
    }

    /// True if `relay` is authorized by some roster entry: the stable
    /// `exit_id`, the Ed25519 `endpoint_id` and the advertised
    /// `country`/`city` must **all** match. Endpoint ids are compared by
    /// decoded pubkey bytes so hex vs SS58 encoding differences do not
    /// matter. `country` and `city` are compared case-insensitively
    /// (matching `query.rs`), so a `Kassel` vs `kassel` casing mismatch
    /// never de-authorizes a roster-listed relay.
    #[must_use]
    pub fn authorizes(&self, relay: &WarrenRelay) -> bool {
        self.entries.iter().any(|e| {
            e.exit_id == relay.exit_id()
                && crate::json_io::decode_endpoint_id(&e.endpoint_id)
                    .is_ok_and(|pk| pk == relay.endpoint_id())
                && e.country
                    .eq_ignore_ascii_case(relay.location().country_code())
                && e.city.eq_ignore_ascii_case(relay.location().city())
        })
    }

    /// Filters `list` to only the relays this roster authorizes. Relays
    /// absent from the offline-signed roster (e.g. injected by a
    /// compromised backend) are dropped and counted in the returned
    /// `dropped` total so the caller can log the discrepancy.
    #[must_use]
    pub fn authorize(&self, list: &WarrenRelayList) -> AuthorizeResult {
        let mut kept = Vec::new();
        let mut dropped = 0usize;
        for relay in list.relays() {
            if self.authorizes(relay) {
                kept.push(relay.clone());
            } else {
                dropped += 1;
            }
        }
        AuthorizeResult {
            authorized: WarrenRelayList::new(kept),
            dropped,
        }
    }
}

/// Outcome of [`VerifiedRoster::authorize`].
#[derive(Debug)]
pub struct AuthorizeResult {
    /// The subset of relays the offline roster vouches for.
    pub authorized: WarrenRelayList,
    /// How many live-list relays were dropped as un-authorized.
    pub dropped: usize,
}

/// Signs a roster with the **offline admin key**. Run on the operator's
/// machine (never on warren-api).
///
/// # Panics
/// Panics only if `serde_json::to_vec(&UnsignedRoster)` fails, which is
/// infallible for this scalar/owned-string schema.
#[must_use]
pub fn sign_roster(
    entries: Vec<RosterEntry>,
    admin_key: &SigningKey,
    generation: u64,
    signed_at: u64,
    expires_at: u64,
) -> SignedRoster {
    let admin_pubkey_hex = hex::encode(admin_key.verifying_key().as_bytes());
    let unsigned = UnsignedRoster {
        version: ROSTER_VERSION,
        entries: &entries,
        generation,
        signed_at,
        expires_at,
        admin_pubkey_hex: &admin_pubkey_hex,
    };
    let canonical =
        serde_json::to_vec(&unsigned).expect("UnsignedRoster JSON serialization is infallible");
    let signature = admin_key.sign(&canonical);
    SignedRoster {
        version: ROSTER_VERSION,
        entries,
        generation,
        signed_at,
        expires_at,
        admin_pubkey_hex,
        signature_hex: hex::encode(signature.to_bytes()),
    }
}

/// Verifies a roster's signature against the pinned **admin** pubkey.
///
/// # Errors
/// - [`SignedError::Json`]: invalid JSON.
/// - [`SignedError::UnsupportedVersion`]: `version != ROSTER_VERSION`.
/// - [`SignedError::ServerPubkeyMismatch`]: admin pubkey ≠ pinned (the
///   variant is reused generically for "wrong signing key").
/// - [`SignedError::InvalidHex`] / [`SignedError::PubkeyNotOnCurve`] /
///   [`SignedError::BadSignature`]: malformed or invalid signature.
pub fn verify_roster(
    s: &str,
    expected_admin_pubkey: Option<&str>,
) -> Result<VerifiedRoster, SignedError> {
    match expected_admin_pubkey {
        Some(p) => verify_roster_any(s, &[p]),
        None => verify_roster_any(s, &[]),
    }
}

/// Multi-key variant of [`verify_roster`] for pinned-admin-key rotation
/// Accepts the roster if signed by **any** of
/// `expected_admin_pubkeys`. Empty slice = TOFU.
///
/// # Errors
/// Same as [`verify_roster`].
pub fn verify_roster_any(
    s: &str,
    expected_admin_pubkeys: &[&str],
) -> Result<VerifiedRoster, SignedError> {
    let signed: SignedRoster = serde_json::from_str(s)?;
    if signed.version != ROSTER_VERSION {
        return Err(SignedError::UnsupportedVersion {
            got: signed.version,
        });
    }
    if !expected_admin_pubkeys.is_empty()
        && !expected_admin_pubkeys
            .iter()
            .any(|p| *p == signed.admin_pubkey_hex)
    {
        return Err(SignedError::ServerPubkeyMismatch {
            got: signed.admin_pubkey_hex.clone(),
            expected: expected_admin_pubkeys.join(","),
        });
    }
    let pubkey_bytes: [u8; 32] = hex::decode(&signed.admin_pubkey_hex)
        .map_err(|_| SignedError::InvalidHex)?
        .try_into()
        .map_err(|_| SignedError::InvalidHex)?;
    let admin_pubkey =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| SignedError::PubkeyNotOnCurve)?;
    let sig_bytes: [u8; 64] = hex::decode(&signed.signature_hex)
        .map_err(|_| SignedError::InvalidHex)?
        .try_into()
        .map_err(|_| SignedError::InvalidHex)?;
    let signature = Signature::from_bytes(&sig_bytes);

    let unsigned = UnsignedRoster {
        version: signed.version,
        entries: &signed.entries,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
        admin_pubkey_hex: &signed.admin_pubkey_hex,
    };
    let canonical = serde_json::to_vec(&unsigned).map_err(SignedError::Json)?;
    admin_pubkey
        .verify(&canonical, &signature)
        .map_err(|_| SignedError::BadSignature)?;

    Ok(VerifiedRoster {
        entries: signed.entries,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::warren_types::WarrenPubkey;
    use crate::{Addr, Ingress, Listener};
    use crate::{Location, sign_relay_list};

    fn admin_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn entry(seed: u8, country: &str, city: &str) -> RosterEntry {
        RosterEntry {
            endpoint_id: hex::encode(WarrenPubkey::from_bytes([seed; 32]).as_bytes()),
            exit_id: ExitId::from_bytes([seed; 16]),
            country: country.to_owned(),
            city: city.to_owned(),
        }
    }

    fn relay(seed: u8, country: &str, city: &str) -> WarrenRelay {
        let id = WarrenPubkey::from_bytes([seed; 32]);
        WarrenRelay::from_public(
            id,
            ExitId::from_bytes([seed; 16]),
            Location::new(country, city),
            100,
            true,
            vec![Ingress::new(
                Addr::new("1.2.3.4".parse().unwrap(), None),
                vec![Listener::new(443, "quic", "h3")],
            )],
            true,
            false,
        )
    }

    fn pin(key: &SigningKey) -> String {
        hex::encode(key.verifying_key().to_bytes())
    }

    #[test]
    fn round_trip_sign_then_verify_with_matching_admin_pubkey() {
        let key = admin_key();
        let signed = sign_roster(vec![entry(1, "se", "Stockholm")], &key, 1, 1_000, 9_999);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_roster(&json, Some(&pin(&key))).expect("must verify");
        assert_eq!(v.entries.len(), 1);
        assert_eq!(v.generation, 1);
        assert_eq!(v.expires_at, 9_999);
    }

    #[test]
    fn verify_rejects_wrong_admin_pubkey() {
        // A roster self-signed by an attacker key must be refused when we
        // pin the legitimate offline admin key - the core guarantee.
        let attacker = SigningKey::from_bytes(&[0x11; 32]);
        let legit = admin_key();
        let signed = sign_roster(
            vec![entry(1, "se", "Stockholm")],
            &attacker,
            1,
            1_000,
            9_999,
        );
        let json = serde_json::to_string(&signed).unwrap();
        let err = verify_roster(&json, Some(&pin(&legit))).expect_err("pinned mismatch");
        assert!(matches!(err, SignedError::ServerPubkeyMismatch { .. }));
    }

    #[test]
    fn verify_rejects_tampered_entries() {
        // A compromised backend appends a fake exit to the roster blob
        // without the admin key -> signature must fail.
        let key = admin_key();
        let mut signed = sign_roster(vec![entry(1, "se", "Stockholm")], &key, 1, 1_000, 9_999);
        signed.entries.push(entry(2, "xx", "Evil"));
        let json = serde_json::to_string(&signed).unwrap();
        let err = verify_roster(&json, None).expect_err("tampered entries");
        assert!(matches!(err, SignedError::BadSignature));
    }

    #[test]
    fn authorize_keeps_only_roster_listed_exits() {
        // The crux: a live list mixing one authorized exit (seed 1) and
        // one backend-injected fake (seed 9, absent from the roster) must
        // be filtered down to just the authorized one.
        let key = admin_key();
        let signed = sign_roster(vec![entry(1, "se", "Stockholm")], &key, 1, 1_000, 9_999);
        let roster = verify_roster(&serde_json::to_string(&signed).unwrap(), Some(&pin(&key)))
            .expect("verify");
        let live = WarrenRelayList::new(vec![
            relay(1, "se", "Stockholm"),
            relay(9, "xx", "Evil"), // injected, not in roster
        ]);
        let res = roster.authorize(&live);
        assert_eq!(
            res.authorized.relays().len(),
            1,
            "only the roster exit kept"
        );
        assert_eq!(res.dropped, 1, "the injected exit is dropped");
        assert_eq!(
            res.authorized.relays()[0].exit_id(),
            ExitId::from_bytes([1; 16])
        );
    }

    #[test]
    fn authorize_drops_exit_relocated_to_unauthorized_country() {
        // A compromised backend keeps an authorized exit_id+pubkey but
        // changes its advertised country (e.g. to fake a US exit). The
        // roster pins country/city, so the relocated relay is dropped.
        let key = admin_key();
        let signed = sign_roster(vec![entry(1, "se", "Stockholm")], &key, 1, 1_000, 9_999);
        let roster = verify_roster(&serde_json::to_string(&signed).unwrap(), None).expect("verify");
        let live = WarrenRelayList::new(vec![relay(1, "us", "Ashburn")]);
        let res = roster.authorize(&live);
        assert_eq!(
            res.authorized.relays().len(),
            0,
            "relocated exit not authorized"
        );
        assert_eq!(res.dropped, 1);
    }

    #[test]
    fn authorizes_relay_with_city_in_different_case() {
        // The roster pins "Kassel" but the live relay advertises
        // "kassel": the city must be compared case-insensitively, the
        // same way the country already is (and the way query.rs matches
        // a city). Byte-exact comparison caused a real kassel/Kassel
        // outage. The relay MUST stay authorized.
        let key = admin_key();
        let signed = sign_roster(vec![entry(1, "de", "Kassel")], &key, 1, 1_000, 9_999);
        let roster = verify_roster(&serde_json::to_string(&signed).unwrap(), None).expect("verify");
        let live = WarrenRelayList::new(vec![relay(1, "de", "kassel")]);
        let res = roster.authorize(&live);
        assert_eq!(
            res.authorized.relays().len(),
            1,
            "city case must not de-authorize a roster-listed relay"
        );
        assert_eq!(res.dropped, 0);
    }

    #[test]
    fn authorize_drops_pubkey_swap_for_authorized_exit_id() {
        // A compromised backend keeps an authorized exit_id but swaps the
        // Ed25519 endpoint_id to an attacker pubkey (to MITM the tunnel).
        // The roster pins endpoint_id, so it is dropped.
        let key = admin_key();
        // Roster authorizes exit_id 1 bound to pubkey seed 1.
        let signed = sign_roster(vec![entry(1, "se", "Stockholm")], &key, 1, 1_000, 9_999);
        let roster = verify_roster(&serde_json::to_string(&signed).unwrap(), None).expect("verify");
        // Live relay: same exit_id 1 + country/city, but pubkey seed 7.
        let attacker_id = WarrenPubkey::from_bytes([7; 32]);
        let swapped = WarrenRelay::from_public(
            attacker_id,
            ExitId::from_bytes([1; 16]),
            Location::new("se", "Stockholm"),
            100,
            true,
            vec![Ingress::new(
                Addr::new("1.2.3.4".parse().unwrap(), None),
                vec![Listener::new(443, "quic", "h3")],
            )],
            true,
            false,
        );
        let live = WarrenRelayList::new(vec![swapped]);
        let res = roster.authorize(&live);
        assert_eq!(
            res.authorized.relays().len(),
            0,
            "pubkey swap not authorized"
        );
        assert_eq!(res.dropped, 1);
    }

    #[test]
    fn authorize_keeps_all_when_every_exit_is_listed() {
        let key = admin_key();
        let signed = sign_roster(
            vec![entry(1, "se", "Stockholm"), entry(2, "fr", "Paris")],
            &key,
            1,
            1_000,
            9_999,
        );
        let roster = verify_roster(&serde_json::to_string(&signed).unwrap(), None).expect("verify");
        let live = WarrenRelayList::new(vec![relay(1, "se", "Stockholm"), relay(2, "fr", "Paris")]);
        let res = roster.authorize(&live);
        assert_eq!(res.authorized.relays().len(), 2);
        assert_eq!(res.dropped, 0);
    }

    #[test]
    fn roster_is_expired_respects_signed_expiry() {
        let key = admin_key();
        let signed = sign_roster(vec![entry(1, "se", "Stockholm")], &key, 1, 1_000, 5_000);
        let v = verify_roster(&serde_json::to_string(&signed).unwrap(), None).unwrap();
        assert!(!v.is_expired(4_999));
        assert!(v.is_expired(5_000));
    }

    #[test]
    fn roster_signature_independent_from_live_list_signature() {
        // Sanity: a SignedRoster is not accidentally verifiable as a
        // SignedRelayList and vice-versa (distinct schemas/keys). We only
        // check the roster verifies as a roster here.
        let key = admin_key();
        let roster_json =
            serde_json::to_string(&sign_roster(vec![entry(1, "se", "x")], &key, 1, 1, 9)).unwrap();
        // A live list signed by the same key is a different schema.
        let list_json = serde_json::to_string(&sign_relay_list(vec![], &key, 1, 1, 9)).unwrap();
        assert!(verify_roster(&roster_json, None).is_ok());
        assert!(
            verify_roster(&list_json, None).is_err(),
            "a live-list blob must not verify as a roster"
        );
    }

    #[test]
    fn verify_roster_any_accepts_key_in_set_rejects_otherwise() {
        // pinned-admin-key rotation for the roster.
        let key = admin_key();
        let signed = sign_roster(vec![entry(1, "se", "Stockholm")], &key, 1, 1_000, 9_999);
        let json = serde_json::to_string(&signed).unwrap();
        let other = hex::encode([0xff; 32]);
        let pinned = pin(&key);
        let v = verify_roster_any(&json, &[other.as_str(), pinned.as_str()])
            .expect("admin key present in set");
        assert_eq!(v.entries.len(), 1);
        let err = verify_roster_any(&json, &[other.as_str()]).expect_err("admin key absent");
        assert!(matches!(err, SignedError::ServerPubkeyMismatch { .. }));
    }
}
