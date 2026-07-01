//! Signed `warren-relays.json` v8 - node (exit/relay/entry) distribution
//! from warren-api to Warren clients. (v8 added the optional per-node
//! `cover_domain` for v6 X.509; the rest of the v7 minimization vocabulary
//! below is unchanged.)
//!
//! **Why sign the list**: an attacker able to intercept the HTTP fetch
//! (MITM, DNS poisoning, compromised certificate) could otherwise
//! substitute their own exits and route the client's traffic through
//! their relays. The warren-api server's Ed25519 signature
//! cryptographically binds the list to a legitimate operator; the
//! client verifies with a known `server_pubkey` (TOFU at boot or
//! hardcoded pin in prod).
//!
//! **Canonical format** (frozen at v7, NEVER modify without rotating
//! to v8):
//!
//! ```text
//! canonical_bytes = serde_json::to_vec(&UnsignedRelayList {
//!     version: 8,
//!     nodes,            // each entry is a JsonNode (v8 vocabulary)
//!     generation,       // monotonic content version (anti-rollback)
//!     signed_at,
//!     expires_at,       // signed expiry (anti-freeze/replay)
//!     server_pubkey_hex,
//! })
//! signature = Ed25519::sign(server_secret_key, canonical_bytes)
//! ```
//!
//! The field order in the struct determines the order in the
//! serialized JSON (serde_json). Any mutation of the order = version
//! rotation, because pre-rotation clients reconstruct the canonical
//! bytes differently and therefore fail signature verification.
//!
//! **Minimization (v7)**: the public single-hop list publishes only what
//! a client actually dials. Compared to v6 it DROPS `multihop_pubkey`,
//! `roles`, per-endpoint `geoip`, and the per-endpoint `ingress`/`egress`
//! flags. Roles are structural (an endpoint with a listener is dialable);
//! egress capability is two node-level booleans (`egress.ipv4` /
//! `egress.ipv6`) with NO egress source address — a client must know an
//! exit's geolocation to pick a country, but never its egress IP. The
//! full canonical model (geoip, egress addresses, relay-facing exit
//! ingress) lives in the admin structure, not on this wire.
//!
//! **Anti-rollback / anti-freeze (TUF model)**: `generation` is a
//! strictly monotonic content version; a client MUST reject a fetched
//! list whose `generation` is lower than the highest already trusted.
//! `expires_at` is a signed expiry; a client MUST reject an expired list
//! on the live-fetch path. Enforcement lives in the caller (this crate
//! stays pure / clock-free); [`VerifiedRelayList`] surfaces the values.

use std::net::IpAddr;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use warrenguard_wire::ExitId;

use crate::json_io::JsonError;
use crate::{Addr, Ingress, Listener, Location, WarrenRelay, WarrenRelayList};

/// Current signed format version. Bumping = incompatible rotation.
///
/// **v3** added the mandatory `exit_id` field.
///
/// **v4 (security hardening)** added the top-level `generation`
/// (anti-rollback) and `expires_at` (anti-freeze) fields.
///
/// **v5 (IPv6 capability)** added a per-relay `ipv6_egress` bool.
///
/// **v6 (node model)** grouped `location`, `roles`, and per-endpoint
/// `{ingress, egress, listeners, geoip}` under a single `endpoints` list.
///
/// **v7 (minimization)** publishes the strict minimum a client dials:
/// drops `multihop_pubkey`, `roles` (structural now), per-endpoint
/// `geoip` and the `ingress`/`egress` flags. Egress becomes two
/// node-level capability booleans (`egress.ipv4`/`egress.ipv6`) with no
/// egress address. Signing-canonical like every prior bump: lockstep
/// rollout of warren-api, warren-relay-selector and warren-app required.
pub const SIGNED_VERSION: u32 = 8;

/// **Wire** dial listener: a `port` plus the wire `transport` and the
/// `alpn` token offered in the handshake. The app surfaces
/// `(transport, alpn)` as a selectable connection type / obfuscation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonListener {
    /// Listening port.
    pub port: u16,
    /// Wire transport (`quic`, future `masque`, ...).
    pub transport: String,
    /// ALPN token offered in the handshake (`h3`).
    pub alpn: String,
}

/// **Wire** entry endpoint (v7): one dialable address with its listeners.
/// An endpoint with at least one listener IS a client dial point; there
/// are no direction flags and no geoip on the public wire.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonEndpoint {
    /// IP literal (no port; ports live in `listeners`).
    pub addr: String,
    /// `"ipv4"` / `"ipv6"`; must match `addr`.
    pub family: String,
    /// Dial listeners served at this address.
    pub listeners: Vec<JsonListener>,
}

/// **Wire** node-level egress capability (v7): whether the node can route
/// in-tunnel client traffic to the v4 / v6 internet. Capability booleans
/// only — the egress source address is NEVER published to clients.
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct JsonEgress {
    /// `true` if the node has a working IPv4 egress source.
    pub ipv4: bool,
    /// `true` if the node has a working IPv6 egress source.
    pub ipv6: bool,
}

/// **Wire** node geolocation (manual, authoritative for selection).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonLocation {
    /// ISO 3166-1 alpha-2 country code.
    pub country: String,
    /// City name (free form).
    pub city: String,
}

/// **Wire** representation of a node in the v7 JSON (public projection).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JsonNode {
    /// SS58 (`wb…`) or 64-char hex of the Ed25519 node pubkey.
    pub id: String,
    /// 32-char hex of the operator-assigned stable identifier (16
    /// bytes). Anchors TOFU pinning.
    pub exit_id: ExitId,
    /// Manual geolocation (authoritative for selection).
    pub location: JsonLocation,
    /// Relative weight for random weighted selection.
    pub weight: u64,
    /// `false` disables the node on the selector side without removing
    /// it from the list (maintenance / rolling deploy).
    pub active: bool,
    /// Node-level egress capability (no source address).
    pub egress: JsonEgress,
    /// Dialable entry endpoints (1..N).
    pub endpoints: Vec<JsonEndpoint>,
    /// v6 X.509 cover-domain SNI (wg-0005): the hostname on the exit's real
    /// certificate that the client dials and validates via WebPKI instead of
    /// pinning the exit's raw public key. `None` (skipped from the wire) keeps
    /// the RPK handshake. Added in v8; must stay last to preserve field order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover_domain: Option<String>,
}

/// **Signed** node list (full wire format, `relays.json` v7).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedRelayList {
    /// Must equal [`SIGNED_VERSION`].
    pub version: u32,
    /// Nodes announced by the warren-api server.
    pub nodes: Vec<JsonNode>,
    /// **Monotonic content version**. Clients MUST reject a fetched
    /// list whose `generation` is lower than the highest already
    /// trusted (TUF rollback defense).
    pub generation: u64,
    /// Unix epoch seconds at which the list was signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which this list MUST NOT be trusted on
    /// the live-fetch path (TUF freeze/replay defense).
    pub expires_at: u64,
    /// 64-char hex of the server's `VerifyingKey`. The client must
    /// check this pubkey is the one expected for its deployment.
    pub server_pubkey_hex: String,
    /// 128-char hex Ed25519 signature over `canonical_bytes`.
    pub signature_hex: String,
}

/// Unsigned form used as the signature preimage.
///
/// **Critical field order**: must match [`SignedRelayList`] so that
/// `serde_json::to_vec(&Unsigned)` produces the same bytes as the
/// unsigned portion of the signed JSON. Any mutation = version
/// rotation.
#[derive(Debug, Serialize)]
struct UnsignedRelayList<'a> {
    version: u32,
    nodes: &'a [JsonNode],
    generation: u64,
    signed_at: u64,
    expires_at: u64,
    server_pubkey_hex: &'a str,
}

/// Result of a successful [`verify_signed_relay_list`]: the resolved
/// node list plus the freshness/anti-rollback metadata the caller must
/// enforce. The crate stays pure (no clock).
#[derive(Debug, Clone)]
pub struct VerifiedRelayList {
    /// Resolved nodes (parsed pubkeys + endpoints).
    pub relays: WarrenRelayList,
    /// Monotonic content version (anti-rollback high-water mark).
    pub generation: u64,
    /// Unix epoch seconds the list was signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which the list is stale.
    pub expires_at: u64,
}

impl VerifiedRelayList {
    /// True if `now_unix_secs` is at or past the signed expiry.
    #[must_use]
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.expires_at
    }
}

/// Extra errors specific to the signed format.
#[derive(Debug, thiserror::Error)]
pub enum SignedError {
    /// Invalid JSON or unexpected structure.
    #[error("invalid signed relay list: {0}")]
    Json(#[from] serde_json::Error),
    /// `version != SIGNED_VERSION`.
    #[error(
        "unsupported signed relay list version: {got} (expected {})",
        SIGNED_VERSION
    )]
    UnsupportedVersion {
        /// Version actually received in the JSON.
        got: u32,
    },
    /// The declared server pubkey does not match the one expected by
    /// the client.
    #[error("server pubkey mismatch: got {got}, expected {expected}")]
    ServerPubkeyMismatch {
        /// Pubkey hex announced in the JSON.
        got: String,
        /// Pubkey hex pinned on the client.
        expected: String,
    },
    /// Invalid hex for `server_pubkey_hex` or `signature_hex`.
    #[error("invalid hex encoding")]
    InvalidHex,
    /// Received pubkey is not a valid Ed25519 point.
    #[error("server pubkey is not a valid Ed25519 point")]
    PubkeyNotOnCurve,
    /// Signature does not verify against `(server_pubkey,
    /// canonical_bytes)`.
    #[error("signature verification failed")]
    BadSignature,
    /// Per-node parsing errors (invalid id / addr / family).
    #[error(transparent)]
    Relay(#[from] JsonError),
}

/// Signs a node list with the server key. warren-api side only.
///
/// - `generation`: monotonic content version (rollback protection).
/// - `signed_at`: unix epoch seconds the list was signed.
/// - `expires_at`: unix epoch seconds after which the list is stale.
///
/// # Panics
///
/// Panics if `serde_json::to_vec(&UnsignedRelayList)` fails, which is
/// infallible for this owned-scalar schema.
#[must_use]
pub fn sign_relay_list(
    nodes: Vec<JsonNode>,
    server_key: &SigningKey,
    generation: u64,
    signed_at: u64,
    expires_at: u64,
) -> SignedRelayList {
    let server_pubkey_hex = hex::encode(server_key.verifying_key().as_bytes());
    let unsigned = UnsignedRelayList {
        version: SIGNED_VERSION,
        nodes: &nodes,
        generation,
        signed_at,
        expires_at,
        server_pubkey_hex: &server_pubkey_hex,
    };
    let canonical =
        serde_json::to_vec(&unsigned).expect("UnsignedRelayList JSON serialization is infallible");
    let signature = server_key.sign(&canonical);

    SignedRelayList {
        version: SIGNED_VERSION,
        nodes,
        generation,
        signed_at,
        expires_at,
        server_pubkey_hex,
        signature_hex: hex::encode(signature.to_bytes()),
    }
}

/// Verifies the signature of a [`SignedRelayList`] and returns the
/// resolved [`WarrenRelayList`] if everything is OK.
///
/// If `expected_server_pubkey` is `Some(hex)`, also rejects any list
/// signed by another pubkey (client pin). If `None`, accepts any
/// self-consistent signature (TOFU mode).
///
/// # Errors
///
/// - [`SignedError::Json`]: invalid JSON.
/// - [`SignedError::UnsupportedVersion`]: `version != SIGNED_VERSION`.
/// - [`SignedError::ServerPubkeyMismatch`]: pubkey ≠ expected.
/// - [`SignedError::InvalidHex`] / [`SignedError::PubkeyNotOnCurve`]:
///   invalid pubkey/signature format.
/// - [`SignedError::BadSignature`]: signature does not verify.
/// - [`SignedError::Relay`]: a node has an invalid format.
pub fn verify_signed_relay_list(
    s: &str,
    expected_server_pubkey: Option<&str>,
) -> Result<VerifiedRelayList, SignedError> {
    match expected_server_pubkey {
        Some(p) => verify_signed_relay_list_any(s, &[p]),
        None => verify_signed_relay_list_any(s, &[]),
    }
}

/// Multi-key variant of [`verify_signed_relay_list`] for pinned-key
/// rotation: accepts the list if signed by **any** of
/// `expected_server_pubkeys`. An empty slice means TOFU.
///
/// # Errors
/// Same as [`verify_signed_relay_list`].
pub fn verify_signed_relay_list_any(
    s: &str,
    expected_server_pubkeys: &[&str],
) -> Result<VerifiedRelayList, SignedError> {
    let signed: SignedRelayList = serde_json::from_str(s)?;
    if signed.version != SIGNED_VERSION {
        return Err(SignedError::UnsupportedVersion {
            got: signed.version,
        });
    }
    if !expected_server_pubkeys.is_empty()
        && !expected_server_pubkeys
            .iter()
            .any(|p| *p == signed.server_pubkey_hex)
    {
        return Err(SignedError::ServerPubkeyMismatch {
            got: signed.server_pubkey_hex.clone(),
            expected: expected_server_pubkeys.join(","),
        });
    }

    // Rebuild the canonical bytes and verify the crypto signature.
    let pubkey_bytes: [u8; 32] = hex::decode(&signed.server_pubkey_hex)
        .map_err(|_| SignedError::InvalidHex)?
        .try_into()
        .map_err(|_| SignedError::InvalidHex)?;
    let server_pubkey =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| SignedError::PubkeyNotOnCurve)?;

    let sig_bytes: [u8; 64] = hex::decode(&signed.signature_hex)
        .map_err(|_| SignedError::InvalidHex)?
        .try_into()
        .map_err(|_| SignedError::InvalidHex)?;
    let signature = Signature::from_bytes(&sig_bytes);

    let unsigned = UnsignedRelayList {
        version: signed.version,
        nodes: &signed.nodes,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
        server_pubkey_hex: &signed.server_pubkey_hex,
    };
    let canonical = serde_json::to_vec(&unsigned).map_err(SignedError::Json)?;

    server_pubkey
        .verify(&canonical, &signature)
        .map_err(|_| SignedError::BadSignature)?;

    // Convert to a runtime WarrenRelayList.
    let relays: Result<Vec<_>, JsonError> =
        signed.nodes.into_iter().map(json_node_to_warren).collect();
    Ok(VerifiedRelayList {
        relays: WarrenRelayList::new(relays?),
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
    })
}

/// Builds a runtime [`WarrenRelay`] (node) from a wire [`JsonNode`].
///
/// Shared by the signed path and the unsigned bootstrap parser
/// ([`crate::json_io`]). v7 is the public projection, so the runtime node
/// is built with [`WarrenRelay::from_public`]: only `entry` endpoints and
/// the node-level egress capability booleans are known on the client.
///
/// # Errors
/// [`JsonError`] when the id, an endpoint address or family is malformed.
pub(crate) fn json_node_to_warren(n: JsonNode) -> Result<WarrenRelay, JsonError> {
    let id = crate::json_io::decode_endpoint_id(&n.id)?;

    let mut entry = Vec::with_capacity(n.endpoints.len());
    for e in n.endpoints {
        let ip: IpAddr = e
            .addr
            .parse()
            .map_err(|_| JsonError::InvalidIpAddr(e.addr.clone()))?;
        // `family` is explicit on the wire but must agree with `addr`
        // (defense against a list that mislabels a family to dodge a
        // client's IP-version filter).
        let declared_v6 = match e.family.as_str() {
            "ipv4" => false,
            "ipv6" => true,
            _ => return Err(JsonError::InvalidFamily(e.family.clone())),
        };
        if declared_v6 != ip.is_ipv6() {
            return Err(JsonError::InvalidFamily(e.family.clone()));
        }
        let listeners = e
            .listeners
            .into_iter()
            .map(|l| Listener::new(l.port, l.transport, l.alpn))
            .collect();
        entry.push(Ingress::new(Addr::new(ip, None), listeners));
    }

    Ok(WarrenRelay::from_public(
        id,
        n.exit_id,
        Location::new(n.location.country, n.location.city),
        n.weight,
        n.active,
        entry,
        n.egress.ipv4,
        n.egress.ipv6,
    )
    .with_cover_domain(n.cover_domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_server_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    fn sample_listener() -> JsonListener {
        JsonListener {
            port: 443,
            transport: "quic".to_owned(),
            alpn: "h3".to_owned(),
        }
    }

    fn sample_node() -> JsonNode {
        JsonNode {
            id: "00".repeat(32),
            exit_id: ExitId::from_bytes([0xaa; 16]),
            location: JsonLocation {
                country: "FR".to_owned(),
                city: "Paris".to_owned(),
            },
            weight: 100,
            active: true,
            egress: JsonEgress {
                ipv4: true,
                ipv6: false,
            },
            endpoints: vec![JsonEndpoint {
                addr: "127.0.0.1".to_owned(),
                family: "ipv4".to_owned(),
                listeners: vec![sample_listener()],
            }],
            cover_domain: None,
        }
    }

    #[test]
    fn cover_domain_flows_from_signed_node_to_dial_target() {
        // wg-0005: a v8 roster node carrying a cover_domain must surface it
        // on the resolved node's dial target, so the client dials the exit's
        // real certificate hostname as SNI (X.509 mode) and validates it via
        // WebPKI instead of pinning the raw public key.
        let key = fixed_server_key();
        let mut node = sample_node();
        node.cover_domain = Some("cover.example.com".to_owned());
        let signed = sign_relay_list(vec![node], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).expect("serialize");

        let verified = verify_signed_relay_list(&json, None).expect("verify must pass");
        let relay = &verified.relays.relays()[0];
        assert_eq!(
            relay.endpoint_addr().cover_domain.as_deref(),
            Some("cover.example.com"),
            "cover_domain must reach the dial target"
        );
    }

    #[test]
    fn absent_cover_domain_keeps_rpk_dial_target() {
        // A node without a cover_domain keeps the RPK handshake: the dial
        // target must carry no SNI hostname override.
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).expect("serialize");
        let verified = verify_signed_relay_list(&json, None).expect("verify must pass");
        assert!(
            verified.relays.relays()[0]
                .endpoint_addr()
                .cover_domain
                .is_none(),
            "no cover_domain on the node keeps the RPK handshake"
        );
    }

    #[test]
    fn signed_round_trip_carries_node_egress_caps() {
        // v7: egress is two node-level booleans (no source address). A
        // node dialable on v6 but without a v6 egress source must NOT
        // report v6 egress (the FDC DAD-fail shape). The booleans must
        // survive sign -> verify, independently of dialability.
        let key = fixed_server_key();
        let mut node = sample_node();
        node.endpoints.push(JsonEndpoint {
            addr: "2001:db8::2".to_owned(),
            family: "ipv6".to_owned(),
            listeners: vec![sample_listener()],
        });
        // egress.ipv4=true, egress.ipv6=false from sample_node().
        let signed = sign_relay_list(vec![node], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).expect("serialize");

        let verified = verify_signed_relay_list(&json, None).expect("verify must pass");
        let n = &verified.relays.relays()[0];
        assert!(n.egress_v4(), "node reports v4 egress capability");
        assert!(
            !n.egress_v6(),
            "v6 endpoint is dialable but node has no v6 egress source"
        );
        assert!(n.has_ipv6(), "v6 endpoint is still dialable");
    }

    #[test]
    fn round_trip_sign_then_verify_passes_with_matching_pubkey() {
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).expect("serialize");

        let expected_pubkey = hex::encode(key.verifying_key().as_bytes());
        let verified =
            verify_signed_relay_list(&json, Some(&expected_pubkey)).expect("verify must pass");
        assert_eq!(verified.relays.relays().len(), 1);
        assert_eq!(verified.generation, 1, "generation surfaced to caller");
        assert_eq!(
            verified.expires_at, 1_700_086_400,
            "expiry surfaced to caller"
        );
    }

    #[test]
    fn verify_rejects_unexpected_server_pubkey() {
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).unwrap();
        let other_pubkey = hex::encode([0xff; 32]);

        let err = verify_signed_relay_list(&json, Some(&other_pubkey))
            .expect_err("must reject mismatched server pubkey");
        assert!(matches!(err, SignedError::ServerPubkeyMismatch { .. }));
    }

    #[test]
    fn verify_rejects_tampered_endpoint_addr() {
        // Anti-tamper: a MITM rewriting an endpoint address (pointing at
        // their own relay) must fail without re-signing.
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let mut tampered = signed.clone();
        tampered.nodes[0].endpoints[0].addr = "127.0.0.2".to_owned();
        let json = serde_json::to_string(&tampered).unwrap();

        let err = verify_signed_relay_list(&json, None).expect_err("tampered must fail");
        assert!(matches!(err, SignedError::BadSignature));
    }

    #[test]
    fn verify_rejects_tampered_egress_capability() {
        // Anti-tamper: flipping a node's egress capability (e.g. to make a
        // v4-only exit appear v6-capable) must break the signature.
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let mut tampered = signed.clone();
        tampered.nodes[0].egress.ipv6 = true;
        let json = serde_json::to_string(&tampered).unwrap();

        let err = verify_signed_relay_list(&json, None).expect_err("tampered must fail");
        assert!(matches!(err, SignedError::BadSignature));
    }

    #[test]
    fn verify_rejects_tampered_signed_at() {
        let key = fixed_server_key();
        let mut signed =
            sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        signed.signed_at = 9_999_999_999;
        let json = serde_json::to_string(&signed).unwrap();

        let err = verify_signed_relay_list(&json, None).expect_err("tampered must fail");
        assert!(matches!(err, SignedError::BadSignature));
    }

    #[test]
    fn verify_rejects_signature_replaced_with_zeros() {
        let key = fixed_server_key();
        let mut signed =
            sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        signed.signature_hex = "00".repeat(64);
        let json = serde_json::to_string(&signed).unwrap();

        let err = verify_signed_relay_list(&json, None).expect_err("zero sig must fail");
        assert!(matches!(err, SignedError::BadSignature));
    }

    #[test]
    fn verify_rejects_unsupported_version() {
        let json = r#"{"version":1,"nodes":[],"generation":0,"signed_at":0,"expires_at":0,"server_pubkey_hex":"00","signature_hex":"00"}"#;
        let err = verify_signed_relay_list(json, None).expect_err("v1 must be rejected");
        assert!(matches!(err, SignedError::UnsupportedVersion { got: 1 }));
    }

    #[test]
    fn verify_rejects_pre_v7_canonical_format() {
        // Breaking-change regression: a v6 version number must be
        // rejected since the bump to v7 (here with a v7-shaped body so
        // the rejection is the version gate, not a deserialization miss).
        let json = r#"{"version":6,"nodes":[],"generation":0,"signed_at":0,"expires_at":0,"server_pubkey_hex":"00","signature_hex":"00"}"#;
        let err = verify_signed_relay_list(json, None).expect_err("v6 must be rejected post-v7");
        assert!(matches!(err, SignedError::UnsupportedVersion { got: 6 }));
    }

    #[test]
    fn round_trip_carries_exit_id_through_warren_relay() {
        let key = fixed_server_key();
        let n = JsonNode {
            exit_id: ExitId::from_bytes([0xcc; 16]),
            ..sample_node()
        };
        let signed = sign_relay_list(vec![n], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).unwrap();
        let resolved = verify_signed_relay_list(&json, None).expect("verify");
        let got = resolved
            .relays
            .relays()
            .first()
            .expect("one node")
            .exit_id();
        assert_eq!(
            got,
            ExitId::from_bytes([0xcc; 16]),
            "exit_id must survive the full sign/verify path"
        );
    }

    #[test]
    fn tampering_with_exit_id_breaks_signature() {
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let mut tampered = signed.clone();
        tampered.nodes[0].exit_id = ExitId::from_bytes([0x99; 16]);
        let json = serde_json::to_string(&tampered).unwrap();
        let err = verify_signed_relay_list(&json, None)
            .expect_err("tampered exit_id must fail signature");
        assert!(matches!(err, SignedError::BadSignature));
    }

    #[test]
    fn verify_rejects_invalid_hex_pubkey() {
        let key = fixed_server_key();
        let mut signed =
            sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        signed.server_pubkey_hex = "zz".repeat(32);
        let json = serde_json::to_string(&signed).unwrap();
        let err = verify_signed_relay_list(&json, None).expect_err("bad hex must fail");
        assert!(matches!(err, SignedError::InvalidHex));
    }

    #[test]
    fn verify_rejects_family_mismatching_addr() {
        // A v6 address labelled "ipv4" (or vice versa) must be rejected:
        // the explicit family is a filter input on the client, so a
        // mislabel could route a v4-only client onto a v6 endpoint.
        let key = fixed_server_key();
        let mut node = sample_node();
        node.endpoints[0].family = "ipv6".to_owned(); // addr is 127.0.0.1
        let signed = sign_relay_list(vec![node], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).unwrap();
        let err = verify_signed_relay_list(&json, None).expect_err("family mismatch must fail");
        assert!(matches!(
            err,
            SignedError::Relay(JsonError::InvalidFamily(_))
        ));
    }

    #[test]
    fn signed_format_is_byte_stable_across_serializations() {
        // Wire vector test: freeze the top-level field order for v8. Any
        // serde reordering invalidates every existing signature.
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![], &key, 7, 42, 86442);
        let json = serde_json::to_string(&signed).expect("ser");

        let expected_field_order = [
            r#""version":8"#,
            r#""nodes":[]"#,
            r#""generation":7"#,
            r#""signed_at":42"#,
            r#""expires_at":86442"#,
            r#""server_pubkey_hex":"#,
            r#""signature_hex":"#,
        ];
        let mut last = 0usize;
        for needle in expected_field_order {
            let pos = json[last..]
                .find(needle)
                .unwrap_or_else(|| panic!("field not found in order: {needle} (json={json})"));
            last += pos + needle.len();
        }
    }

    #[test]
    fn signed_version_is_pinned_at_8() {
        // The client and every exit must agree on the signed relay-list wire
        // version. Bumping SIGNED_VERSION is a wire break: it needs a
        // coordinated exit redeploy plus updates to every consumer that pins the
        // number (warren-api `non_auth.rs`, the backend smoke script). Pinning it
        // here makes a silent bump impossible: change the number and this
        // dedicated test fails first, pointing straight at the contract.
        assert_eq!(SIGNED_VERSION, 8);
    }

    #[test]
    fn json_node_field_order_is_frozen_at_v8() {
        // Wire vector test: freeze the JsonNode + JsonEndpoint +
        // JsonListener + JsonEgress + JsonLocation field order. Any drift
        // changes the canonical signing bytes for every entry.
        let node = sample_node();
        let json = serde_json::to_string(&node).expect("ser");
        let expected = [
            r#""id":"#,
            r#""exit_id":"#,
            r#""location":"#,
            r#""country":"#,
            r#""city":"#,
            r#""weight":"#,
            r#""active":"#,
            r#""egress":"#,
            r#""ipv4":"#,
            r#""ipv6":"#,
            r#""endpoints":"#,
            r#""addr":"#,
            r#""family":"#,
            r#""listeners":"#,
            r#""port":"#,
            r#""transport":"#,
            r#""alpn":"#,
        ];
        let mut last = 0usize;
        for needle in expected {
            let pos = json[last..]
                .find(needle)
                .unwrap_or_else(|| panic!("field not found in order: {needle} (json={json})"));
            last += pos + needle.len();
        }
    }

    #[test]
    fn public_wire_omits_geoip_roles_and_multihop_pubkey() {
        // Minimization guard: the v7 wire must NOT carry the dropped v6
        // fields. A censor scraping the list gets geoloc + dial points but
        // no per-IP geoip, no roles, no multihop pubkey.
        let node = sample_node();
        let json = serde_json::to_string(&node).expect("ser");
        for forbidden in ["geoip", "roles", "multihop_pubkey", "ingress"] {
            assert!(
                !json.contains(forbidden),
                "v7 public node must not contain `{forbidden}` (json={json})"
            );
        }
    }

    #[test]
    fn round_trip_with_no_pin_accepts_any_pubkey() {
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).unwrap();
        verify_signed_relay_list(&json, None).expect("TOFU mode must accept self-consistent sig");
    }

    #[test]
    fn tampering_with_generation_breaks_signature() {
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 9, 1_700_000_000, 1_700_086_400);
        let mut tampered = signed.clone();
        tampered.generation = 1;
        let json = serde_json::to_string(&tampered).unwrap();
        let err = verify_signed_relay_list(&json, None).expect_err("tampered generation must fail");
        assert!(matches!(err, SignedError::BadSignature));
    }

    #[test]
    fn tampering_with_expires_at_breaks_signature() {
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let mut tampered = signed.clone();
        tampered.expires_at = 9_999_999_999;
        let json = serde_json::to_string(&tampered).unwrap();
        let err = verify_signed_relay_list(&json, None).expect_err("tampered expires_at must fail");
        assert!(matches!(err, SignedError::BadSignature));
    }

    #[test]
    fn verified_is_expired_respects_signed_expiry() {
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_signed_relay_list(&json, None).expect("verify");
        assert!(
            !v.is_expired(1_700_086_399),
            "one second before expiry: fresh"
        );
        assert!(v.is_expired(1_700_086_400), "at expiry: stale");
        assert!(v.is_expired(1_700_200_000), "well past expiry: stale");
    }

    #[test]
    fn verify_any_accepts_when_signing_key_is_in_the_pinned_set() {
        let key = fixed_server_key();
        let other = hex::encode([0xff; 32]);
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).unwrap();
        let pin = hex::encode(key.verifying_key().as_bytes());
        let v = verify_signed_relay_list_any(&json, &[other.as_str(), pin.as_str()])
            .expect("must accept a key present in the pinned set");
        assert_eq!(v.relays.relays().len(), 1);
    }

    #[test]
    fn verify_any_rejects_when_signing_key_not_in_set() {
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).unwrap();
        let a = hex::encode([0x11; 32]);
        let b = hex::encode([0x22; 32]);
        let err = verify_signed_relay_list_any(&json, &[a.as_str(), b.as_str()])
            .expect_err("none of the pins match the signer");
        assert!(matches!(err, SignedError::ServerPubkeyMismatch { .. }));
    }

    #[test]
    fn verify_any_empty_set_is_tofu() {
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).unwrap();
        verify_signed_relay_list_any(&json, &[])
            .expect("empty set = TOFU, any self-consistent sig");
    }
}
