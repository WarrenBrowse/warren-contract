//! Signed `warren-relays.json` v10 - node (exit/relay/entry) distribution
//! from warren-api to Warren clients. (v10 added the optional per-node
//! `tcp_fallback` carrier capability flag; v9 added the optional per-node
//! `port_forward` NAT-PMP capability flag; v8 added the optional per-node
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
//! **Canonical format** (frozen at v10; any further mutation must rotate
//! to v11):
//!
//! ```text
//! canonical_bytes = serde_json::to_vec(&UnsignedRelayList {
//!     version: 10,
//!     nodes,            // each entry is a JsonNode (v10 vocabulary)
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
//! `egress.ipv6`) with NO egress source address: a client must know an
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

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use warrenguard_wire::ExitId;

use crate::envelope;
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
///
/// **v8 (cover-domain, ADR-0004/wg-0005)** adds the optional per-node
/// `cover_domain`: the hostname on the exit's real X.509 certificate,
/// appended last on [`JsonNode`] (additive, `skip_serializing_if` when
/// absent) to keep pre-v8 canonical bytes reproducible for nodes without
/// it. A node carrying it is dialed via WebPKI SNI instead of the raw
/// Ed25519 public-key pin.
///
/// **v9 (port-forwarding capability, doc 79)** adds the optional per-node
/// `port_forward`: whether the exit runs an enabled NAT-PMP gateway. Warren
/// is mono-IP, so this is a per-exit capability toggle, not a second-IP
/// announcement; the client only offers/prefers port forwarding on exits
/// where it is active. Appended last on [`JsonNode`] (additive,
/// `skip_serializing_if` when absent) so nodes without it keep reproducing
/// their pre-v9 canonical bytes. Signing-canonical like every prior bump:
/// lockstep rollout of warren-api, warren-relay-selector and warren-app.
///
/// **v10 (TCP-fallback carrier capability)** adds the optional per-node
/// `tcp_fallback`: whether the exit terminates the TLS-over-TCP anti-censorship
/// carrier on `:443/tcp`. The client reads it (stamped onto
/// [`WarrenExitAddr::tcp_fallback`](warrenguard_wire::WarrenExitAddr)) to decide
/// whether a UDP-handshake timeout against this exit is worth retrying over TCP.
/// Appended last on [`JsonNode`] (additive, `skip_serializing_if` when absent)
/// so nodes without it keep reproducing their pre-v10 canonical bytes.
/// Signing-canonical like every prior bump: lockstep rollout of warren-api,
/// warren-relay-selector, warren-app and every language SDK that replays
/// `vectors/relays.json`.
pub const SIGNED_VERSION: u32 = 10;

/// Schema version served on `GET /v2/exits`.
///
/// v10 is **frozen and still served on `/v1/exits`**, byte for byte. Client
/// verification is a strict equality (`signed.version != expected`), with no
/// negotiation, so mutating v10 in place would fail every installed client the
/// moment its cache expired: a silent, fleet-wide directory outage. A second
/// route carrying a second version is the only additive shape available, and
/// clients migrate route by route across their own releases.
///
/// v11 = v10 plus six optional node fields (see [`JsonNode`]). Because they are
/// all `skip_serializing_if`, a v10 emission with them unset is byte-identical
/// to a pre-v11 one, which is what lets one `JsonNode` serve both schemas.
pub const SIGNED_VERSION_V2: u32 = 11;

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
/// only: the egress source address is NEVER published to clients.
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
    /// the RPK handshake. Added in v8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover_domain: Option<String>,
    /// Node-level NAT-PMP port-forwarding capability (doc 79): `Some(true)` if
    /// the exit runs an enabled NAT-PMP gateway, `Some(false)` if explicitly
    /// disabled, `None` (skipped from the wire) if the exit binary pre-dates
    /// the flag. Warren is mono-IP, so this is a per-exit capability toggle,
    /// not a second-IP announcement. Added in v9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_forward: Option<bool>,
    /// Node-level TLS-over-TCP fallback carrier capability (v10): `Some(true)` if
    /// the exit terminates the anti-censorship carrier on `:443/tcp`, `Some(false)`
    /// if explicitly disabled, `None` (skipped from the wire) if the exit binary
    /// pre-dates the flag. The client only retries a blocked UDP
    /// handshake over TCP against an exit that advertises it. Added in v10; must
    /// stay last to preserve the canonical field order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_fallback: Option<bool>,

    // ---- v11 (`/v2/exits` only). Every field below is optional and
    // `skip_serializing_if`, so a v10 emission omits all of them and
    // reproduces its canonical bytes exactly. They are declared after
    // `tcp_fallback` to keep the v10 canonical field order intact.
    //
    // All six names are in `SIGNED_V11_FIELDS` from day one even though only
    // the two liveness fields are populated today. That is deliberate: a
    // signed schema is frozen, so appending the naming fields later would
    // force a v12. Reserving the names now costs nothing (an absent optional
    // field changes no bytes) and buys the fleet-naming work a landing spot
    // that needs no further rotation.
    /// Unix second of this node's last heartbeat, on the SERVER's clock.
    ///
    /// Absolute, never an age. The list is cached (ETag on `generation`, and
    /// clients hold it for hours), so a relative age would be frozen at
    /// signing time and become a lie the moment the document is reused. Read
    /// it against [`SignedRelayList::signed_at`], which is in the same signed
    /// document and on the same clock: `signed_at - last_seen_unix` is the
    /// node's staleness at signing, computable with no reference to the
    /// client's own clock. That matters: 2026-08-18 refused 100 % of one
    /// day's mobile logins over device clocks more than 60 s off, and a
    /// freshness rule that consulted the client clock would reopen that class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_unix: Option<u64>,
    /// The server's own verdict that this node is past its heartbeat TTL.
    ///
    /// Redundant with `last_seen_unix` on purpose: it saves every client
    /// hardcoding `EXIT_HEARTBEAT_TTL_SECS`, and it keeps the TTL a server
    /// policy rather than a constant duplicated into three SDKs.
    ///
    /// A stale node is a DIAGNOSTIC, never a candidate. It exists so a client
    /// can tell "this exit aged out of a liveness TTL" from "this exit was
    /// decommissioned", which plain absence cannot express, and which on
    /// 2026-08-29 turned a stalled API host into a host-wide kill-switch
    /// block. Selecting one would replace a fail-closed block with a
    /// fail-slow dial, which is worse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    /// The node's fleet name, composed server-side from its stored
    /// components (`<cc>-<city3>-<env><virt><role><provider><n>`, e.g.
    /// `fr-par-bved1`).
    ///
    /// Composed here and not at the edge, on purpose. The scheme must have
    /// exactly ONE implementation: a wire that shipped the components would
    /// hand every consumer a copy of the rules, and two unreconciled naming
    /// conventions is precisely the problem this replaced. The letters that
    /// build it (`provider_code`, `virt_code`, `city_code`, `node_index`) are
    /// operator-assigned facts that live in the manifest and the database and
    /// have no reason to travel to a client handed the finished name.
    ///
    /// `None` while a node has not reported every component, so a partially
    /// migrated fleet carries no name rather than a malformed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Hosting provider in PLAINTEXT, for display (`Hetzner`, `FDCservers`).
    ///
    /// Not the scheme letter: the letter is not derivable from the name
    /// (FDCservers is `d`, because `f` is FlokiNet) and the name is not
    /// derivable from the letter without a mapping table, which is the
    /// hand-maintained list this field exists to delete.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Virtualization in PLAINTEXT, for display (`KVM`, `Bare metal`).
    /// Auto-detected on the node from DMI, overridable from its manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virt: Option<String>,
}

/// **Signed** node list (full wire format, `relays.json` v10).
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
    /// Hex of the server key that signed this list (for TOFU pinning).
    pub server_pubkey_hex: String,
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
#[non_exhaustive]
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
    /// Signature does not verify against `(server_pubkey,
    /// canonical_bytes)`.
    #[error("signature verification failed")]
    BadSignature,
    /// Signature does not verify AND the payload carries a field outside
    /// the [`SIGNED_VERSION`] schema. The dominant cause is a signer
    /// covering a new field without a version rotation (this verifier
    /// cannot reconstruct the preimage), not a MITM: distinct from
    /// [`Self::BadSignature`] so a fleet-wide schema skew is identifiable
    /// from a single client log line.
    #[error(
        "signature verification failed over a payload with unknown field `{field}` (likely a new signed field emitted without a SIGNED_VERSION rotation)"
    )]
    BadSignatureUnknownField {
        /// Schema path of the first unknown field, leaf redacted (the
        /// name arrives in unauthenticated input).
        field: String,
    },
    /// Per-node parsing errors (invalid id / addr / family).
    #[error(transparent)]
    Relay(#[from] JsonError),
    /// The input exceeds the crate's pre-authentication size gate,
    /// rejected before parsing to bound the allocation an untrusted
    /// payload can force.
    #[error("input exceeds the maximum allowed size")]
    InputTooLarge,
}

impl From<envelope::DecodeError> for SignedError {
    fn from(e: envelope::DecodeError) -> Self {
        match e {
            envelope::DecodeError::InvalidHex => Self::InvalidHex,
            envelope::DecodeError::PubkeyNotOnCurve => Self::PubkeyNotOnCurve,
        }
    }
}

impl SignedError {
    /// Stable, secret-free category for logs and metrics. A caller that only
    /// wants to say a directory verify failed (returning cached/empty) can log
    /// this to keep the failure classes operationally distinct: a pin mismatch,
    /// an unsupported version, and a canonicalization/signature failure demand
    /// very different responses, and the `Display` string is a human sentence,
    /// not a stable label. Never carries a key, address, or other identity
    /// material, so it is safe to emit at any log level.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Json(_) => "malformed-json",
            Self::UnsupportedVersion { .. } => "unsupported-version",
            Self::ServerPubkeyMismatch { .. } => "server-pubkey-mismatch",
            Self::InvalidHex => "invalid-hex",
            Self::PubkeyNotOnCurve => "pubkey-not-on-curve",
            Self::BadSignature => "bad-signature",
            Self::BadSignatureUnknownField { .. } => "bad-signature-unknown-field",
            Self::Relay(_) => "malformed-node",
            Self::InputTooLarge => "input-too-large",
        }
    }
}

/// Serialized field paths of the SIGNED_VERSION == 10 relay-list schema
/// (`[]` marks array elements). This is the emit/verify-side twin of the
/// frozen canonical format: any field addition, even optional, changes the
/// signed preimage for nodes that carry it, so extending this list is a
/// wire break that requires rotating [`SIGNED_VERSION`], never a quiet
/// edit.
const SIGNED_V10_FIELDS: &[&str] = &[
    "version",
    "nodes",
    "generation",
    "signed_at",
    "expires_at",
    "server_pubkey_hex",
    "signature_hex",
    "nodes[].id",
    "nodes[].exit_id",
    "nodes[].location",
    "nodes[].location.country",
    "nodes[].location.city",
    "nodes[].weight",
    "nodes[].active",
    "nodes[].egress",
    "nodes[].egress.ipv4",
    "nodes[].egress.ipv6",
    "nodes[].endpoints",
    "nodes[].endpoints[].addr",
    "nodes[].endpoints[].family",
    "nodes[].endpoints[].listeners",
    "nodes[].endpoints[].listeners[].port",
    "nodes[].endpoints[].listeners[].transport",
    "nodes[].endpoints[].listeners[].alpn",
    "nodes[].cover_domain",
    "nodes[].port_forward",
    "nodes[].tcp_fallback",
];

/// Serialized field paths of the [`SIGNED_VERSION_V2`] schema: every v10
/// path plus the six appended in v11.
///
/// Deliberately declared as v10 + a delta rather than a second hand-written
/// list: the two must never disagree about a shared field, and a copy is how
/// they would. The four naming paths are reserved here before anything emits
/// them, so the fleet-naming work lands without a further rotation.
const SIGNED_V11_EXTRA_FIELDS: &[&str] = &[
    "nodes[].last_seen_unix",
    "nodes[].stale",
    "nodes[].name",
    "nodes[].provider",
    "nodes[].virt",
];

/// Whether `path` is covered by the schema of `version`.
fn field_is_covered(version: u32, path: &str) -> bool {
    SIGNED_V10_FIELDS.contains(&path)
        || (version == SIGNED_VERSION_V2 && SIGNED_V11_EXTRA_FIELDS.contains(&path))
}

/// Field paths in a serialized relay list that are not part of the
/// [`SIGNED_VERSION`]-covered schema, sorted and deduplicated (empty =
/// fully covered). A non-empty result on an emitted list means the signer
/// is about to cover a field deployed verifiers cannot reconstruct: every
/// client would fail with a generic bad-signature, a silent fleet-wide
/// directory outage. Signers must refuse to emit in that case; verifiers
/// use it to turn that failure mode into a distinct, actionable error.
#[must_use]
pub fn unknown_signed_fields(payload: &serde_json::Value) -> Vec<String> {
    unknown_signed_fields_for(SIGNED_VERSION, payload)
}

/// [`unknown_signed_fields`] against a specific schema version, so the
/// `/v2/exits` signer and verifier check the v11 allowlist while `/v1/exits`
/// keeps checking v10 unchanged.
#[must_use]
pub fn unknown_signed_fields_for(version: u32, payload: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    collect_unknown_fields(version, payload, "", &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_unknown_fields(
    version: u32,
    value: &serde_json::Value,
    path: &str,
    out: &mut Vec<String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                if field_is_covered(version, &child_path) {
                    collect_unknown_fields(version, child, &child_path, out);
                } else {
                    out.push(child_path);
                }
            }
        }
        serde_json::Value::Array(items) => {
            let elem_path = format!("{path}[]");
            for item in items {
                collect_unknown_fields(version, item, &elem_path, out);
            }
        }
        _ => {}
    }
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
    sign_relay_list_versioned(
        SIGNED_VERSION,
        nodes,
        server_key,
        generation,
        signed_at,
        expires_at,
    )
}

/// [`sign_relay_list`] stamping [`SIGNED_VERSION_V2`], for `GET /v2/exits`.
///
/// # Panics
/// Same infallible-serialization invariant as [`sign_relay_list`].
#[must_use]
pub fn sign_relay_list_v2(
    nodes: Vec<JsonNode>,
    server_key: &SigningKey,
    generation: u64,
    signed_at: u64,
    expires_at: u64,
) -> SignedRelayList {
    sign_relay_list_versioned(
        SIGNED_VERSION_V2,
        nodes,
        server_key,
        generation,
        signed_at,
        expires_at,
    )
}

/// The one signer both versions share. Version is a parameter rather than two
/// copies of the body: the canonical preimage must stay identical apart from
/// the `version` field, and two copies are how that silently stops being true.
#[must_use]
fn sign_relay_list_versioned(
    version: u32,
    nodes: Vec<JsonNode>,
    server_key: &SigningKey,
    generation: u64,
    signed_at: u64,
    expires_at: u64,
) -> SignedRelayList {
    let server_pubkey_hex = hex::encode(server_key.verifying_key().as_bytes());
    let unsigned = UnsignedRelayList {
        version,
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
        version,
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
/// - [`SignedError::BadSignatureUnknownField`]: signature does not verify
///   and the payload carries a field outside the [`SIGNED_VERSION`]
///   schema (signer/client schema skew).
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
/// Same as [`verify_signed_relay_list`]. Also returns
/// [`SignedError::InputTooLarge`] if `s` exceeds the pre-authentication
/// size gate.
pub fn verify_signed_relay_list_any(
    s: &str,
    expected_server_pubkeys: &[&str],
) -> Result<VerifiedRelayList, SignedError> {
    if s.len() > envelope::MAX_VERIFY_INPUT_LEN {
        return Err(SignedError::InputTooLarge);
    }
    let signed: SignedRelayList = serde_json::from_str(s)?;
    // Both served schemas are accepted: /v1/exits still emits v10 and
    // /v2/exits emits v11. Anything else is refused, as before.
    if signed.version != SIGNED_VERSION && signed.version != SIGNED_VERSION_V2 {
        return Err(SignedError::UnsupportedVersion {
            got: signed.version,
        });
    }
    if !envelope::pin_allows(expected_server_pubkeys, &signed.server_pubkey_hex) {
        let (got, expected) =
            envelope::redact_pin_mismatch(expected_server_pubkeys, &signed.server_pubkey_hex);
        return Err(SignedError::ServerPubkeyMismatch { got, expected });
    }

    // Rebuild the canonical bytes and verify the crypto signature.
    let server_pubkey = envelope::decode_verifying_key(&signed.server_pubkey_hex)?;
    let signature = envelope::decode_signature(&signed.signature_hex)?;

    let unsigned = UnsignedRelayList {
        version: signed.version,
        nodes: &signed.nodes,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
        server_pubkey_hex: &signed.server_pubkey_hex,
    };
    let canonical = serde_json::to_vec(&unsigned).map_err(SignedError::Json)?;

    // verify_strict (rather than verify) also rejects small-order and
    // non-canonical S/R components: defense in depth on top of the basic
    // signature equation.
    server_pubkey
        .verify_strict(&canonical, &signature)
        .map_err(|_| classify_bad_signature(s))?;

    // Convert to a runtime WarrenRelayList.
    let relays: Result<Vec<_>, JsonError> =
        signed.nodes.into_iter().map(json_node_to_warren).collect();
    Ok(VerifiedRelayList {
        relays: WarrenRelayList::new(relays?),
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
        server_pubkey_hex: signed.server_pubkey_hex,
    })
}

/// Refines a failed signature check with the unknown-field scan. Runs
/// only on the failure path (the accept path is untouched, so an extra
/// UNSIGNED field can never turn into a reject: forward compatibility is
/// preserved). The input re-parses as JSON by construction here; a bare
/// [`SignedError::BadSignature`] is kept if it somehow does not.
fn classify_bad_signature(s: &str) -> SignedError {
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(s) else {
        return SignedError::BadSignature;
    };
    // Classify against the payload's OWN declared version: a v11 list read by
    // a build that only knew v10 would otherwise report its six legitimate
    // v11 fields as the cause of a bad signature, which is the opposite of
    // actionable.
    let version = payload
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(SIGNED_VERSION);
    let unknown = unknown_signed_fields_for(version, &payload);
    let Some(path) = unknown.first() else {
        return SignedError::BadSignature;
    };
    let field = match path.rsplit_once('.') {
        Some((prefix, leaf)) => format!("{prefix}.{}", warren_contract::redact(leaf)),
        None => warren_contract::redact(path),
    };
    SignedError::BadSignatureUnknownField { field }
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
            .map_err(|_| JsonError::InvalidIpAddr(warren_contract::redact(&e.addr)))?;
        // `family` is explicit on the wire but must agree with `addr`
        // (defense against a list that mislabels a family to dodge a
        // client's IP-version filter).
        let declared_v6 = match e.family.as_str() {
            "ipv4" => false,
            "ipv6" => true,
            _ => return Err(JsonError::InvalidFamily(warren_contract::redact(&e.family))),
        };
        if declared_v6 != ip.is_ipv6() {
            return Err(JsonError::InvalidFamily(warren_contract::redact(&e.family)));
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
    .with_cover_domain(n.cover_domain)
    .with_port_forward(n.port_forward)
    .with_tcp_fallback(n.tcp_fallback))
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
            port_forward: None,
            tcp_fallback: None,
            last_seen_unix: None,
            stale: None,
            name: None,
            provider: None,
            virt: None,
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
        assert_eq!(
            verified.server_pubkey_hex, expected_pubkey,
            "signer key surfaced to caller for TOFU pinning"
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
    fn server_pubkey_mismatch_error_redacts_both_keys() {
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).unwrap();
        let announced = hex::encode(key.verifying_key().to_bytes());
        let pinned = hex::encode([0xff; 32]);

        let msg = verify_signed_relay_list(&json, Some(&pinned))
            .expect_err("must reject mismatched server pubkey")
            .to_string();
        assert!(
            !msg.contains(&announced),
            "announced key must not leak: {msg}"
        );
        assert!(!msg.contains(&pinned), "pinned key must not leak: {msg}");
        assert!(msg.contains(&announced[..8]), "short prefix kept: {msg}");
        assert!(msg.contains(&pinned[..8]), "short prefix kept: {msg}");
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
        // Wire vector test: freeze the top-level field order for v10. Any
        // serde reordering invalidates every existing signature.
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![], &key, 7, 42, 86442);
        let json = serde_json::to_string(&signed).expect("ser");

        let expected_field_order = [
            r#""version":10"#,
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
    fn signed_version_is_pinned_at_10() {
        // The client and every exit must agree on the signed relay-list wire
        // version. Bumping SIGNED_VERSION is a wire break: it needs a
        // coordinated exit redeploy plus updates to every consumer that pins the
        // number (warren-api `non_auth.rs`, the backend smoke script). Pinning it
        // here makes a silent bump impossible: change the number and this
        // dedicated test fails first, pointing straight at the contract.
        assert_eq!(SIGNED_VERSION, 10);
    }

    #[test]
    fn json_node_field_order_is_frozen_at_v10() {
        // Wire vector test: freeze the JsonNode + JsonEndpoint +
        // JsonListener + JsonEgress + JsonLocation field order, including
        // the v8 addition `cover_domain`, the v9 addition `port_forward`, and
        // the v10 addition `tcp_fallback` (which must serialize last). Any drift
        // changes the canonical signing bytes for every entry.
        let mut node = sample_node();
        node.cover_domain = Some("cover.example.com".to_owned());
        node.port_forward = Some(true);
        node.tcp_fallback = Some(true);
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
            r#""cover_domain":"#,
            r#""port_forward":"#,
            r#""tcp_fallback":"#,
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

    #[test]
    fn verify_accepts_a_pin_differing_only_in_hex_case() {
        // The pin comparison must be case-insensitive, mirroring
        // release.rs's `eq_ignore_ascii_case` policy: a legitimate pin
        // written in a different hex case must not be wrongly rejected.
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).unwrap();
        let upper_pin = hex::encode(key.verifying_key().as_bytes()).to_ascii_uppercase();
        verify_signed_relay_list(&json, Some(&upper_pin))
            .expect("a pin differing only in hex case must still be accepted");
    }

    #[test]
    fn verify_rejects_oversize_input() {
        let oversize = "0".repeat(envelope::MAX_VERIFY_INPUT_LEN + 1);
        let err = verify_signed_relay_list(&oversize, None).expect_err("oversize must be rejected");
        assert!(matches!(err, SignedError::InputTooLarge));
    }

    #[test]
    fn golden_vector_v10_signed_relay_list_is_frozen() {
        // Wire vector (rule 40): freeze today's exact signed bytes for a
        // representative v10 list, including one node WITH cover_domain (v8),
        // port_forward (v9) and tcp_fallback (the v10 addition), produced from a
        // deterministic key. If this drifts, deployed clients stop verifying
        // lists from this build: bump SIGNED_VERSION instead of mutating the
        // canonical shape.
        let key = SigningKey::from_bytes(&[0x07; 32]);
        let mut node = sample_node();
        node.cover_domain = Some("cover.example.com".to_owned());
        node.port_forward = Some(true);
        node.tcp_fallback = Some(true);
        let signed = sign_relay_list(vec![node], &key, 3, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).expect("serialize");

        let expected = concat!(
            "{\"version\":10,",
            "\"nodes\":[{\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\",",
            "\"exit_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",",
            "\"location\":{\"country\":\"FR\",\"city\":\"Paris\"},",
            "\"weight\":100,",
            "\"active\":true,",
            "\"egress\":{\"ipv4\":true,\"ipv6\":false},",
            "\"endpoints\":[{\"addr\":\"127.0.0.1\",\"family\":\"ipv4\",",
            "\"listeners\":[{\"port\":443,\"transport\":\"quic\",\"alpn\":\"h3\"}]}],",
            "\"cover_domain\":\"cover.example.com\",",
            "\"port_forward\":true,\"tcp_fallback\":true}],",
            "\"generation\":3,",
            "\"signed_at\":1700000000,",
            "\"expires_at\":1700086400,",
            "\"server_pubkey_hex\":\"ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c\",",
            "\"signature_hex\":\"981b68143e08de5bef8c235c4882c3d6b10f4da1dbba7dcca1d6f5cea32f15bd",
            "ea6742610e0e18102499ab9cba3ce3a2090edec8a98e2ac3fa50d1b2567fca0f\"}",
        );
        assert_eq!(
            json, expected,
            "signed relay-list v10 wire bytes drifted (wire break: bump SIGNED_VERSION)"
        );

        let pin = hex::encode(key.verifying_key().as_bytes());
        verify_signed_relay_list(&json, Some(&pin)).expect("frozen vector must keep verifying");
    }

    #[test]
    fn port_forward_flows_from_signed_node_to_resolved_relay() {
        // doc 79: a v9 roster node carrying port_forward must surface the
        // capability on the resolved relay so the client can gate the feature.
        // Some(true)/Some(false)/absent(None) must all survive sign -> verify
        // distinctly, and the flag must be part of the signed preimage.
        let key = fixed_server_key();
        let mut on = sample_node();
        on.port_forward = Some(true);
        let signed = sign_relay_list(vec![on], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).expect("serialize");
        let verified = verify_signed_relay_list(&json, None).expect("verify must pass");
        assert_eq!(
            verified.relays.relays()[0].port_forward(),
            Some(true),
            "an enabled NAT-PMP exit must resolve to Some(true)"
        );

        let mut off = sample_node();
        off.port_forward = Some(false);
        let signed = sign_relay_list(vec![off], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).expect("serialize");
        let verified = verify_signed_relay_list(&json, None).expect("verify must pass");
        assert_eq!(
            verified.relays.relays()[0].port_forward(),
            Some(false),
            "a disabled NAT-PMP exit must resolve to Some(false), distinct from unknown"
        );
    }

    #[test]
    fn absent_port_forward_is_skipped_and_preserves_node_bytes() {
        // Additive-field discipline: a node without port_forward (legacy exit)
        // must NOT emit the key (skip_serializing_if) and must resolve to
        // `None` (unknown), so pre-v9 nodes reproduce byte-identical canonical
        // bytes and keep verifying.
        let node = sample_node();
        assert_eq!(node.port_forward, None);
        let node_json = serde_json::to_string(&node).expect("ser");
        assert!(
            !node_json.contains("port_forward"),
            "absent port_forward must be skipped from the wire: {node_json}"
        );

        let key = fixed_server_key();
        let signed = sign_relay_list(vec![node], &key, 1, 1_700_000_000, 1_700_086_400);
        let json = serde_json::to_string(&signed).expect("serialize");
        let verified = verify_signed_relay_list(&json, None).expect("verify must pass");
        assert_eq!(
            verified.relays.relays()[0].port_forward(),
            None,
            "a node with no port_forward flag resolves to unknown"
        );
    }

    #[test]
    fn verify_rejects_tampered_port_forward() {
        // Anti-tamper: flipping a node's port_forward capability (e.g. to make
        // a NAT-PMP-disabled exit appear capable) must break the signature.
        let key = fixed_server_key();
        let mut node = sample_node();
        node.port_forward = Some(false);
        let signed = sign_relay_list(vec![node], &key, 1, 1_700_000_000, 1_700_086_400);
        let mut tampered = signed.clone();
        tampered.nodes[0].port_forward = Some(true);
        let json = serde_json::to_string(&tampered).unwrap();
        let err = verify_signed_relay_list(&json, None).expect_err("tampered must fail");
        assert!(matches!(err, SignedError::BadSignature));
    }

    #[test]
    fn verify_rejects_pre_v9_canonical_format() {
        // Breaking-change regression: the v8 version number must be rejected
        // since the bump to v9 (v8-shaped body so the rejection is the version
        // gate, not a deserialization miss). Pre-v9 clients and lists do not
        // interoperate with v9 without a coordinated redeploy.
        let json = r#"{"version":8,"nodes":[],"generation":0,"signed_at":0,"expires_at":0,"server_pubkey_hex":"00","signature_hex":"00"}"#;
        let err = verify_signed_relay_list(json, None).expect_err("v8 must be rejected post-v9");
        assert!(matches!(err, SignedError::UnsupportedVersion { got: 8 }));
    }

    fn fully_populated_node() -> JsonNode {
        let mut node = sample_node();
        node.cover_domain = Some("cover.example.com".to_owned());
        node.port_forward = Some(true);
        node.tcp_fallback = Some(true);
        node
    }

    #[test]
    fn unknown_signed_fields_flags_fields_outside_the_v10_schema() {
        // The exact fleet-outage shape: a signer whose structs grew a field
        // (node-level, nested, or top-level) while SIGNED_VERSION stayed 10.
        let key = fixed_server_key();
        let signed = sign_relay_list(
            vec![fully_populated_node()],
            &key,
            1,
            1_700_000_000,
            1_700_086_400,
        );
        let mut payload = serde_json::to_value(&signed).expect("to_value");
        payload["nodes"][0]["daita"] = serde_json::Value::Bool(true);
        payload["nodes"][0]["location"]["region"] = serde_json::Value::String("EU".to_owned());
        payload["max_clients"] = serde_json::Value::from(10);

        assert_eq!(
            unknown_signed_fields(&payload),
            vec!["max_clients", "nodes[].daita", "nodes[].location.region"],
            "every field outside the v10 schema must be reported with its path"
        );
    }

    #[test]
    fn v10_schema_allowlist_exactly_covers_a_fully_populated_list() {
        // Set equality both ways: a struct field missing from the allowlist
        // would false-positive the emit guard on every signer; a stale
        // allowlist entry no struct produces would mask a future collision.
        fn collect_paths(value: &serde_json::Value, path: &str, out: &mut Vec<String>) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, child) in map {
                        let child_path = if path.is_empty() {
                            key.clone()
                        } else {
                            format!("{path}.{key}")
                        };
                        collect_paths(child, &child_path, out);
                        out.push(child_path);
                    }
                }
                serde_json::Value::Array(items) => {
                    for item in items {
                        collect_paths(item, &format!("{path}[]"), out);
                    }
                }
                _ => {}
            }
        }

        let key = fixed_server_key();
        let signed = sign_relay_list(
            vec![fully_populated_node()],
            &key,
            1,
            1_700_000_000,
            1_700_086_400,
        );
        let payload = serde_json::to_value(&signed).expect("to_value");
        let mut produced = Vec::new();
        collect_paths(&payload, "", &mut produced);
        produced.sort();
        produced.dedup();

        let mut allowlist: Vec<String> =
            SIGNED_V10_FIELDS.iter().map(|s| (*s).to_owned()).collect();
        allowlist.sort();
        assert_eq!(
            produced, allowlist,
            "the v10 allowlist must match the serialized schema exactly; extending it is a wire break (bump SIGNED_VERSION)"
        );
    }

    /// Emulates a signer whose SIGNED_VERSION == 10 preimage covers one
    /// extra field this verifier does not know: the exact fleet-outage
    /// shape the schema guard exists for.
    fn future_signer_payload(key: &SigningKey, extra_field: &str) -> String {
        let server_pubkey_hex = hex::encode(key.verifying_key().as_bytes());
        let unsigned = UnsignedRelayList {
            version: SIGNED_VERSION,
            nodes: &[sample_node()],
            generation: 1,
            signed_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            server_pubkey_hex: &server_pubkey_hex,
        };
        let mut payload = serde_json::to_value(&unsigned).expect("to_value");
        payload["nodes"][0][extra_field] = serde_json::Value::Bool(true);
        let canonical = serde_json::to_vec(&payload).expect("canonical");
        payload["signature_hex"] =
            serde_json::Value::String(hex::encode(key.sign(&canonical).to_bytes()));
        serde_json::to_string(&payload).expect("serialize")
    }

    #[test]
    fn future_signed_field_yields_the_distinct_schema_skew_error() {
        let key = fixed_server_key();
        let json = future_signer_payload(&key, "daita");

        let err = verify_signed_relay_list(&json, None)
            .expect_err("a preimage this verifier cannot reconstruct must fail");
        assert!(
            matches!(&err, SignedError::BadSignatureUnknownField { field } if field == "nodes[].daita"),
            "schema skew must be distinct from a generic bad signature: {err:?}"
        );
        assert_eq!(err.reason_code(), "bad-signature-unknown-field");
    }

    #[test]
    fn schema_skew_error_redacts_the_unknown_field_name() {
        // The field name arrives in unauthenticated input, so it is log
        // injection surface: only a short prefix may surface.
        let key = fixed_server_key();
        let json = future_signer_payload(&key, "x_padding_class_experimental");

        let err = verify_signed_relay_list(&json, None).expect_err("must fail");
        let msg = err.to_string();
        assert!(
            !msg.contains("x_padding_class_experimental"),
            "full unknown field name must not surface: {msg}"
        );
        assert!(
            msg.contains("nodes[].x_paddin"),
            "redacted prefix kept for diagnosis: {msg}"
        );
    }

    #[test]
    fn unsigned_unknown_field_keeps_verifying() {
        // Forward-compat invariant: an extra field NOT covered by the
        // signature is ignored, never a reject. Hard-rejecting unknown
        // fields (deny_unknown_fields) would black-hole every deployed
        // client during a legitimate rolling upgrade; only the failure
        // path may look at them.
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let mut payload = serde_json::to_value(&signed).expect("to_value");
        payload["advisory"] = serde_json::Value::String("ignored".to_owned());
        let json = serde_json::to_string(&payload).expect("serialize");

        verify_signed_relay_list(&json, None)
            .expect("an unsigned unknown field must not break verification");
    }

    #[test]
    fn tampered_payload_without_unknown_fields_stays_a_plain_bad_signature() {
        // The skew refinement must not reclassify an ordinary MITM tamper.
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let mut tampered = signed.clone();
        tampered.nodes[0].weight = 999;
        let json = serde_json::to_string(&tampered).expect("serialize");

        let err = verify_signed_relay_list(&json, None).expect_err("tampered must fail");
        assert!(matches!(err, SignedError::BadSignature), "got {err:?}");
    }

    #[test]
    fn reason_code_is_distinct_and_secret_free_per_variant() {
        // The whole point of the category is to keep failure classes
        // operationally distinct, so no two variants may collapse to the same
        // code, and a code must never carry identity material even when the
        // variant does (ServerPubkeyMismatch holds redacted key prefixes).
        let variants = [
            SignedError::Json(serde_json::from_str::<serde_json::Value>("{").unwrap_err()),
            SignedError::UnsupportedVersion { got: 9 },
            SignedError::ServerPubkeyMismatch {
                got: "deadbeef".to_owned(),
                expected: "feedface".to_owned(),
            },
            SignedError::InvalidHex,
            SignedError::PubkeyNotOnCurve,
            SignedError::BadSignature,
            SignedError::BadSignatureUnknownField {
                field: "nodes[].deadbeef".to_owned(),
            },
            SignedError::Relay(JsonError::InvalidFamily("v6".to_owned())),
            SignedError::InputTooLarge,
        ];
        let codes: Vec<&str> = variants.iter().map(SignedError::reason_code).collect();
        for code in &codes {
            assert!(!code.is_empty(), "reason_code must be non-empty");
            assert!(
                !code.contains("deadbeef") && !code.contains("feedface"),
                "reason_code must not leak the variant's payload: {code}"
            );
        }
        let unique: std::collections::HashSet<&&str> = codes.iter().collect();
        assert_eq!(
            unique.len(),
            codes.len(),
            "each variant needs a distinct reason_code: {codes:?}"
        );
    }

    #[test]
    fn reason_code_tags_the_error_each_verify_failure_produces() {
        // Tie the codes to the real failure paths a caller sees, so a swallowed
        // Err can be logged with the check that actually failed instead of a
        // fixed "signature verify failed" string.
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let good = serde_json::to_string(&signed).unwrap();

        let mut tampered = signed.clone();
        tampered.nodes[0].endpoints[0].addr = "127.0.0.2".to_owned();
        let bad_sig = serde_json::to_string(&tampered).unwrap();
        assert_eq!(
            verify_signed_relay_list(&bad_sig, None)
                .unwrap_err()
                .reason_code(),
            "bad-signature"
        );

        let wrong_pin = hex::encode([0xff; 32]);
        assert_eq!(
            verify_signed_relay_list(&good, Some(&wrong_pin))
                .unwrap_err()
                .reason_code(),
            "server-pubkey-mismatch"
        );

        let older = r#"{"version":9,"nodes":[],"generation":0,"signed_at":0,"expires_at":0,"server_pubkey_hex":"00","signature_hex":"00"}"#;
        assert_eq!(
            verify_signed_relay_list(older, None)
                .unwrap_err()
                .reason_code(),
            "unsupported-version"
        );

        assert_eq!(
            verify_signed_relay_list("not json", None)
                .unwrap_err()
                .reason_code(),
            "malformed-json"
        );

        let oversize = "0".repeat(envelope::MAX_VERIFY_INPUT_LEN + 1);
        assert_eq!(
            verify_signed_relay_list(&oversize, None)
                .unwrap_err()
                .reason_code(),
            "input-too-large"
        );
    }

    // ---- v11 / `GET /v2/exits` (2026-08-29: absence in the roster could not
    // express "aged out of a liveness TTL" versus "decommissioned", and that
    // ambiguity walled a user's host).

    fn stale_node() -> JsonNode {
        JsonNode {
            last_seen_unix: Some(1_700_000_000),
            stale: Some(true),
            ..sample_node()
        }
    }

    fn named_node() -> JsonNode {
        JsonNode {
            name: Some("fr-par-bved1".to_owned()),
            provider: Some("FDCservers".to_owned()),
            virt: Some("Bare metal".to_owned()),
            ..sample_node()
        }
    }

    /// The wire carries the COMPOSED name and PLAINTEXT labels, never the
    /// scheme letters. The letters (`provider_code`, `city_code`, ...) are
    /// operator-assigned codes that stay in the manifest and the database:
    /// shipping them would hand every consumer a copy of the naming rules, and
    /// two implementations of one scheme is the drift this replaced.
    #[test]
    fn v11_carries_the_composed_name_and_plaintext_never_the_scheme_letters() {
        let key = fixed_server_key();
        let signed = sign_relay_list_v2(vec![named_node()], &key, 12, 1_700_000_000, 1_700_086_400);
        let payload = serde_json::to_value(&signed).expect("to_value");
        let node = &payload["nodes"][0];

        assert_eq!(node["name"], "fr-par-bved1");
        assert_eq!(
            node["provider"], "FDCservers",
            "plaintext, not the letter d"
        );
        assert_eq!(node["virt"], "Bare metal");
        for letter_field in ["provider_code", "virt_code", "city_code", "node_index"] {
            assert_eq!(
                node.get(letter_field),
                None,
                "{letter_field} is a server-side component and must never reach a client"
            );
        }
        assert!(unknown_signed_fields_for(SIGNED_VERSION_V2, &payload).is_empty());
    }

    /// THE regression guard for this whole rotation. A v10 list emitted with
    /// every v11 field unset must reproduce byte-for-byte what it produced
    /// before v11 existed, because client verification is a strict equality
    /// and `/v1/exits` stays frozen at v10 forever.
    #[test]
    fn a_v10_list_is_byte_identical_now_that_v11_fields_exist() {
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 7, 1_700_000_000, 1_700_086_400);
        let payload = serde_json::to_value(&signed).expect("to_value");
        let node = &payload["nodes"][0];

        assert_eq!(signed.version, 10, "/v1 must keep emitting v10");
        for field in ["last_seen_unix", "stale", "name", "provider", "virt"] {
            assert_eq!(
                node.get(field),
                None,
                "an unset v11 field must not appear in a v10 payload: it would \
                 change the signed preimage and every installed client would \
                 fail with a generic bad signature"
            );
        }
        assert!(
            unknown_signed_fields(&payload).is_empty(),
            "a v10 payload stays fully covered by the v10 schema"
        );
    }

    /// The v11 fields ride on `/v2/exits` and verify there.
    #[test]
    fn a_v11_list_carries_the_liveness_fields_and_verifies() {
        let key = fixed_server_key();
        let signed = sign_relay_list_v2(vec![stale_node()], &key, 8, 1_700_000_600, 1_700_086_400);
        assert_eq!(signed.version, SIGNED_VERSION_V2);

        let payload = serde_json::to_value(&signed).expect("to_value");
        assert_eq!(payload["nodes"][0]["last_seen_unix"], 1_700_000_000);
        assert_eq!(payload["nodes"][0]["stale"], true);
        assert!(
            unknown_signed_fields_for(SIGNED_VERSION_V2, &payload).is_empty(),
            "the v11 schema must cover its own fields, or the emit guard 500s"
        );

        let json = serde_json::to_string(&signed).expect("to_string");
        let verified = verify_signed_relay_list(&json, None).expect("a v11 list must verify");
        assert_eq!(verified.relays.relays().len(), 1);
    }

    /// Staleness is read against the envelope's own `signed_at`, never the
    /// client's clock: both timestamps are the server's and are signed
    /// together, so the reading survives caching and is immune to device clock
    /// skew (2026-08-18 refused a whole day of mobile logins over that).
    #[test]
    fn staleness_is_computable_from_the_envelope_without_a_client_clock() {
        let key = fixed_server_key();
        let signed = sign_relay_list_v2(vec![stale_node()], &key, 9, 1_700_000_095, 1_700_086_400);
        let age = signed.signed_at - signed.nodes[0].last_seen_unix.expect("carried");
        assert_eq!(age, 95, "95 s of staleness at signing, on one clock");
    }

    /// A v11 field on a v10 payload is still uncovered, so the emit guard
    /// keeps refusing the exact drift it exists to catch: the rotation must
    /// not have quietly widened v10.
    #[test]
    fn a_v11_field_is_still_uncovered_under_the_v10_schema() {
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let mut payload = serde_json::to_value(&signed).expect("to_value");
        payload["nodes"][0]["stale"] = serde_json::Value::Bool(true);
        assert_eq!(
            unknown_signed_fields(&payload),
            vec!["nodes[].stale".to_owned()],
            "v10 must not have been widened by the v11 rotation"
        );
    }

    /// Widening the verifier to two versions must not widen it to any version.
    #[test]
    fn a_version_that_is_neither_ten_nor_eleven_is_refused() {
        let key = fixed_server_key();
        let signed = sign_relay_list(vec![sample_node()], &key, 1, 1_700_000_000, 1_700_086_400);
        let mut payload = serde_json::to_value(&signed).expect("to_value");
        payload["version"] = serde_json::Value::from(12);
        let json = serde_json::to_string(&payload).expect("to_string");
        assert!(matches!(
            verify_signed_relay_list(&json, None),
            Err(SignedError::UnsupportedVersion { got: 12 })
        ));
    }
}
