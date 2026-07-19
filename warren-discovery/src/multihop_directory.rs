//! Signed **multi-hop directory** - the dynamic, secure source of
//! multi-hop nodes a Warren client assembles a circuit from.
//!
//! # Why a directory (and why this trust shape)
//!
//! The single-hop path fetches `/v1/exits` (server-signed) and
//! cross-checks it against an offline-admin-signed roster. Multi-hop needs
//! more: the client must learn, for each node, the **operational-signed**
//! relay and exit descriptors (`warrenguard_multihop::{RelayDescriptorSigned,
//! ExitDescriptorSigned}`) that bind the node's routing tag, Ed25519 RPK
//! identity and HPKE X25519 key. Those descriptors are minted **offline**
//! by the operational key; warren-api only stores and serves them.
//!
//! The directory therefore carries a three-level trust chain:
//!
//! 1. **server envelope** (`signature_hex`): signed by warren-api's online
//!    key over the canonical bytes, giving freshness (`generation` /
//!    `expires_at`) and anti-rollback. A compromised server can replay a
//!    stale-but-authentic directory (bounded by expiry) but cannot forge
//!    descriptors.
//! 2. **operational certificate** (`operational_cert_hex`): the **root**
//!    key's signature over `operational_pubkey` (see
//!    [`warrenguard_multihop::verify_operational_cert`]). The client pins the
//!    root, so the operational key can rotate without a client rebuild.
//! 3. **descriptors**: each node's relay + exit descriptor, signed by the
//!    operational key. Verified with [`warrenguard_multihop::verify_relay_descriptor`]
//!    / [`warrenguard_multihop::verify_exit_descriptor`].
//!
//! **Accepted risk**: per-node `weight`, the `city` label, and the optional
//! `edge_cert_sha256` browser-edge cert pin are carried in the server
//! envelope only; the operational attestation (`attestation_hex`) binds
//! `country` / `asn` / the exit Ed25519 identity, not `weight`, `city`, or
//! the edge pin. A compromised **online** signer can therefore still steer
//! client traffic weighting, mislabel a node's city, or swap the edge pin,
//! without the offline operational key catching it. The edge pin is
//! DoS-only, though: the datapath stays HPKE-sealed to the
//! operational-attested `exit_x25519_multihop_pubkey`, so a bad pin only
//! breaks the browser's WebTransport edge connection, never confidentiality.
//!
//! # Unified dual-role fleet
//!
//! Every node is **both** relay and exit. A [`NodeEntry`] carries both
//! descriptors for the **same** physical node (same endpoint / Ed25519
//! identity). The client picks two *distinct* nodes per circuit: one's
//! `relay` descriptor as the entry hop, the other's `exit` descriptor as
//! the exit hop. The per-circuit `entry != exit` rule is what preserves
//! unlinkability (a node only ever holds its *own* HPKE key, so when it
//! forwards as an entry it is cryptographically blind to the payload).
//!
//! # `/v1` contract
//!
//! Canonical signing preimage field order is frozen (see
//! `UnsignedMultiHopDirectory`); any mutation = v3 rotation, exactly
//! like the signed relay list.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use warrenguard_multihop::{
    ExitDescAttestation, ExitDescriptorSigned, RelayDescriptorSigned, verify_exit_descriptor_pq,
    verify_exit_descriptor_with_dns_attestation, verify_node_attestation, verify_operational_cert,
    verify_relay_descriptor,
};

use crate::envelope;

/// Current directory format version. Bumping = incompatible rotation.
///
/// **v2** adds the per-node operational attestation (`attestation_hex`)
/// binding `country` / `asn` / `exit_ed25519_pubkey` under the offline
/// operational key, so geographic/AS diversity and the exit TLS pin are
/// cryptographic rather than server-trusted.
pub const MULTIHOP_DIRECTORY_VERSION: u32 = 2;

/// One node in the unified fleet. The same physical node is described as
/// both a relay (entry hop) and an exit (exit hop); both descriptors are
/// operational-signed and share the node's endpoint + Ed25519 identity.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct NodeEntry {
    /// The node as an **entry** hop (blind QUIC forwarder).
    pub relay: RelayDescriptorSigned,
    /// The node as an **exit** hop (HPKE recipient + internet egress).
    pub exit: ExitDescriptorSigned,
    /// ISO 3166-1 alpha-2 country code (selection: entry/exit country).
    pub country: String,
    /// City (free form).
    pub city: String,
    /// Autonomous System number, when known, for entry/exit AS diversity.
    /// `0` = unknown (the selector then cannot enforce AS diversity for
    /// this node and falls back to country-only). Bound by
    /// `attestation_hex`.
    #[serde(default)]
    pub asn: u32,
    /// Relative weight for random weighted selection.
    pub weight: u64,
    /// 128-char hex operational-key attestation over
    /// `(relay_id, exit_ed25519_pubkey, asn, country)` - see
    /// [`warrenguard_multihop::verify_node_attestation`]. Binds the geo + exit
    /// identity under the offline operational key so a compromised
    /// warren-api cannot fake circuit diversity or redirect the exit pin.
    pub attestation_hex: String,
    /// 64-char hex SHA-256 of the node's ephemeral P-256 EdgeConnect cert, for
    /// browser `serverCertificateHashes` pinning of the WebTransport edge.
    /// `None` when the node advertises no edge.
    ///
    /// Server-envelope tier, NOT operational-attested (like `weight` / `city`):
    /// the edge cert rotates every <=14 days, faster than the offline signing
    /// cadence, so warren-api overlays the live hash from the exit heartbeat and
    /// re-signs it with its online key at serve time. A compromised online key
    /// could swap the pin, but the inner datapath is HPKE-sealed to the
    /// operational-attested `exit.exit_x25519_multihop_pubkey`, so the worst
    /// case is DoS, never a confidentiality break (warren-core doc 66).
    ///
    /// Additive: `skip_serializing_if` keeps an edge-less directory byte-identical
    /// to the pre-edge wire, so no directory-version rotation is required.
    ///
    /// Rollout ordering constraint: every client must model this field
    /// BEFORE warren-api starts overlaying pins into served directories. An
    /// older client that does not know the key fails the WHOLE directory
    /// once a pin is served, not just the edge feature: an old Rust build's
    /// `NodeEntry` silently drops the unknown field at deserialize, rebuilds
    /// a canonical preimage missing it, and the server envelope no longer
    /// matches ([`DirectoryError::BadEnvelopeSignature`]); an old TS build's
    /// object-shape check rejects the unknown key outright. Same
    /// client-first ordering as the ADR-0004 `cover_domain` rollout
    /// (`warren-core/docs/X509-COVER-DOMAIN.md`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_cert_sha256: Option<String>,
}

/// Signed multi-hop directory (full wire form). Served verbatim by
/// warren-api at `GET /v1/multihop/directory`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedMultiHopDirectory {
    /// Must equal [`MULTIHOP_DIRECTORY_VERSION`].
    pub version: u32,
    /// The unified node fleet.
    pub nodes: Vec<NodeEntry>,
    /// Monotonic content version (anti-rollback high-water mark).
    pub generation: u64,
    /// Unix epoch seconds the directory was signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which the directory is stale (anti-freeze).
    pub expires_at: u64,
    /// 64-char hex of the **operational** verifying key that signed the
    /// per-node descriptors.
    pub operational_pubkey_hex: String,
    /// 128-char hex Ed25519 signature of the **root** key over
    /// `operational_pubkey` (the operational certificate).
    pub operational_cert_hex: String,
    /// 64-char hex of the **server** (online) verifying key.
    pub server_pubkey_hex: String,
    /// 128-char hex Ed25519 signature of the **server** key over the
    /// canonical bytes (`UnsignedMultiHopDirectory`).
    pub signature_hex: String,
}

/// Canonical signing preimage for the server envelope. Field order frozen;
/// any mutation = v3. Mirrors `signed::UnsignedRelayList`.
#[derive(Debug, Serialize)]
struct UnsignedMultiHopDirectory<'a> {
    version: u32,
    nodes: &'a [NodeEntry],
    generation: u64,
    signed_at: u64,
    expires_at: u64,
    operational_pubkey_hex: &'a str,
    operational_cert_hex: &'a str,
    server_pubkey_hex: &'a str,
}

/// A verified directory: operational-vouched nodes plus the freshness
/// metadata the caller enforces (monotonic `generation`, `expires_at`).
#[derive(Debug, Clone)]
pub struct VerifiedMultiHopDirectory {
    /// The operational key that vouched for the nodes (the trust anchor a
    /// caller embeds into a `MultiHopConfig`).
    pub operational_pubkey: VerifyingKey,
    /// Nodes whose relay AND exit descriptors verified under
    /// `operational_pubkey`.
    pub nodes: Vec<NodeEntry>,
    /// Monotonic content version.
    pub generation: u64,
    /// Unix epoch seconds signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which stale.
    pub expires_at: u64,
    /// Nodes dropped because a descriptor did not verify under the
    /// operational key (a compromised server attempting to inject a node
    /// the offline key never vouched for). Caller should log this.
    pub dropped: usize,
}

impl VerifiedMultiHopDirectory {
    /// True if `now_unix_secs` is at or past the signed expiry. The
    /// live-fetch path rejects expired directories (replay defense).
    #[must_use]
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.expires_at
    }
}

/// Errors raised verifying a [`SignedMultiHopDirectory`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DirectoryError {
    /// Invalid JSON or unexpected structure.
    #[error("invalid signed multi-hop directory: {0}")]
    Json(#[from] serde_json::Error),
    /// `version != MULTIHOP_DIRECTORY_VERSION`.
    #[error(
        "unsupported directory version: {got} (expected {})",
        MULTIHOP_DIRECTORY_VERSION
    )]
    UnsupportedVersion {
        /// Version actually received.
        got: u32,
    },
    /// The declared server pubkey does not match any pinned server key.
    #[error("server pubkey mismatch: got {got}, expected {expected}")]
    ServerPubkeyMismatch {
        /// Redacted prefix of the pubkey hex announced in the JSON
        /// (no-log discipline: never the full key).
        got: String,
        /// Comma-joined redacted prefixes of the pinned set.
        expected: String,
    },
    /// Invalid hex for one of the pubkey/signature fields.
    #[error("invalid hex encoding")]
    InvalidHex,
    /// A pubkey field is not a valid Ed25519 point.
    #[error("pubkey is not a valid Ed25519 point")]
    PubkeyNotOnCurve,
    /// The server envelope signature does not verify.
    #[error("server envelope signature verification failed")]
    BadEnvelopeSignature,
    /// The operational certificate does not verify against any pinned
    /// root key (or no root pin was supplied and one is required).
    #[error("operational certificate does not verify under the pinned root")]
    BadOperationalCert,
    /// A node descriptor in a [`MultiHopDirectoryDraft`] is not vouched for
    /// by the claimed operational key: its relay descriptor, exit
    /// descriptor, or geo/identity attestation does not verify under it.
    #[error("node descriptor not vouched by the claimed operational key")]
    NodeNotVouched,
    /// Re-serializing the parsed draft yielded different JSON than the raw
    /// input: this build dropped a field the publisher sent, i.e. the backend
    /// is older than the directory it is being asked to serve. See
    /// [`ensure_lossless_roundtrip`].
    #[error(
        "directory round-trip is lossy: this build dropped a field the publisher sent \
         (warren-api is older than the directory / its warrenguard pin lags the publisher)"
    )]
    LossyRoundtrip,
    /// The input exceeds the crate's pre-authentication size gate,
    /// rejected before parsing to bound the allocation an untrusted
    /// payload can force.
    #[error("input exceeds the maximum allowed size")]
    InputTooLarge,
    /// A node's `edge_cert_sha256` is `Some` but is not a well-formed
    /// 64-char hex SHA-256, mirroring the TS verifier's `asFixedHex` check
    /// (`packages/core/src/discovery/multihop.ts`) so a malformed pin is
    /// rejected by every implementation rather than silently accepted only
    /// by Rust.
    #[error("edge_cert_sha256 is not a well-formed 64-char hex pin: {prefix}")]
    MalformedEdgeCertPin {
        /// Redacted prefix of the offending value (no-log discipline: never
        /// the full pin).
        prefix: String,
    },
}

impl From<envelope::DecodeError> for DirectoryError {
    fn from(e: envelope::DecodeError) -> Self {
        match e {
            envelope::DecodeError::InvalidHex => Self::InvalidHex,
            envelope::DecodeError::PubkeyNotOnCurve => Self::PubkeyNotOnCurve,
        }
    }
}

/// `true` iff `s` is exactly 64 ASCII hex chars (either case), the length a
/// SHA-256 hex digest must have. Mirrors the TS verifier's
/// `asFixedHex(v, 32, 'edge_cert_sha256')` check byte for byte, so a
/// malformed pin is rejected the same way by both implementations.
fn is_valid_edge_cert_pin(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Fails on the first node whose `edge_cert_sha256` is `Some` but not a
/// well-formed pin. Shared by the verify and sign paths: a malformed pin
/// must be refused wherever it is encountered, not merely accepted by a
/// lenient signer and only caught by a strict verifier (or vice versa).
fn check_edge_cert_pins(nodes: &[NodeEntry]) -> Result<(), DirectoryError> {
    for node in nodes {
        if let Some(pin) = node.edge_cert_sha256.as_deref()
            && !is_valid_edge_cert_pin(pin)
        {
            return Err(DirectoryError::MalformedEdgeCertPin {
                prefix: warren_contract::redact(pin),
            });
        }
    }
    Ok(())
}

/// Fails when re-serializing a parsed [`MultiHopDirectoryDraft`] is LOSSY
/// versus the raw POSTed bytes, i.e. this `warren-api` build's structs dropped
/// a field the publisher (`wapi`) sent because the backend is built against an
/// OLDER `warrenguard` engine than the directory it is being asked to store.
///
/// Additive directory fields (e.g. the ADR-0004 `cover_domain`) are
/// `#[serde(default, skip_serializing_if = "Option::is_none")]` optionals, so a
/// too-old struct silently deserializes them to `None` and re-serializes
/// WITHOUT them. That exact silent strip shipped a `cover_domain`-less directory
/// to clients and broke the X.509 fleet with NO error at publish time. Calling
/// this in the POST path converts the silent strip into a loud rejection: the
/// operator sees the publish fail instead of a quietly degraded fleet. Storing
/// the raw bytes after this passes then guarantees the serve path (same build,
/// so equally lossless) is faithful too.
///
/// # Errors
/// [`DirectoryError::InputTooLarge`] if `raw` exceeds the pre-authentication
/// size gate; [`DirectoryError::Json`] if `raw` is not a valid draft;
/// [`DirectoryError::LossyRoundtrip`] if any field was dropped.
pub fn ensure_lossless_roundtrip(raw: &[u8]) -> Result<(), DirectoryError> {
    if raw.len() > envelope::MAX_VERIFY_INPUT_LEN {
        return Err(DirectoryError::InputTooLarge);
    }
    let original: serde_json::Value = serde_json::from_slice(raw)?;
    let draft: MultiHopDirectoryDraft = serde_json::from_value(original.clone())?;
    let reserialized = serde_json::to_value(&draft)?;
    if original != reserialized {
        return Err(DirectoryError::LossyRoundtrip);
    }
    Ok(())
}

/// Signs a multi-hop directory with the **server** (online) key. The
/// `operational_pubkey` and its root `operational_cert` are produced
/// offline and passed in; this function never holds the operational or
/// root key. Intended for the warren-api side only.
///
/// # Errors
/// [`DirectoryError::MalformedEdgeCertPin`] if any node's `edge_cert_sha256`
/// is `Some` but not a well-formed 64-char hex pin: refusing to sign here
/// means a signer can never mint a directory a verifier would reject.
///
/// # Panics
/// Panics only if `serde_json::to_vec(&UnsignedMultiHopDirectory)` fails,
/// which is infallible for this owned-string/scalar schema.
#[allow(clippy::too_many_arguments)]
pub fn sign_multihop_directory(
    nodes: Vec<NodeEntry>,
    server_key: &SigningKey,
    operational_pubkey: &VerifyingKey,
    operational_cert: &[u8; 64],
    generation: u64,
    signed_at: u64,
    expires_at: u64,
) -> Result<SignedMultiHopDirectory, DirectoryError> {
    check_edge_cert_pins(&nodes)?;
    Ok(sign_multihop_directory_unchecked(
        nodes,
        server_key,
        operational_pubkey,
        operational_cert,
        generation,
        signed_at,
        expires_at,
    ))
}

/// Signs without the `edge_cert_sha256` format gate. Crate-private: every
/// production entry point goes through [`sign_multihop_directory`], checked.
/// Exists so a test can mint an authentically-signed envelope carrying a
/// malformed pin, to prove the VERIFIER independently fails closed rather
/// than relying solely on the signer's own gate.
#[allow(clippy::too_many_arguments)]
fn sign_multihop_directory_unchecked(
    nodes: Vec<NodeEntry>,
    server_key: &SigningKey,
    operational_pubkey: &VerifyingKey,
    operational_cert: &[u8; 64],
    generation: u64,
    signed_at: u64,
    expires_at: u64,
) -> SignedMultiHopDirectory {
    let server_pubkey_hex = hex::encode(server_key.verifying_key().as_bytes());
    let operational_pubkey_hex = hex::encode(operational_pubkey.as_bytes());
    let operational_cert_hex = hex::encode(operational_cert);
    let unsigned = UnsignedMultiHopDirectory {
        version: MULTIHOP_DIRECTORY_VERSION,
        nodes: &nodes,
        generation,
        signed_at,
        expires_at,
        operational_pubkey_hex: &operational_pubkey_hex,
        operational_cert_hex: &operational_cert_hex,
        server_pubkey_hex: &server_pubkey_hex,
    };
    let canonical = serde_json::to_vec(&unsigned)
        .expect("UnsignedMultiHopDirectory JSON serialization is infallible");
    let signature = server_key.sign(&canonical);
    SignedMultiHopDirectory {
        version: MULTIHOP_DIRECTORY_VERSION,
        nodes,
        generation,
        signed_at,
        expires_at,
        operational_pubkey_hex,
        operational_cert_hex,
        server_pubkey_hex,
        signature_hex: hex::encode(signature.to_bytes()),
    }
}

/// Single-pin convenience over [`verify_multihop_directory_any`]: verifies
/// against at most one expected server pubkey and one expected root
/// pubkey (`None` = TOFU for that pin). Mirrors the shape of
/// [`crate::verify_signed_relay_list`] / [`crate::verify_roster`].
///
/// # Errors
/// Same as [`verify_multihop_directory_any`].
pub fn verify_multihop_directory(
    s: &str,
    expected_server_pubkey: Option<&str>,
    expected_root_pubkey: Option<&str>,
) -> Result<VerifiedMultiHopDirectory, DirectoryError> {
    let servers: Vec<&str> = expected_server_pubkey.into_iter().collect();
    let roots: Vec<&str> = expected_root_pubkey.into_iter().collect();
    verify_multihop_directory_any(s, &servers, &roots)
}

/// Verifies a [`SignedMultiHopDirectory`] end to end:
///
/// 1. version + server-pubkey pin (`expected_server_pubkeys`, empty = TOFU);
/// 2. server envelope signature over the canonical bytes;
/// 3. operational certificate against a pinned **root** key
///    (`expected_root_pubkeys` - empty = TOFU, accept the carried
///    operational key as-is, intended for dev/bench only);
/// 4. each node's relay + exit descriptor under the operational key,
///    dropping (and counting) any node that fails.
///
/// Freshness (`generation` monotonicity, `expires_at`) is enforced by the
/// caller via the returned [`VerifiedMultiHopDirectory`], keeping this
/// function clock-free.
///
/// # Errors
/// See [`DirectoryError`]. Also returns [`DirectoryError::InputTooLarge`]
/// if `s` exceeds the pre-authentication size gate.
///
/// # Panics
/// Panics only if re-serializing the already-deserialized
/// `UnsignedMultiHopDirectory` to canonical JSON fails, which is
/// impossible for a value that just round-tripped through `serde_json`
/// (no maps with non-string keys, no non-finite floats).
pub fn verify_multihop_directory_any(
    s: &str,
    expected_server_pubkeys: &[&str],
    expected_root_pubkeys: &[&str],
) -> Result<VerifiedMultiHopDirectory, DirectoryError> {
    if s.len() > envelope::MAX_VERIFY_INPUT_LEN {
        return Err(DirectoryError::InputTooLarge);
    }
    let signed: SignedMultiHopDirectory = serde_json::from_str(s)?;
    if signed.version != MULTIHOP_DIRECTORY_VERSION {
        return Err(DirectoryError::UnsupportedVersion {
            got: signed.version,
        });
    }

    // Fail-closed structural check, same position as the TS verifier's
    // per-node `validateNode` (before any signature verification): an
    // untrusted directory with a malformed edge-cert pin is rejected outright
    // rather than accepted here and only caught by the TS sibling.
    check_edge_cert_pins(&signed.nodes)?;

    // (1) server pubkey pin
    if !envelope::pin_allows(expected_server_pubkeys, &signed.server_pubkey_hex) {
        let (got, expected) =
            envelope::redact_pin_mismatch(expected_server_pubkeys, &signed.server_pubkey_hex);
        return Err(DirectoryError::ServerPubkeyMismatch { got, expected });
    }

    // (2) server envelope signature
    let server_pubkey = envelope::decode_verifying_key(&signed.server_pubkey_hex)?;
    let canonical = {
        let unsigned = UnsignedMultiHopDirectory {
            version: signed.version,
            nodes: &signed.nodes,
            generation: signed.generation,
            signed_at: signed.signed_at,
            expires_at: signed.expires_at,
            operational_pubkey_hex: &signed.operational_pubkey_hex,
            operational_cert_hex: &signed.operational_cert_hex,
            server_pubkey_hex: &signed.server_pubkey_hex,
        };
        serde_json::to_vec(&unsigned)
            .expect("UnsignedMultiHopDirectory JSON serialization is infallible")
    };
    let envelope_sig = envelope::decode_signature(&signed.signature_hex)?;
    // verify_strict: defense in depth, rejects small-order/non-canonical
    // signatures the basic verification equation would still accept.
    server_pubkey
        .verify_strict(&canonical, &envelope_sig)
        .map_err(|_| DirectoryError::BadEnvelopeSignature)?;

    // (3) operational certificate against the pinned root
    let operational_pubkey = envelope::decode_verifying_key(&signed.operational_pubkey_hex)?;
    let cert: [u8; 64] = hex::decode(&signed.operational_cert_hex)
        .map_err(|_| DirectoryError::InvalidHex)?
        .try_into()
        .map_err(|_| DirectoryError::InvalidHex)?;
    if expected_root_pubkeys.is_empty() {
        // TOFU (dev/bench): no root pin, trust the carried operational key.
    } else {
        let mut ok = false;
        for root_hex in expected_root_pubkeys {
            let Ok(root) = envelope::decode_verifying_key(root_hex) else {
                continue;
            };
            if verify_operational_cert(&root, &operational_pubkey, &cert).is_ok() {
                ok = true;
                break;
            }
        }
        if !ok {
            return Err(DirectoryError::BadOperationalCert);
        }
    }

    // (4) per-node descriptor verification under the operational key
    let mut kept = Vec::with_capacity(signed.nodes.len());
    let mut dropped = 0usize;
    for node in signed.nodes {
        if node_fully_vouched(&operational_pubkey, &node) {
            kept.push(node);
        } else {
            dropped += 1;
        }
    }

    Ok(VerifiedMultiHopDirectory {
        operational_pubkey,
        nodes: kept,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
        dropped,
    })
}

/// Operator-produced **draft** of a multi-hop directory: the operational
/// material (nodes + operational pubkey + root certificate) WITHOUT the
/// server envelope. Built offline by `wapi` - the operational and root
/// keys are never online - and POSTed to warren-api, which wraps it with
/// the server-key freshness envelope at serve time via
/// [`sign_directory_draft`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MultiHopDirectoryDraft {
    /// The unified node fleet, each carrying operational-signed relay +
    /// exit descriptors.
    pub nodes: Vec<NodeEntry>,
    /// 64-char hex of the operational verifying key.
    pub operational_pubkey_hex: String,
    /// 128-char hex root signature over the operational pubkey.
    pub operational_cert_hex: String,
    /// Monotonic content version set by the offline admin (anti-rollback).
    /// warren-api copies it into the server envelope; it never invents a
    /// generation, so a replayed-but-older draft cannot raise it. The
    /// admin bumps it on every re-mint.
    pub generation: u64,
}

impl MultiHopDirectoryDraft {
    /// Sanity-checks the draft warren-api receives: the operational
    /// pubkey + cert hex parse, and **every** node's relay and exit
    /// descriptor verifies under the claimed operational key. Lets
    /// warren-api refuse a malformed or internally-inconsistent draft
    /// (it cannot verify the root cert - it holds no root pin - but it
    /// can reject descriptors the claimed operational key did not sign).
    ///
    /// # Errors
    /// - [`DirectoryError::InvalidHex`] / [`DirectoryError::PubkeyNotOnCurve`]
    ///   for malformed operational fields.
    /// - [`DirectoryError::NodeNotVouched`] if any node descriptor does
    ///   not verify under the claimed operational key.
    pub fn validate_self_consistent(&self) -> Result<(), DirectoryError> {
        let operational_pubkey = envelope::decode_verifying_key(&self.operational_pubkey_hex)?;
        let _cert: [u8; 64] = hex::decode(&self.operational_cert_hex)
            .map_err(|_| DirectoryError::InvalidHex)?
            .try_into()
            .map_err(|_| DirectoryError::InvalidHex)?;
        for node in &self.nodes {
            if !node_fully_vouched(&operational_pubkey, node) {
                return Err(DirectoryError::NodeNotVouched);
            }
        }
        Ok(())
    }
}

/// Wraps an operator [`MultiHopDirectoryDraft`] with the **server-key**
/// freshness envelope. warren-api calls this at serve time; the
/// operational and root keys are never needed (already embedded in the
/// draft). This is the only signing warren-api performs for the
/// directory, exactly mirroring how it signs the relay list.
///
/// # Errors
/// - [`DirectoryError::InvalidHex`] / [`DirectoryError::PubkeyNotOnCurve`]
///   if the draft's operational pubkey or certificate hex is malformed.
/// - [`DirectoryError::MalformedEdgeCertPin`] if any node's
///   `edge_cert_sha256` is `Some` but not a well-formed 64-char hex pin.
pub fn sign_directory_draft(
    draft: &MultiHopDirectoryDraft,
    server_key: &SigningKey,
    signed_at: u64,
    expires_at: u64,
) -> Result<SignedMultiHopDirectory, DirectoryError> {
    let operational_pubkey = envelope::decode_verifying_key(&draft.operational_pubkey_hex)?;
    let cert: [u8; 64] = hex::decode(&draft.operational_cert_hex)
        .map_err(|_| DirectoryError::InvalidHex)?
        .try_into()
        .map_err(|_| DirectoryError::InvalidHex)?;
    sign_multihop_directory(
        draft.nodes.clone(),
        server_key,
        &operational_pubkey,
        &cert,
        draft.generation,
        signed_at,
        expires_at,
    )
}

/// Censorship-minimization: returns a copy of `nodes` with every
/// node's **exit egress IP redacted** (`exit.endpoint = None`), for the
/// client-facing `/v1/multihop/directory`.
///
/// The client never dials the exit (it dials the entry relay, whose
/// `relay.endpoint` is kept); only the auth-gated relay-facing directory
/// carries the exit endpoint. Because `endpoint` is **not** under the
/// operational descriptor signature, redacting it leaves
/// `verify_exit_descriptor` (and the whole per-node chain) valid. The
/// server envelope is recomputed over the redacted nodes at serve time
/// ([`sign_directory_draft`]), so the client copy verifies end to end.
///
/// This only hides anything for **exit-only** nodes: a dual-role node's
/// IP is already exposed via its `relay.endpoint`.
#[must_use]
pub fn redact_exit_endpoints(nodes: &[NodeEntry]) -> Vec<NodeEntry> {
    nodes
        .iter()
        .map(|n| {
            let mut n = n.clone();
            n.exit.endpoint = None;
            n
        })
        .collect()
}

/// True iff every operational-signed part of `node` verifies under
/// `operational_pubkey`: the relay descriptor, the exit descriptor, and
/// the geo+identity attestation. A node failing any check is not vouched
/// by the offline key and must be dropped.
fn node_fully_vouched(operational_pubkey: &VerifyingKey, node: &NodeEntry) -> bool {
    if verify_relay_descriptor(operational_pubkey, &node.relay).is_err() {
        return false;
    }
    // PQ first, then the classical contexts (mirrors the relay's
    // `verify_descriptor_any_version` so a pool can mix `/v1`, `/v2` and PQ
    // descriptors during a rolling fleet upgrade). The PQ context binds both
    // the ML-KEM key and the dns bit, so a PQ-verified exit needs no further
    // dns-attestation policy.
    if verify_exit_descriptor_pq(operational_pubkey, &node.exit).is_err() {
        // Multi-hop client policy (engine spec): reject an exit that advertises
        // `dns_disabled = true` but is only `/v1`-signed (the bit is unattested), a
        // downgrade-attack suspect that could silently disable in-tunnel DNS. An
        // attested exit, or an unattested exit with DNS enabled, is kept.
        match verify_exit_descriptor_with_dns_attestation(operational_pubkey, &node.exit) {
            Err(_) => return false,
            Ok(ExitDescAttestation::Unattested) if node.exit.dns_disabled => return false,
            Ok(_) => {}
        }
    }
    let Ok(att_bytes) = hex::decode(&node.attestation_hex) else {
        return false;
    };
    let Ok(att): Result<[u8; 64], _> = att_bytes.try_into() else {
        return false;
    };
    verify_node_attestation(
        operational_pubkey,
        &node.relay.relay_id,
        &node.exit.exit_ed25519_pubkey,
        node.asn,
        &node.country,
        &att,
    )
    .is_ok()
}

/// A trusted exit projected from a verified multi-hop directory: the flat,
/// client-facing dial view. Every node kept here passed the full operational +
/// attestation checks, including the anti-downgrade DNS-attestation policy in
/// `node_fully_vouched`, so `dns_disabled` is trustworthy.
#[derive(Debug, Clone)]
pub struct VerifiedExit {
    /// 16-byte exit identifier (cleartext routing key for the frame).
    pub exit_id: [u8; 16],
    /// The exit's Ed25519 identity (TLS RPK).
    pub exit_ed25519_pubkey: [u8; 32],
    /// The exit's long-lived X25519 HPKE recipient key.
    pub exit_x25519_multihop_pubkey: [u8; 32],
    /// Entry-relay QUIC endpoint to dial (v7 redacts the exit egress IP; the
    /// client always dials the entry hop).
    pub endpoint: std::net::SocketAddr,
    /// ISO 3166-1 alpha-2 country.
    pub country: String,
    /// Autonomous System number (`0` = unknown), the AS-diversity input for
    /// [`CircuitPolicy`]. Bound by the node attestation, like `country`.
    pub asn: u32,
    /// City.
    pub city: String,
    /// Selection weight.
    pub weight: u64,
    /// The exit runs no in-tunnel DNS forwarder (trustworthy: unattested
    /// `dns_disabled` exits are dropped by `node_fully_vouched`).
    pub dns_disabled: bool,
    /// X.509 cover-domain SNI from the relay descriptor (ADR-0004), if any.
    pub cover_domain: Option<String>,
    /// The dialed hop advertises the TLS-over-TCP anti-censorship carrier
    /// (roster v10): a UDP-blocked dial may be retried over `:443/tcp` under the
    /// `cover_domain` SNI. After [`VerifiedExit::via_entry`] this is the ENTRY's
    /// flag (the hop the client actually dials), mirroring `cover_domain`. The
    /// transport arms the UDP->TCP fallback race only when this is set AND a
    /// `cover_domain` is present.
    pub tcp_fallback: bool,
    /// SHA-256 hex of the dialed hop's EdgeConnect cert for browser pinning,
    /// if it advertises an edge. After [`VerifiedExit::via_entry`] this is the
    /// ENTRY's edge cert (the WebTransport the browser actually connects to).
    pub edge_cert_sha256: Option<String>,
    /// The exit's ML-KEM-768 recipient key (the X-Wing hybrid-seal half),
    /// present ONLY when the PQ operational signature bound it. A key a
    /// classical signature merely transported stays `None`: surfacing an
    /// unbound key would hand the dial layer downgrade-forgeable PQ material.
    pub exit_mlkem768_pubkey: Option<Vec<u8>>,
}

/// A trusted node projected as an **entry** hop (blind QUIC forwarder). Same
/// vetting as [`VerifiedExit`]; carries the co-located exit id so the
/// per-circuit `entry != exit` rule can be enforced without a node handle.
#[derive(Debug, Clone)]
pub struct VerifiedEntry {
    /// The relay's Ed25519 identity (TLS RPK of the dialed hop), also the
    /// handle for cross-checking the node against the signed relay list.
    pub relay_ed25519_pubkey: [u8; 32],
    /// Entry-relay QUIC endpoint to dial.
    pub endpoint: std::net::SocketAddr,
    /// ISO 3166-1 alpha-2 country.
    pub country: String,
    /// Autonomous System number (`0` = unknown), the AS-diversity input for
    /// [`CircuitPolicy`]. Bound by the node attestation, like `country`.
    pub asn: u32,
    /// City.
    pub city: String,
    /// Selection weight.
    pub weight: u64,
    /// X.509 cover-domain SNI from the relay descriptor (ADR-0004), if any.
    pub cover_domain: Option<String>,
    /// The entry hop advertises the TLS-over-TCP anti-censorship carrier
    /// (roster v10): a UDP-blocked dial to this hop may be retried over
    /// `:443/tcp` under the `cover_domain` SNI.
    pub tcp_fallback: bool,
    /// SHA-256 hex of this entry hop's EdgeConnect cert for browser pinning,
    /// if it advertises an edge; the pin for the WebTransport a browser dials.
    pub edge_cert_sha256: Option<String>,
    /// The exit id of the SAME physical node (relay and exit are co-located),
    /// the identity used to refuse `entry == exit` circuits.
    pub exit_id: [u8; 16],
}

impl VerifiedExit {
    /// The circuit view of this exit dialed through an entry node that the
    /// `policy` permits.
    ///
    /// The client dials the ENTRY and forwards to the exit, so three fields
    /// take the entry's values: the dial `endpoint`, the `cover_domain` SNI,
    /// and `exit_ed25519_pubkey` (which the transport consumes as the RPK /
    /// relay-auth identity of the hop it actually dials, NOT as the exit's
    /// identity). Only what the HPKE-sealed setup frame needs stays the
    /// exit's: `exit_x25519_multihop_pubkey` and the `exit_id` routing tag.
    ///
    /// Returns `None` when [`CircuitPolicy::permits`] rejects the pair: a
    /// same-node circuit (a node forwarding to itself sees both sides, breaking
    /// unlinkability), a same-country circuit, or a same-AS circuit on a fleet
    /// spanning multiple ASNs. Taking the policy as an argument makes the
    /// diversity check impossible to skip: every entry-selected circuit is
    /// gated by the one shared rule, so an SDK caller can no longer form a
    /// topology the app forbids.
    #[must_use]
    pub fn via_entry(&self, entry: &VerifiedEntry, policy: &CircuitPolicy) -> Option<VerifiedExit> {
        if !policy.permits(entry, self) {
            return None;
        }
        Some(VerifiedExit {
            endpoint: entry.endpoint,
            cover_domain: entry.cover_domain.clone(),
            // The carrier terminates at the hop the client dials, so this must be
            // the ENTRY's flag, not the exit's `..self` value the spread carries.
            tcp_fallback: entry.tcp_fallback,
            edge_cert_sha256: entry.edge_cert_sha256.clone(),
            exit_ed25519_pubkey: entry.relay_ed25519_pubkey,
            ..self.clone()
        })
    }
}

/// The multi-hop circuit **security policy**: which `(entry, exit)` hop pairs
/// may legally form a 2-hop circuit. This is the single home of the diversity
/// rule that every client (the app daemon, iOS, and the SDK family) enforces
/// identically, so an SDK-built circuit can never be a topology the app's
/// security rule forbids.
///
/// The rule: entry and exit are **distinct physical nodes** in **different
/// countries** (mandatory), and on **different non-zero ASNs** when the fleet
/// spans two or more ASNs. A single-AS (or AS-unknown) fleet relaxes the AS
/// clause so a homogeneous deployment can still form circuits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitPolicy {
    /// AS diversity is mandatory only when the fleet spans at least two
    /// distinct non-zero ASNs.
    as_diversity_required: bool,
}

impl CircuitPolicy {
    /// Derives the policy from a verified directory's fleet AS spread.
    #[must_use]
    pub fn for_directory(dir: &VerifiedMultiHopDirectory) -> Self {
        Self::from_asns(dir.nodes.iter().map(|n| n.asn))
    }

    /// Derives the policy from node ASNs (`0` = unknown). For the flat-view
    /// consumers that hold [`VerifiedMultiHopDirectory::entries`] /
    /// [`VerifiedMultiHopDirectory::exits`] rather than the directory handle:
    /// `entries()` projects every vouched node, so its AS set equals the
    /// fleet's.
    #[must_use]
    pub fn from_asns(asns: impl IntoIterator<Item = u32>) -> Self {
        let mut seen = std::collections::HashSet::new();
        for asn in asns {
            if asn != 0 {
                seen.insert(asn);
            }
        }
        Self {
            as_diversity_required: seen.len() >= 2,
        }
    }

    /// `true` if this fleet mandates AS diversity between the two hops.
    #[must_use]
    pub fn as_diversity_required(&self) -> bool {
        self.as_diversity_required
    }

    /// `true` iff `entry` and `exit` may form a circuit under this policy:
    /// distinct nodes, different countries, and different non-zero ASNs when
    /// AS diversity is required.
    #[must_use]
    pub fn permits(&self, entry: &VerifiedEntry, exit: &VerifiedExit) -> bool {
        circuit_permitted(
            self.as_diversity_required,
            &entry.country,
            entry.asn,
            &exit.country,
            exit.asn,
            entry.exit_id != exit.exit_id,
        )
    }
}

/// The single definition of the circuit diversity rule, shared by
/// [`CircuitPolicy::permits`] (flat entry/exit views) and [`valid_circuits`]
/// (the directory `nodes` view) so the invariant has exactly one home and
/// cannot drift between the app and SDK families.
fn circuit_permitted(
    as_diversity_required: bool,
    entry_country: &str,
    entry_asn: u32,
    exit_country: &str,
    exit_asn: u32,
    distinct_node: bool,
) -> bool {
    distinct_node
        && !entry_country.eq_ignore_ascii_case(exit_country)
        && !(as_diversity_required && (entry_asn == 0 || exit_asn == 0 || entry_asn == exit_asn))
}

/// `true` when `country` satisfies the optional `filter` (empty = any).
fn country_matches(filter: &str, country: &str) -> bool {
    filter.is_empty() || filter.eq_ignore_ascii_case(country)
}

/// Every `(entry_idx, exit_idx)` pair (indices into `dir.nodes`) that forms a
/// valid circuit under the optional `entry_country` / `exit_country` hints
/// (empty = any), the [`CircuitPolicy`] diversity rule, and the drained-node
/// avoid-set `exclude_exit_ids` (an exit id excluded on BOTH legs).
///
/// This is the directory-view counterpart of [`CircuitPolicy::permits`], for
/// callers that select over `dir.nodes` (the app daemon and iOS). The SDK
/// family selects over the flat entry/exit projections and gates each pair
/// with [`VerifiedExit::via_entry`], but both paths share `circuit_permitted`,
/// so the security rule is identical.
#[must_use]
pub fn valid_circuits(
    dir: &VerifiedMultiHopDirectory,
    entry_country: &str,
    exit_country: &str,
    exclude_exit_ids: &[[u8; 16]],
) -> Vec<(usize, usize)> {
    let policy = CircuitPolicy::for_directory(dir);
    let mut pairs = Vec::new();
    for (i, e) in dir.nodes.iter().enumerate() {
        if !country_matches(entry_country, &e.country) {
            continue;
        }
        // A drained node is excluded as the ENTRY too: a drain precedes a
        // whole-box restart (fleet rollout) and its admission gate refuses new
        // QUIC connections outright, so a circuit entering through it either
        // dies at the swap or can never be dialed at all.
        if exclude_exit_ids.contains(e.exit.exit_id.as_bytes()) {
            continue;
        }
        for (j, x) in dir.nodes.iter().enumerate() {
            if i == j {
                continue;
            }
            if !country_matches(exit_country, &x.country) {
                continue;
            }
            // ADR 36: skip an exit that signalled a maintenance drain so a
            // drain-triggered reconnect lands on a different exit.
            if exclude_exit_ids.contains(x.exit.exit_id.as_bytes()) {
                continue;
            }
            if circuit_permitted(
                policy.as_diversity_required,
                &e.country,
                e.asn,
                &x.country,
                x.asn,
                e.relay.relay_id != x.relay.relay_id,
            ) {
                pairs.push((i, j));
            }
        }
    }
    pairs
}

impl VerifiedMultiHopDirectory {
    /// The trusted nodes projected as entry hops.
    #[must_use]
    pub fn entries(&self) -> Vec<VerifiedEntry> {
        self.nodes
            .iter()
            .map(|n| VerifiedEntry {
                relay_ed25519_pubkey: n.relay.relay_ed25519_pubkey,
                endpoint: n.relay.endpoint,
                country: n.country.clone(),
                asn: n.asn,
                city: n.city.clone(),
                weight: n.weight,
                cover_domain: n.relay.cover_domain.clone(),
                tcp_fallback: n.relay.tcp_fallback,
                edge_cert_sha256: n.edge_cert_sha256.clone(),
                exit_id: *n.exit.exit_id.as_bytes(),
            })
            .collect()
    }

    /// The trusted exits as a flat client dial view.
    #[must_use]
    pub fn exits(&self) -> Vec<VerifiedExit> {
        self.nodes
            .iter()
            .map(|n| VerifiedExit {
                exit_id: *n.exit.exit_id.as_bytes(),
                exit_ed25519_pubkey: n.exit.exit_ed25519_pubkey,
                exit_x25519_multihop_pubkey: n.exit.exit_x25519_multihop_pubkey,
                endpoint: n.relay.endpoint,
                country: n.country.clone(),
                asn: n.asn,
                city: n.city.clone(),
                weight: n.weight,
                dns_disabled: n.exit.dns_disabled,
                cover_domain: n.relay.cover_domain.clone(),
                tcp_fallback: n.relay.tcp_fallback,
                edge_cert_sha256: n.edge_cert_sha256.clone(),
                // Re-checked at the surfacing point so the anti-downgrade
                // invariant holds locally, independent of the vouching policy.
                exit_mlkem768_pubkey: verify_exit_descriptor_pq(&self.operational_pubkey, &n.exit)
                    .is_ok()
                    .then(|| n.exit.exit_mlkem768_pubkey.clone())
                    .flatten(),
            })
            .collect()
    }
}

/// Directory-minting fixtures for other crates' tests (the SDK facade), gated
/// behind the `test-helpers` feature so they never enter production builds.
#[cfg(feature = "test-helpers")]
pub mod test_helpers {
    use ed25519_dalek::{Signer, SigningKey};
    use warrenguard_multihop::{
        ExitId, exit_descriptor_signing_payload, relay_descriptor_signing_payload,
        sign_node_attestation, sign_operational_cert,
    };

    use super::{ExitDescriptorSigned, NodeEntry, RelayDescriptorSigned, sign_multihop_directory};

    fn vouched_node(op: &SigningKey, tag: u8, country: &str, asn: u32) -> NodeEntry {
        let endpoint: std::net::SocketAddr = format!("198.51.100.{tag}:443").parse().unwrap();
        let relay_id = [tag; 16];
        let relay_ed = [tag.wrapping_add(1); 32];
        let relay_sig = op
            .sign(&relay_descriptor_signing_payload(&relay_id, &relay_ed))
            .to_bytes();
        let relay = RelayDescriptorSigned {
            relay_id,
            relay_ed25519_pubkey: relay_ed,
            endpoint,
            cover_domain: None,
            tcp_fallback: false,
            signature: relay_sig,
        };
        let exit_id = ExitId::from_bytes([tag; 16]);
        let exit_x = [tag.wrapping_add(2); 32];
        let exit_sig = op
            .sign(&exit_descriptor_signing_payload(exit_id, &exit_x))
            .to_bytes();
        let exit = ExitDescriptorSigned {
            exit_id,
            exit_ed25519_pubkey: relay_ed,
            exit_x25519_multihop_pubkey: exit_x,
            endpoint: Some(endpoint),
            cover_domain: None,
            signature: exit_sig,
            dns_disabled: false,
            exit_mlkem768_pubkey: None,
        };
        let attestation = sign_node_attestation(op, &relay_id, &relay_ed, asn, country);
        NodeEntry {
            relay,
            exit,
            country: country.to_owned(),
            city: "City".to_owned(),
            asn,
            weight: 100,
            attestation_hex: hex::encode(attestation),
            edge_cert_sha256: None,
        }
    }

    /// Mints a signed multi-hop directory JSON with two fully-vouched exits.
    #[must_use]
    pub fn mint_directory_json(
        root: &SigningKey,
        op: &SigningKey,
        server: &SigningKey,
        generation: u64,
        signed_at: u64,
        expires_at: u64,
    ) -> String {
        let nodes = vec![
            vouched_node(op, 10, "RO", 100),
            vouched_node(op, 20, "NL", 200),
        ];
        let cert = sign_operational_cert(root, &op.verifying_key());
        let signed = sign_multihop_directory(
            nodes,
            server,
            &op.verifying_key(),
            &cert,
            generation,
            signed_at,
            expires_at,
        )
        .expect("fixture nodes never carry a malformed edge-cert pin");
        serde_json::to_string(&signed).expect("serialize minted directory")
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use ed25519_dalek::{Signer, SigningKey};
    use warrenguard_multihop::{
        ExitId, MLKEM768_ENCAPS_KEY_LEN, exit_descriptor_signing_payload,
        exit_descriptor_signing_payload_pq, relay_descriptor_signing_payload,
    };

    use super::*;

    #[test]
    fn lossless_roundtrip_accepts_a_modeled_draft_and_rejects_a_dropped_field() {
        let draft = MultiHopDirectoryDraft {
            nodes: vec![],
            operational_pubkey_hex: "00".repeat(32),
            operational_cert_hex: "00".repeat(64),
            generation: 7,
        };
        let raw = serde_json::to_vec(&draft).expect("serialize draft");
        ensure_lossless_roundtrip(&raw).expect("a draft this build fully models must round-trip");

        // Simulate a publisher that emitted a field this (older) build does not
        // model - exactly how the additive `cover_domain` looked to warren-api
        // v0.6.1, which silently dropped it. The round-trip is now lossy and
        // MUST be rejected rather than stored + served field-stripped.
        let mut value = serde_json::to_value(&draft).expect("draft to value");
        value
            .as_object_mut()
            .expect("draft is a JSON object")
            .insert("future_additive_field".to_owned(), serde_json::json!("x"));
        let raw_with_unknown = serde_json::to_vec(&value).expect("serialize tampered draft");
        assert!(
            matches!(
                ensure_lossless_roundtrip(&raw_with_unknown),
                Err(DirectoryError::LossyRoundtrip)
            ),
            "a dropped field must be rejected loudly, not stripped silently",
        );
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Mints a NodeEntry whose relay + exit descriptors are signed by
    /// `op`. `tag` disambiguates node identity across the fleet.
    fn signed_node(op: &SigningKey, tag: u8, country: &str, asn: u32) -> NodeEntry {
        let endpoint: SocketAddr = format!("198.51.100.{tag}:443").parse().unwrap();
        let relay_id = [tag; 16];
        let relay_ed = [tag.wrapping_add(1); 32];
        let relay_sig = op
            .sign(&relay_descriptor_signing_payload(&relay_id, &relay_ed))
            .to_bytes();
        let relay = RelayDescriptorSigned {
            relay_id,
            relay_ed25519_pubkey: relay_ed,
            endpoint,
            cover_domain: None,
            tcp_fallback: false,
            signature: relay_sig,
        };

        let exit_id = ExitId::from_bytes([tag; 16]);
        let exit_x = [tag.wrapping_add(2); 32];
        let exit_sig = op
            .sign(&exit_descriptor_signing_payload(exit_id, &exit_x))
            .to_bytes();
        let exit = ExitDescriptorSigned {
            exit_id,
            exit_ed25519_pubkey: relay_ed,
            exit_x25519_multihop_pubkey: exit_x,
            endpoint: Some(endpoint),
            cover_domain: None,
            signature: exit_sig,
            dns_disabled: false,
            exit_mlkem768_pubkey: None,
        };

        let attestation =
            warrenguard_multihop::sign_node_attestation(op, &relay_id, &relay_ed, asn, country);

        NodeEntry {
            relay,
            exit,
            country: country.to_owned(),
            city: "City".to_owned(),
            asn,
            weight: 100,
            attestation_hex: hex::encode(attestation),
            edge_cert_sha256: None,
        }
    }

    fn dummy_mlkem_ek() -> Vec<u8> {
        (0..MLKEM768_ENCAPS_KEY_LEN)
            .map(|i| (i % 251) as u8)
            .collect()
    }

    /// Re-signs `signed_node`'s exit descriptor under the PQ context, binding
    /// the ML-KEM key and the dns bit under the operational signature.
    fn pq_signed_node(
        op: &SigningKey,
        tag: u8,
        country: &str,
        asn: u32,
        dns_disabled: bool,
    ) -> NodeEntry {
        let mut node = signed_node(op, tag, country, asn);
        let ek = dummy_mlkem_ek();
        node.exit.dns_disabled = dns_disabled;
        node.exit.exit_mlkem768_pubkey = Some(ek.clone());
        node.exit.signature = op
            .sign(&exit_descriptor_signing_payload_pq(
                node.exit.exit_id,
                &node.exit.exit_x25519_multihop_pubkey,
                dns_disabled,
                &ek,
            ))
            .to_bytes();
        node
    }

    fn build(
        root: &SigningKey,
        op: &SigningKey,
        server: &SigningKey,
        nodes: Vec<NodeEntry>,
    ) -> SignedMultiHopDirectory {
        let cert = warrenguard_multihop::sign_operational_cert(root, &op.verifying_key());
        sign_multihop_directory(
            nodes,
            server,
            &op.verifying_key(),
            &cert,
            7,
            1_000,
            1_000 + 21_600,
        )
        .expect("test nodes never carry a malformed edge-cert pin")
    }

    fn hexk(k: &SigningKey) -> String {
        hex::encode(k.verifying_key().as_bytes())
    }

    #[test]
    fn happy_path_verifies_full_chain() {
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let nodes = vec![
            signed_node(&op, 1, "fr", 24940),
            signed_node(&op, 2, "de", 16276),
        ];
        let signed = build(&root, &op, &server, nodes);
        let json = serde_json::to_string(&signed).unwrap();

        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("full chain must verify");
        assert_eq!(v.nodes.len(), 2);
        assert_eq!(v.dropped, 0);
        assert_eq!(v.generation, 7);
        assert_eq!(v.operational_pubkey, op.verifying_key());
        assert!(!v.is_expired(1_500));
        assert!(v.is_expired(1_000 + 21_600));
    }

    #[test]
    fn pq_signed_descriptor_is_vouched_alongside_classical() {
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let nodes = vec![
            pq_signed_node(&op, 1, "fr", 1, false),
            signed_node(&op, 2, "de", 2),
        ];
        let signed = build(&root, &op, &server, nodes);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("a directory mixing PQ and classical descriptors verifies");
        assert_eq!(
            v.nodes.len(),
            2,
            "the PQ-signed node must be vouched alongside the classical one"
        );
        assert_eq!(v.dropped, 0);
    }

    #[test]
    fn pq_signed_descriptor_with_attested_dns_disabled_is_kept() {
        // The PQ payload covers the dns bit, so unlike the unattested `/v1`
        // case a PQ-signed `dns_disabled = true` is trustworthy, not a
        // downgrade suspect.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let signed = build(
            &root,
            &op,
            &server,
            vec![pq_signed_node(&op, 1, "fr", 1, true)],
        );
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("verify");
        assert_eq!(v.nodes.len(), 1);
        assert!(v.exits()[0].dns_disabled, "the attested bit flows through");
    }

    #[test]
    fn pq_descriptor_with_wrong_length_mlkem_key_is_dropped() {
        // Honestly signed over a 100-byte key: the length gate must reject it
        // before any signature question, and no classical context can rescue a
        // PQ-context signature.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let mut node = signed_node(&op, 1, "fr", 1);
        let short_ek = vec![0xAB; 100];
        node.exit.exit_mlkem768_pubkey = Some(short_ek.clone());
        node.exit.signature = op
            .sign(&exit_descriptor_signing_payload_pq(
                node.exit.exit_id,
                &node.exit.exit_x25519_multihop_pubkey,
                false,
                &short_ek,
            ))
            .to_bytes();
        let signed = build(&root, &op, &server, vec![node]);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("envelope verifies; the malformed node is dropped");
        assert_eq!(v.nodes.len(), 0);
        assert_eq!(v.dropped, 1);
    }

    #[test]
    fn pq_descriptor_with_tampered_mlkem_key_is_dropped() {
        // Flipped before the envelope is minted, so the envelope verifies and
        // the drop is provably the descriptor signature check.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let mut node = pq_signed_node(&op, 1, "fr", 1, false);
        node.exit
            .exit_mlkem768_pubkey
            .as_mut()
            .expect("pq node carries a key")[0] ^= 0x01;
        let signed = build(&root, &op, &server, vec![node]);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("envelope verifies; the tampered node is dropped");
        assert_eq!(v.nodes.len(), 0);
        assert_eq!(v.dropped, 1);
    }

    #[test]
    fn pq_descriptor_with_stripped_mlkem_key_is_dropped() {
        // Stripping the key from a PQ-signed descriptor invalidates every
        // context (the PQ signature never verifies as `/v1` or `/v2`), so the
        // downgrade is refused rather than silently going classical.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let mut node = pq_signed_node(&op, 1, "fr", 1, false);
        node.exit.exit_mlkem768_pubkey = None;
        let signed = build(&root, &op, &server, vec![node]);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("envelope verifies; the stripped node is dropped");
        assert_eq!(v.nodes.len(), 0);
        assert_eq!(v.dropped, 1);
    }

    #[test]
    fn exits_surface_the_mlkem_key_only_when_pq_attested() {
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let signed = build(
            &root,
            &op,
            &server,
            vec![
                pq_signed_node(&op, 1, "fr", 1, false),
                signed_node(&op, 2, "de", 2),
            ],
        );
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("verify");
        let exits = v.exits();
        let pq = exits.iter().find(|e| e.country == "fr").expect("pq exit");
        let classical = exits
            .iter()
            .find(|e| e.country == "de")
            .expect("classical exit");
        assert_eq!(
            pq.exit_mlkem768_pubkey.as_deref(),
            Some(dummy_mlkem_ek().as_slice()),
            "the PQ-attested key reaches the dial view"
        );
        assert!(classical.exit_mlkem768_pubkey.is_none());
    }

    #[test]
    fn unbound_mlkem_key_on_a_classical_descriptor_is_never_surfaced() {
        // Anti-downgrade invariant: only the PQ signature vouches the key. A
        // classical `/v1` descriptor with a key merely attached (outside its
        // signature) still verifies classically, so the node is kept, but the
        // unbound key must never surface as usable PQ material.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let mut node = signed_node(&op, 1, "fr", 1);
        node.exit.exit_mlkem768_pubkey = Some(dummy_mlkem_ek());
        let signed = build(&root, &op, &server, vec![node]);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("verify");
        assert_eq!(
            v.nodes.len(),
            1,
            "the node itself stays classically vouched"
        );
        assert!(v.exits()[0].exit_mlkem768_pubkey.is_none());
    }

    #[test]
    fn via_entry_keeps_the_exit_mlkem_key() {
        // The circuit view hands the dial layer the ENTRY's transport identity
        // but the EXIT's sealed-frame material; the ML-KEM key is seal
        // material and must survive the projection.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let signed = build(
            &root,
            &op,
            &server,
            vec![
                pq_signed_node(&op, 1, "fr", 1, false),
                signed_node(&op, 2, "de", 2),
            ],
        );
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("verify");
        let exits = v.exits();
        let exit = exits.iter().find(|e| e.country == "fr").expect("fr exit");
        let entries = v.entries();
        let entry = entries
            .iter()
            .find(|e| e.country == "de")
            .expect("de entry");
        let policy = CircuitPolicy::for_directory(&v);
        let dialed = exit
            .via_entry(entry, &policy)
            .expect("distinct nodes form a circuit");
        assert_eq!(
            dialed.exit_mlkem768_pubkey.as_deref(),
            Some(dummy_mlkem_ek().as_slice())
        );
    }

    #[test]
    fn wrong_server_pin_is_rejected() {
        let (root, op, server, attacker) = (key(0x01), key(0x02), key(0x03), key(0x09));
        let signed = build(&root, &op, &server, vec![signed_node(&op, 1, "fr", 1)]);
        let json = serde_json::to_string(&signed).unwrap();
        let err = verify_multihop_directory_any(&json, &[&hexk(&attacker)], &[&hexk(&root)])
            .expect_err("wrong server pin must reject");
        assert!(matches!(err, DirectoryError::ServerPubkeyMismatch { .. }));
    }

    #[test]
    fn server_pubkey_mismatch_error_redacts_both_keys() {
        let (root, op, server, attacker) = (key(0x01), key(0x02), key(0x03), key(0x09));
        let signed = build(&root, &op, &server, vec![signed_node(&op, 1, "fr", 1)]);
        let json = serde_json::to_string(&signed).unwrap();
        let announced = hexk(&server);
        let pinned = hexk(&attacker);

        let msg = verify_multihop_directory_any(&json, &[&pinned], &[&hexk(&root)])
            .expect_err("wrong server pin must reject")
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
    fn tampered_envelope_is_rejected() {
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let mut signed = build(&root, &op, &server, vec![signed_node(&op, 1, "fr", 1)]);
        // Mutate a signed field without re-signing → envelope must fail.
        signed.generation = 999;
        let json = serde_json::to_string(&signed).unwrap();
        let err = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect_err("tampered envelope must reject");
        assert!(matches!(err, DirectoryError::BadEnvelopeSignature));
    }

    #[test]
    fn wrong_root_pin_is_rejected() {
        let (root, op, server, attacker_root) = (key(0x01), key(0x02), key(0x03), key(0x0a));
        let signed = build(&root, &op, &server, vec![signed_node(&op, 1, "fr", 1)]);
        let json = serde_json::to_string(&signed).unwrap();
        // The operational cert was minted by `root`; pinning a different
        // root must reject - a compromised server cannot present an
        // operational key the trusted root never certified.
        let err = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&attacker_root)])
            .expect_err("wrong root pin must reject");
        assert!(matches!(err, DirectoryError::BadOperationalCert));
    }

    #[test]
    fn node_with_descriptor_signed_by_other_key_is_dropped() {
        let (root, op, server, rogue) = (key(0x01), key(0x02), key(0x03), key(0x0b));
        // Node minted by a rogue operational key: envelope still signs it
        // (server included it), but per-node verify under the real
        // operational key fails → dropped, not trusted.
        let good = signed_node(&op, 1, "fr", 1);
        let bad = signed_node(&rogue, 2, "de", 2);
        let signed = build(&root, &op, &server, vec![good, bad]);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("verify succeeds, rogue node dropped");
        assert_eq!(v.nodes.len(), 1, "only the operational-vouched node kept");
        assert_eq!(v.dropped, 1);
        assert_eq!(v.nodes[0].country, "fr");
    }

    #[test]
    fn node_with_relabeled_geo_is_dropped() {
        // /v2 hardening: the server envelope can carry any country
        // label, but the operational attestation binds the true one. A
        // node whose `country` was relabeled (envelope re-signs it, but
        // the attestation still attests the original) must be dropped.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let mut relabeled = signed_node(&op, 1, "fr", 0);
        relabeled.country = "de".to_owned();
        let honest = signed_node(&op, 2, "se", 0);
        let signed = build(&root, &op, &server, vec![relabeled, honest]);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("envelope verifies; relabeled node dropped on attestation");
        assert_eq!(v.nodes.len(), 1, "only the honestly-attested node is kept");
        assert_eq!(v.dropped, 1);
        assert_eq!(v.nodes[0].country, "se");
    }

    #[test]
    fn unattested_exit_claiming_dns_disabled_is_dropped() {
        // Engine-spec client policy (anti-downgrade): a `/v1`-only-signed exit
        // (dns_disabled unattested) that advertises `dns_disabled = true` could
        // silently disable in-tunnel DNS. It must be dropped. The `/v1` exit
        // signature does not cover the dns bit, so flipping it keeps the
        // signature valid but leaves the bit unattested.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let honest = signed_node(&op, 1, "fr", 1);
        let mut downgrade = signed_node(&op, 2, "de", 2);
        downgrade.exit.dns_disabled = true;
        let signed = build(&root, &op, &server, vec![honest, downgrade]);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("verify succeeds, downgrade-suspect exit dropped");
        assert_eq!(v.nodes.len(), 1, "only the honest DNS-enabled node kept");
        assert_eq!(v.dropped, 1);
        assert_eq!(v.nodes[0].country, "fr");
    }

    #[test]
    fn exits_projection_flattens_verified_nodes() {
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let signed = build(&root, &op, &server, vec![signed_node(&op, 7, "fr", 1)]);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)]).unwrap();
        let exits = v.exits();
        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].country, "fr");
        assert_eq!(exits[0].exit_id, [7u8; 16]);
        assert!(!exits[0].dns_disabled);
    }

    #[test]
    fn tofu_root_accepts_when_no_pin() {
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let signed = build(&root, &op, &server, vec![signed_node(&op, 1, "fr", 1)]);
        let json = serde_json::to_string(&signed).unwrap();
        // Empty root-pin set = TOFU (dev/bench): the carried operational
        // key is trusted as-is, descriptors still verify under it.
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[])
            .expect("TOFU root accepts");
        assert_eq!(v.nodes.len(), 1);
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let mut signed = build(&root, &op, &server, vec![signed_node(&op, 1, "fr", 1)]);
        signed.version = 99;
        let json = serde_json::to_string(&signed).unwrap();
        let err = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect_err("bad version must reject");
        assert!(matches!(
            err,
            DirectoryError::UnsupportedVersion { got: 99 }
        ));
    }

    fn draft(root: &SigningKey, op: &SigningKey, nodes: Vec<NodeEntry>) -> MultiHopDirectoryDraft {
        let cert = warrenguard_multihop::sign_operational_cert(root, &op.verifying_key());
        MultiHopDirectoryDraft {
            nodes,
            operational_pubkey_hex: hex::encode(op.verifying_key().as_bytes()),
            operational_cert_hex: hex::encode(cert),
            generation: 9,
        }
    }

    #[test]
    fn draft_self_consistency_accepts_vouched_nodes() {
        let (root, op) = (key(0x01), key(0x02));
        let d = draft(&root, &op, vec![signed_node(&op, 1, "fr", 1)]);
        d.validate_self_consistent()
            .expect("vouched draft must validate");
    }

    #[test]
    fn draft_self_consistency_rejects_rogue_node() {
        let (root, op, rogue) = (key(0x01), key(0x02), key(0x0b));
        // A node whose descriptors were signed by a different key than the
        // draft's declared operational key must be refused at POST time.
        let d = draft(&root, &op, vec![signed_node(&rogue, 1, "fr", 1)]);
        let err = d
            .validate_self_consistent()
            .expect_err("rogue node draft must reject");
        assert!(matches!(err, DirectoryError::NodeNotVouched));
    }

    #[test]
    fn redacted_client_directory_hides_exit_endpoint_and_still_verifies() {
        // The client-facing directory is signed over nodes whose
        // exit egress IP is redacted. It must verify end to end (the
        // endpoint is outside the operational signature, and the server
        // envelope is computed over the redacted nodes), expose the entry
        // relay endpoint (the client dials it), and carry NO exit endpoint.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let d = draft(&root, &op, vec![signed_node(&op, 1, "fr", 24940)]);
        let redacted = redact_exit_endpoints(&d.nodes);
        assert!(
            redacted[0].exit.endpoint.is_none(),
            "exit endpoint must be redacted"
        );
        assert!(
            redacted[0]
                .relay
                .endpoint
                .to_string()
                .starts_with("198.51.100."),
            "entry relay endpoint stays (the client dials it)"
        );

        let cert = warrenguard_multihop::sign_operational_cert(&root, &op.verifying_key());
        let signed = sign_multihop_directory(
            redacted,
            &server,
            &op.verifying_key(),
            &cert,
            9,
            2_000,
            2_000 + 21_600,
        )
        .expect("test nodes never carry a malformed edge-cert pin");
        let json = serde_json::to_string(&signed).unwrap();
        // In a dual-role node the exit endpoint equals the relay endpoint;
        // after redaction the address appears exactly once (the relay's),
        // never as a second, exit-side occurrence.
        assert_eq!(
            json.matches("198.51.100.1:443").count(),
            1,
            "redaction leaves only the entry-relay endpoint on the client wire"
        );

        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("redacted client directory must verify end to end");
        assert_eq!(v.nodes.len(), 1);
        assert!(
            v.nodes[0].exit.endpoint.is_none(),
            "verified client node carries no exit endpoint"
        );
    }

    #[test]
    fn server_wraps_draft_into_verifiable_directory() {
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let d = draft(&root, &op, vec![signed_node(&op, 1, "fr", 1)]);
        // warren-api wraps the offline draft with its online server key.
        let signed =
            sign_directory_draft(&d, &server, 2_000, 2_000 + 21_600).expect("wrap must succeed");
        let json = serde_json::to_string(&signed).unwrap();
        // The wrapped directory verifies end-to-end under the pinned root.
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("wrapped directory must verify");
        assert_eq!(v.generation, 9);
        assert_eq!(v.nodes.len(), 1);
    }

    #[test]
    fn single_pin_convenience_matches_the_any_variant() {
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let signed = build(&root, &op, &server, vec![signed_node(&op, 1, "fr", 1)]);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory(&json, Some(&hexk(&server)), Some(&hexk(&root)))
            .expect("single-pin convenience must verify like verify_multihop_directory_any");
        assert_eq!(v.nodes.len(), 1);
        assert!(
            verify_multihop_directory(&json, None, None).is_ok(),
            "TOFU on both pins"
        );
    }

    #[test]
    fn verify_accepts_server_and_root_pins_differing_only_in_hex_case() {
        // Mirrors release.rs's `eq_ignore_ascii_case` pin policy: legitimate
        // server/root pins written in a different hex case must not be
        // wrongly rejected.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let signed = build(&root, &op, &server, vec![signed_node(&op, 1, "fr", 1)]);
        let json = serde_json::to_string(&signed).unwrap();
        let upper_server = hexk(&server).to_ascii_uppercase();
        let upper_root = hexk(&root).to_ascii_uppercase();
        verify_multihop_directory_any(&json, &[&upper_server], &[&upper_root])
            .expect("pins differing only in hex case must still be accepted");
    }

    #[test]
    fn verify_rejects_oversize_input() {
        let oversize = "0".repeat(envelope::MAX_VERIFY_INPUT_LEN + 1);
        let err =
            verify_multihop_directory_any(&oversize, &[], &[]).expect_err("oversize must reject");
        assert!(matches!(err, DirectoryError::InputTooLarge));
    }

    #[test]
    fn circuit_dials_a_distinct_entry_and_refuses_the_same_node() {
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let signed = build(
            &root,
            &op,
            &server,
            vec![signed_node(&op, 1, "fr", 1), signed_node(&op, 2, "de", 2)],
        );
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("verify");

        let exits = v.exits();
        let exit = exits.iter().find(|e| e.country == "fr").expect("fr exit");
        let entries = v.entries();
        let de_entry = entries
            .iter()
            .find(|e| e.country == "de")
            .expect("de entry");

        let policy = CircuitPolicy::for_directory(&v);
        let dialed = exit
            .via_entry(de_entry, &policy)
            .expect("two distinct nodes form a circuit");
        // The dial target, SNI and the DIALED-HOP identity come from the entry;
        // only what the sealed frame needs (HPKE key, routing id) stays the
        // exit's. The ed25519 is the RPK / relay-auth identity of the hop we
        // actually dial (the entry), NOT the exit: keeping the exit's ed25519
        // makes the entry relay reject the circuit with a relay-auth signature
        // mismatch.
        assert_eq!(dialed.endpoint, de_entry.endpoint);
        assert_eq!(dialed.cover_domain, de_entry.cover_domain);
        assert_eq!(dialed.exit_id, exit.exit_id);
        assert_eq!(
            dialed.exit_ed25519_pubkey, de_entry.relay_ed25519_pubkey,
            "dialed-hop identity must be the entry relay's, not the exit's"
        );
        assert_ne!(
            dialed.exit_ed25519_pubkey, exit.exit_ed25519_pubkey,
            "distinct nodes have distinct dialed identities"
        );
        assert_eq!(
            dialed.exit_x25519_multihop_pubkey,
            exit.exit_x25519_multihop_pubkey
        );
        assert_eq!(dialed.country, exit.country, "display stays the exit's");

        let fr_entry = entries
            .iter()
            .find(|e| e.country == "fr")
            .expect("fr entry");
        assert!(
            exit.via_entry(fr_entry, &policy).is_none(),
            "entry == exit node must be refused (unlinkability rule)"
        );
    }

    #[test]
    fn entries_expose_the_relay_view_of_every_vouched_node() {
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let signed = build(
            &root,
            &op,
            &server,
            vec![signed_node(&op, 1, "fr", 1), signed_node(&op, 2, "de", 2)],
        );
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("verify");

        let entries = v.entries();
        assert_eq!(entries.len(), 2);
        let de = entries.iter().find(|e| e.country == "de").expect("de");
        let de_node = v.nodes.iter().find(|n| n.country == "de").expect("node");
        assert_eq!(de.endpoint, de_node.relay.endpoint);
        assert_eq!(de.relay_ed25519_pubkey, de_node.relay.relay_ed25519_pubkey);
        assert_eq!(de.exit_id, *de_node.exit.exit_id.as_bytes());
        assert_eq!(de.weight, de_node.weight);
    }

    #[test]
    fn edge_cert_absent_keeps_the_edge_key_off_the_wire() {
        // An edge-less directory must serialize with NO `edge_cert_sha256` key,
        // so the additive field never forces a directory-version rotation:
        // existing v2 clients see the same shape they always did and keep
        // verifying.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let signed = build(&root, &op, &server, vec![signed_node(&op, 1, "fr", 1)]);
        let json = serde_json::to_string(&signed).unwrap();
        assert!(
            !json.contains("edge_cert_sha256"),
            "absent edge cert must not appear on the wire: {json}"
        );
        verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("edge-less directory still verifies");
    }

    #[test]
    fn edge_cert_is_server_signed_and_flows_to_the_verified_views() {
        // Set before signing: the pin rides the server envelope and must survive
        // verification, surfacing on both the exit and entry projections.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let pin = "ab".repeat(32);
        let mut node = signed_node(&op, 1, "fr", 1);
        node.edge_cert_sha256 = Some(pin.clone());
        let signed = build(&root, &op, &server, vec![node]);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("directory with an edge pin verifies");
        assert_eq!(v.exits()[0].edge_cert_sha256.as_deref(), Some(pin.as_str()));
        assert_eq!(
            v.entries()[0].edge_cert_sha256.as_deref(),
            Some(pin.as_str())
        );
    }

    #[test]
    fn malformed_edge_cert_pin_is_rejected_by_verify() {
        // A 63-char pin (one hex char short of the SHA-256 length) must be
        // rejected, mirroring the TS verifier's `asFixedHex` length check.
        // Minted via the unchecked sign helper so the envelope is
        // authentically signed over the bad pin: this proves
        // `verify_multihop_directory_any` itself fails closed, not merely
        // that `sign_multihop_directory` refuses to produce one.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let mut node = signed_node(&op, 1, "fr", 1);
        node.edge_cert_sha256 = Some("a".repeat(63));
        let cert = warrenguard_multihop::sign_operational_cert(&root, &op.verifying_key());
        let signed = sign_multihop_directory_unchecked(
            vec![node],
            &server,
            &op.verifying_key(),
            &cert,
            7,
            1_000,
            1_000 + 21_600,
        );
        let json = serde_json::to_string(&signed).unwrap();
        let err = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect_err("a 63-char edge cert pin must be rejected");
        assert!(matches!(err, DirectoryError::MalformedEdgeCertPin { .. }));
    }

    #[test]
    fn sign_multihop_directory_refuses_a_malformed_edge_cert_pin() {
        // Defense in depth: the shared signing entry point must never mint a
        // directory that `verify_multihop_directory_any` (or the TS sibling)
        // would reject, even if a malformed pin reached it from upstream.
        let (op, server) = (key(0x02), key(0x03));
        let mut node = signed_node(&op, 1, "fr", 1);
        node.edge_cert_sha256 = Some("not-hex-and-too-short".to_owned());
        let cert = [0u8; 64];
        let err = sign_multihop_directory(
            vec![node],
            &server,
            &op.verifying_key(),
            &cert,
            7,
            1_000,
            1_000 + 21_600,
        )
        .expect_err("a malformed pin must be refused at sign time");
        assert!(matches!(err, DirectoryError::MalformedEdgeCertPin { .. }));
    }

    #[test]
    fn tampering_the_edge_cert_pin_breaks_the_server_envelope() {
        // Proves the pin is INSIDE the server signature, not a bare transported
        // field: swapping it after signing must fail the envelope. This is why
        // the canonical (signed) tier beats a non-canonical field: a compromised
        // serve host cannot silently substitute the browser cert pin.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let mut node = signed_node(&op, 1, "fr", 1);
        node.edge_cert_sha256 = Some("ab".repeat(32));
        let mut signed = build(&root, &op, &server, vec![node]);
        signed.nodes[0].edge_cert_sha256 = Some("cd".repeat(32));
        let json = serde_json::to_string(&signed).unwrap();
        let err = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect_err("a swapped edge pin must fail the server envelope");
        assert!(matches!(err, DirectoryError::BadEnvelopeSignature));
    }

    #[test]
    fn via_entry_pins_the_dialed_entry_edge_cert() {
        // The browser connects to the ENTRY's WebTransport, so the circuit view
        // must carry the ENTRY's edge cert, not the exit node's own.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let mut exit_node = signed_node(&op, 1, "fr", 1);
        exit_node.edge_cert_sha256 = Some("11".repeat(32));
        let mut entry_node = signed_node(&op, 2, "de", 2);
        entry_node.edge_cert_sha256 = Some("22".repeat(32));
        let signed = build(&root, &op, &server, vec![exit_node, entry_node]);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("verify");
        let exit = v.exits().into_iter().find(|e| e.country == "fr").unwrap();
        let entry = v.entries().into_iter().find(|e| e.country == "de").unwrap();
        let policy = CircuitPolicy::for_directory(&v);
        let dialed = exit
            .via_entry(&entry, &policy)
            .expect("two distinct nodes form a circuit");
        assert_eq!(
            dialed.edge_cert_sha256,
            Some("22".repeat(32)),
            "circuit pins the entry's edge cert (the dialed WebTransport)"
        );
    }

    #[test]
    fn exits_and_entries_project_the_relay_carrier_capability() {
        // roster v10: the dialed hop's `tcp_fallback` flag must survive the flat
        // projection so the transport can arm the UDP->TCP carrier race. The flag
        // rides the relay descriptor unsigned (the multi-hop signing payload is
        // only relay_id + relay_ed), so setting it after `signed_node` is faithful
        // to how warren-api overlays it on the additive wire.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let mut carrier = signed_node(&op, 1, "fr", 1);
        carrier.relay.tcp_fallback = true;
        let plain = signed_node(&op, 2, "de", 2);
        let signed = build(&root, &op, &server, vec![carrier, plain]);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("verify");

        let exit_on = v.exits().into_iter().find(|e| e.country == "fr").unwrap();
        let exit_off = v.exits().into_iter().find(|e| e.country == "de").unwrap();
        assert!(
            exit_on.tcp_fallback,
            "an advertised carrier must reach the exit dial view"
        );
        assert!(
            !exit_off.tcp_fallback,
            "a node without the carrier must project as unarmed"
        );

        let entry_on = v.entries().into_iter().find(|e| e.country == "fr").unwrap();
        let entry_off = v.entries().into_iter().find(|e| e.country == "de").unwrap();
        assert!(
            entry_on.tcp_fallback,
            "an advertised carrier must reach the entry dial view"
        );
        assert!(
            !entry_off.tcp_fallback,
            "a node without the carrier must project as unarmed"
        );
    }

    #[test]
    fn via_entry_takes_the_entry_carrier_capability_not_the_exit() {
        // The carrier terminates at the hop the client dials (the ENTRY), so the
        // circuit view must carry the entry's flag, never the exit node's own.
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let mut exit_node = signed_node(&op, 1, "fr", 1);
        exit_node.relay.tcp_fallback = true; // exit's own relay advertises it
        let mut entry_node = signed_node(&op, 2, "de", 2);
        entry_node.relay.tcp_fallback = false; // the dialed entry does not
        let signed = build(&root, &op, &server, vec![exit_node, entry_node]);
        let json = serde_json::to_string(&signed).unwrap();
        let v = verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)])
            .expect("verify");
        let exit = v.exits().into_iter().find(|e| e.country == "fr").unwrap();
        let entry = v.entries().into_iter().find(|e| e.country == "de").unwrap();
        let policy = CircuitPolicy::for_directory(&v);
        let dialed = exit
            .via_entry(&entry, &policy)
            .expect("two distinct nodes form a circuit");
        assert!(
            !dialed.tcp_fallback,
            "the circuit must take the entry's carrier flag, not the exit's"
        );
    }

    /// Verifies a directory of `(country, asn)` nodes so the policy fixtures
    /// below exercise the real projection, not hand-built structs.
    fn verified_dir(nodes: &[(&str, u32)]) -> VerifiedMultiHopDirectory {
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let nodes = nodes
            .iter()
            .enumerate()
            .map(|(i, (country, asn))| signed_node(&op, (i + 1) as u8, country, *asn))
            .collect();
        let signed = build(&root, &op, &server, nodes);
        let json = serde_json::to_string(&signed).unwrap();
        verify_multihop_directory_any(&json, &[&hexk(&server)], &[&hexk(&root)]).expect("verify")
    }

    #[test]
    fn policy_rejects_a_same_country_circuit() {
        // Two distinct FR nodes: distinct-node passes but the mandatory country
        // diversity rule must forbid the circuit. This is exactly what the old
        // `via_entry` (distinct-node only) let SDK/TS build.
        let v = verified_dir(&[("fr", 0), ("fr", 0)]);
        let policy = CircuitPolicy::for_directory(&v);
        let exits = v.exits();
        let entries = v.entries();
        assert_ne!(
            entries[1].exit_id, exits[0].exit_id,
            "the two nodes are distinct, so the old distinct-node check alone would have permitted this same-country circuit"
        );
        assert!(
            !policy.permits(&entries[1], &exits[0]),
            "a same-country circuit must be rejected"
        );
        assert!(
            exits[0].via_entry(&entries[1], &policy).is_none(),
            "via_entry must refuse a same-country pair"
        );
        assert!(
            valid_circuits(&v, "", "", &[]).is_empty(),
            "no cross-country pair exists in an all-FR fleet"
        );
    }

    #[test]
    fn policy_rejects_a_same_as_circuit_when_the_fleet_is_multi_as() {
        // FR and DE share AS100; SE is on AS200. With >= 2 ASNs, AS diversity
        // is mandatory, so FR<->DE is forbidden despite different countries.
        let v = verified_dir(&[("fr", 100), ("de", 100), ("se", 200)]);
        let policy = CircuitPolicy::for_directory(&v);
        assert!(
            policy.as_diversity_required(),
            "a 2-ASN fleet mandates AS diversity"
        );
        let exits = v.exits();
        let entries = v.entries();
        let fr = exits.iter().find(|e| e.country == "fr").unwrap();
        let de_entry = entries.iter().find(|e| e.country == "de").unwrap();
        assert!(
            !policy.permits(de_entry, fr),
            "a same-AS circuit must be rejected on a multi-AS fleet"
        );

        let pairs = valid_circuits(&v, "", "", &[]);
        assert!(!pairs.is_empty());
        for (i, j) in &pairs {
            assert_ne!(
                v.nodes[*i].asn, v.nodes[*j].asn,
                "no surviving pair shares an ASN"
            );
            assert_ne!(v.nodes[*i].asn, 0);
            assert_ne!(v.nodes[*j].asn, 0);
        }
        // Only the four ordered pairs that involve the AS200 node survive.
        assert_eq!(pairs.len(), 4);
    }

    #[test]
    fn policy_allows_same_as_on_a_single_as_fleet() {
        // One distinct non-zero ASN across the fleet relaxes the AS clause, so
        // a cross-country circuit sharing that ASN is legal (a homogeneous
        // single-provider deployment must still form circuits).
        let v = verified_dir(&[("fr", 100), ("de", 100)]);
        let policy = CircuitPolicy::for_directory(&v);
        assert!(
            !policy.as_diversity_required(),
            "a single-ASN fleet relaxes AS diversity"
        );
        let exits = v.exits();
        let entries = v.entries();
        let fr = exits.iter().find(|e| e.country == "fr").unwrap();
        let de_entry = entries.iter().find(|e| e.country == "de").unwrap();
        assert!(
            policy.permits(de_entry, fr),
            "same-AS cross-country must be allowed when the fleet has a single ASN"
        );
        assert_eq!(
            valid_circuits(&v, "", "", &[]).len(),
            2,
            "both ordered cross-country pairs are valid"
        );
    }

    #[test]
    fn policy_excludes_a_drained_node_on_both_legs() {
        // ADR 36: a drained exit must never appear as an exit OR an entry.
        let v = verified_dir(&[("fr", 0), ("de", 0), ("se", 0)]);
        let de_exit = *v.nodes[1].exit.exit_id.as_bytes();
        assert!(
            valid_circuits(&v, "", "", &[])
                .iter()
                .any(|&(_, x)| *v.nodes[x].exit.exit_id.as_bytes() == de_exit),
            "DE must be selectable before it drains"
        );
        let pairs = valid_circuits(&v, "", "", &[de_exit]);
        assert!(!pairs.is_empty(), "other nodes remain selectable");
        for (e, x) in &pairs {
            assert_ne!(
                *v.nodes[*x].exit.exit_id.as_bytes(),
                de_exit,
                "drained node never an exit"
            );
            assert_ne!(
                *v.nodes[*e].exit.exit_id.as_bytes(),
                de_exit,
                "drained node never an entry"
            );
        }
    }

    #[test]
    fn policy_requires_distinct_nodes() {
        // A single node cannot form a circuit with itself: via_entry refuses the
        // co-located entry, and valid_circuits never pairs a node with itself.
        let v = verified_dir(&[("fr", 100), ("de", 200)]);
        let policy = CircuitPolicy::for_directory(&v);
        let exit = &v.exits()[0];
        let own_entry = v
            .entries()
            .into_iter()
            .find(|e| e.exit_id == exit.exit_id)
            .unwrap();
        assert!(
            exit.via_entry(&own_entry, &policy).is_none(),
            "a node forwarding to itself breaks unlinkability and must be refused"
        );
        for (i, j) in valid_circuits(&v, "", "", &[]) {
            assert_ne!(i, j, "valid_circuits never pairs a node with itself");
        }
    }

    #[test]
    #[ignore = "generator: prints the cross-impl golden replayed by warren-sdk-ts"]
    fn print_edge_cert_golden_for_ts_crossimpl() {
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let mut node = signed_node(&op, 1, "fr", 24940);
        node.edge_cert_sha256 = Some("ab".repeat(32));
        let signed = build(&root, &op, &server, vec![node]);
        println!(
            "EDGE_GOLDEN_JSON={}",
            serde_json::to_string(&signed).unwrap()
        );
        println!("EDGE_GOLDEN_SERVER={}", hexk(&server));
        println!("EDGE_GOLDEN_ROOT={}", hexk(&root));
    }

    #[test]
    #[ignore = "generator: prints the cross-impl golden replayed by warren-sdk-ts"]
    fn print_pq_descriptor_golden_for_ts_crossimpl() {
        let (root, op, server) = (key(0x01), key(0x02), key(0x03));
        let signed = build(
            &root,
            &op,
            &server,
            vec![pq_signed_node(&op, 1, "fr", 24940, false)],
        );
        println!("PQ_GOLDEN_JSON={}", serde_json::to_string(&signed).unwrap());
        println!("PQ_GOLDEN_SERVER={}", hexk(&server));
        println!("PQ_GOLDEN_ROOT={}", hexk(&root));
    }
}
