//! Signed **multi-hop directory** - the dynamic, secure source of
//! multi-hop nodes a Warren client assembles a circuit from.
//!
//! # Why a directory (and why this trust shape)
//!
//! Single-hop clients fetch `/v1/exits` (server-signed) and cross-check
//! it against an offline-admin-signed roster. Multi-hop needs more: the
//! client must learn, for each node, the **operational-signed** relay and
//! exit descriptors (`warrenguard_multihop::{RelayDescriptorSigned,
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
//! [`UnsignedMultiHopDirectory`]); any mutation = v2 rotation, exactly
//! like the signed relay list.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use warrenguard_multihop::{
    ExitDescAttestation, ExitDescriptorSigned, RelayDescriptorSigned,
    verify_exit_descriptor_with_dns_attestation, verify_node_attestation, verify_operational_cert,
    verify_relay_descriptor,
};

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
    /// canonical bytes ([`UnsignedMultiHopDirectory`]).
    pub signature_hex: String,
}

/// Canonical signing preimage for the server envelope. Field order frozen;
/// any mutation = v2. Mirrors `signed::UnsignedRelayList`.
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
        /// Pubkey hex announced in the JSON.
        got: String,
        /// Comma-joined pinned set.
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
    /// Re-serializing the parsed draft yielded different JSON than the raw
    /// input: this build dropped a field the publisher sent, i.e. the backend
    /// is older than the directory it is being asked to serve. See
    /// [`ensure_lossless_roundtrip`].
    #[error(
        "directory round-trip is lossy: this build dropped a field the publisher sent \
         (warren-api is older than the directory / its warrenguard pin lags the publisher)"
    )]
    LossyRoundtrip,
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
/// [`DirectoryError::Json`] if `raw` is not a valid draft;
/// [`DirectoryError::LossyRoundtrip`] if any field was dropped.
pub fn ensure_lossless_roundtrip(raw: &[u8]) -> Result<(), DirectoryError> {
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
/// # Panics
/// Panics only if `serde_json::to_vec(&UnsignedMultiHopDirectory)` fails,
/// which is infallible for this owned-string/scalar schema.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn sign_multihop_directory(
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
/// See [`DirectoryError`].
///
/// # Panics
/// Panics only if re-serializing the already-deserialized
/// [`UnsignedMultiHopDirectory`] to canonical JSON fails, which is
/// impossible for a value that just round-tripped through `serde_json`
/// (no maps with non-string keys, no non-finite floats).
pub fn verify_multihop_directory_any(
    s: &str,
    expected_server_pubkeys: &[&str],
    expected_root_pubkeys: &[&str],
) -> Result<VerifiedMultiHopDirectory, DirectoryError> {
    let signed: SignedMultiHopDirectory = serde_json::from_str(s)?;
    if signed.version != MULTIHOP_DIRECTORY_VERSION {
        return Err(DirectoryError::UnsupportedVersion {
            got: signed.version,
        });
    }

    // (1) server pubkey pin
    if !expected_server_pubkeys.is_empty()
        && !expected_server_pubkeys
            .iter()
            .any(|p| *p == signed.server_pubkey_hex)
    {
        return Err(DirectoryError::ServerPubkeyMismatch {
            got: signed.server_pubkey_hex.clone(),
            expected: expected_server_pubkeys.join(","),
        });
    }

    // (2) server envelope signature
    let server_pubkey = decode_verifying_key(&signed.server_pubkey_hex)?;
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
    let envelope_sig = decode_signature(&signed.signature_hex)?;
    server_pubkey
        .verify(&canonical, &envelope_sig)
        .map_err(|_| DirectoryError::BadEnvelopeSignature)?;

    // (3) operational certificate against the pinned root
    let operational_pubkey = decode_verifying_key(&signed.operational_pubkey_hex)?;
    let cert: [u8; 64] = hex::decode(&signed.operational_cert_hex)
        .map_err(|_| DirectoryError::InvalidHex)?
        .try_into()
        .map_err(|_| DirectoryError::InvalidHex)?;
    if expected_root_pubkeys.is_empty() {
        // TOFU (dev/bench): no root pin, trust the carried operational key.
    } else {
        let mut ok = false;
        for root_hex in expected_root_pubkeys {
            let Ok(root) = decode_verifying_key(root_hex) else {
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
    /// - [`DirectoryError::BadOperationalCert`] if any node descriptor
    ///   does not verify under the operational key (variant reused to
    ///   signal "descriptor not vouched by the claimed operational key").
    pub fn validate_self_consistent(&self) -> Result<(), DirectoryError> {
        let operational_pubkey = decode_verifying_key(&self.operational_pubkey_hex)?;
        let _cert: [u8; 64] = hex::decode(&self.operational_cert_hex)
            .map_err(|_| DirectoryError::InvalidHex)?
            .try_into()
            .map_err(|_| DirectoryError::InvalidHex)?;
        for node in &self.nodes {
            if !node_fully_vouched(&operational_pubkey, node) {
                return Err(DirectoryError::BadOperationalCert);
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
pub fn sign_directory_draft(
    draft: &MultiHopDirectoryDraft,
    server_key: &SigningKey,
    signed_at: u64,
    expires_at: u64,
) -> Result<SignedMultiHopDirectory, DirectoryError> {
    let operational_pubkey = decode_verifying_key(&draft.operational_pubkey_hex)?;
    let cert: [u8; 64] = hex::decode(&draft.operational_cert_hex)
        .map_err(|_| DirectoryError::InvalidHex)?
        .try_into()
        .map_err(|_| DirectoryError::InvalidHex)?;
    Ok(sign_multihop_directory(
        draft.nodes.clone(),
        server_key,
        &operational_pubkey,
        &cert,
        draft.generation,
        signed_at,
        expires_at,
    ))
}

/// Censorship-minimization: returns a copy of `nodes` with every
/// node's **exit egress IP redacted** (`exit.endpoint = None`), for the
/// client-facing `/v1/multihop/directory`.
///
/// The client never dials the exit (it dials the entry relay, whose
/// `relay.endpoint` is kept); only the auth-gated relay-facing directory
/// carries the exit endpoint. Because `endpoint` is **not** under the
/// operational descriptor signature, redacting it leaves
/// [`verify_exit_descriptor`] (and the whole per-node chain) valid. The
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
    // Multi-hop client policy (engine spec): reject an exit that advertises
    // `dns_disabled = true` but is only `/v1`-signed (the bit is unattested), a
    // downgrade-attack suspect that could silently disable in-tunnel DNS. An
    // attested exit, or an unattested exit with DNS enabled, is kept.
    match verify_exit_descriptor_with_dns_attestation(operational_pubkey, &node.exit) {
        Err(_) => return false,
        Ok(ExitDescAttestation::Unattested) if node.exit.dns_disabled => return false,
        Ok(_) => {}
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

fn decode_verifying_key(hex_str: &str) -> Result<VerifyingKey, DirectoryError> {
    let bytes: [u8; 32] = hex::decode(hex_str)
        .map_err(|_| DirectoryError::InvalidHex)?
        .try_into()
        .map_err(|_| DirectoryError::InvalidHex)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| DirectoryError::PubkeyNotOnCurve)
}

fn decode_signature(hex_str: &str) -> Result<Signature, DirectoryError> {
    let bytes: [u8; 64] = hex::decode(hex_str)
        .map_err(|_| DirectoryError::InvalidHex)?
        .try_into()
        .map_err(|_| DirectoryError::InvalidHex)?;
    Ok(Signature::from_bytes(&bytes))
}

/// A trusted exit projected from a verified multi-hop directory: the flat,
/// client-facing dial view. Every node kept here passed the full operational +
/// attestation checks, including the anti-downgrade DNS-attestation policy in
/// [`node_fully_vouched`], so `dns_disabled` is trustworthy.
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
    /// City.
    pub city: String,
    /// Selection weight.
    pub weight: u64,
    /// The exit runs no in-tunnel DNS forwarder (trustworthy: unattested
    /// `dns_disabled` exits are dropped by [`node_fully_vouched`]).
    pub dns_disabled: bool,
    /// X.509 cover-domain SNI from the relay descriptor (ADR-0004), if any.
    pub cover_domain: Option<String>,
}

impl VerifiedMultiHopDirectory {
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
                city: n.city.clone(),
                weight: n.weight,
                dns_disabled: n.exit.dns_disabled,
                cover_domain: n.relay.cover_domain.clone(),
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
        );
        serde_json::to_string(&signed).expect("serialize minted directory")
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use ed25519_dalek::{Signer, SigningKey};
    use warrenguard_multihop::{
        ExitId, exit_descriptor_signing_payload, relay_descriptor_signing_payload,
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
        }
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
    fn wrong_server_pin_is_rejected() {
        let (root, op, server, attacker) = (key(0x01), key(0x02), key(0x03), key(0x09));
        let signed = build(&root, &op, &server, vec![signed_node(&op, 1, "fr", 1)]);
        let json = serde_json::to_string(&signed).unwrap();
        let err = verify_multihop_directory_any(&json, &[&hexk(&attacker)], &[&hexk(&root)])
            .expect_err("wrong server pin must reject");
        assert!(matches!(err, DirectoryError::ServerPubkeyMismatch { .. }));
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
        assert!(matches!(err, DirectoryError::BadOperationalCert));
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
        );
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
}
