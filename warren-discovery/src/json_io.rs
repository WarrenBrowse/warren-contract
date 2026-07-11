//! Parsing of the `warren-relays.json` JSON format.
//!
//! Bootstrap (unsigned) format for the POC; mirrors the per-node shape
//! of the signed v8 list. The production path uses the signed format
//! ([`crate::signed`]); this is a local development / baked-bootstrap
//! convenience.

use serde::{Deserialize, Serialize};
use warrenguard_wire::WarrenPubkey;

use crate::WarrenRelayList;
use crate::signed::{JsonNode, json_node_to_warren};

/// Supported JSON format version. Bump when the schema breaks
/// forward compatibility (= an old parser cannot read a new file).
///
/// **v4 (minimized node model)**: aligned with the signed v8 list; the
/// root is `nodes`, each entry a minimized [`JsonNode`] (entry endpoints
/// with listeners + node-level egress capability booleans; no roles, no
/// per-endpoint geoip/flags). Was v3 (v6 node model), v2 (flat `relays`).
const SUPPORTED_VERSION: u32 = 4;

/// Parsing errors for `warren-relays.json`. Malformed-input payloads
/// carry only a redacted prefix of the offending value (a node id is a
/// pubkey; no-log discipline).
#[derive(Debug, thiserror::Error)]
pub enum JsonError {
    /// Syntactically invalid JSON or unexpected structure.
    #[error("invalid warren-relays.json: {0}")]
    Json(#[from] serde_json::Error),

    /// The file version is not supported by this release.
    #[error("unsupported warren-relays.json version: {0} (expected {SUPPORTED_VERSION})")]
    UnsupportedVersion(u32),

    /// An `id` is neither a valid Warren SS58 (`wb…`) address nor a
    /// 64-char hex encoding of a 32-byte Ed25519 key.
    #[error("invalid node id (expected SS58 wb… address or 64-char hex): {0}")]
    InvalidEndpointId(String),

    /// An endpoint `addr` is not a valid IP address literal.
    #[error("invalid endpoint addr: {0}")]
    InvalidIpAddr(String),

    /// An endpoint `family` is neither `ipv4` nor `ipv6`, or disagrees
    /// with the parsed `addr`.
    #[error("invalid endpoint family (expected ipv4/ipv6 matching addr): {0}")]
    InvalidFamily(String),

    /// The input exceeds the crate's pre-authentication size gate,
    /// rejected before parsing to bound the allocation an untrusted
    /// payload can force.
    #[error("input exceeds the maximum allowed size")]
    InputTooLarge,
}

#[derive(Debug, Deserialize, Serialize)]
struct JsonRoot {
    version: u32,
    nodes: Vec<JsonNode>,
}

impl WarrenRelayList {
    /// Parses a JSON string in the `warren-relays.json` v4 (node) format.
    ///
    /// # Errors
    ///
    /// - [`JsonError::InputTooLarge`] if `s` exceeds the pre-authentication
    ///   size gate.
    /// - [`JsonError::Json`] if the string is not valid JSON.
    /// - [`JsonError::UnsupportedVersion`] if `version != SUPPORTED_VERSION`.
    /// - [`JsonError::InvalidEndpointId`] if a node `id` is malformed.
    /// - [`JsonError::InvalidIpAddr`] / [`JsonError::InvalidFamily`] on a
    ///   malformed endpoint address or family.
    pub fn from_json_str(s: &str) -> Result<Self, JsonError> {
        if s.len() > crate::envelope::MAX_VERIFY_INPUT_LEN {
            return Err(JsonError::InputTooLarge);
        }
        let root: JsonRoot = serde_json::from_str(s)?;
        if root.version != SUPPORTED_VERSION {
            return Err(JsonError::UnsupportedVersion(root.version));
        }
        let relays = root
            .nodes
            .into_iter()
            .map(json_node_to_warren)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::new(relays))
    }
}

/// Decodes a node `id` field into a [`WarrenPubkey`].
///
/// warren-api publishes the node identity as a Warren SS58 (`wb…`)
/// address. The raw 64-char hex form is accepted as a fallback for
/// legacy / locally-authored caches. A 64-char hex string is never a
/// valid SS58 address and vice-versa, so the dispatch is unambiguous.
pub(crate) fn decode_endpoint_id(s: &str) -> Result<WarrenPubkey, JsonError> {
    if let Ok(bytes) = warren_contract::ss58::decode(s) {
        return Ok(WarrenPubkey::from_bytes(bytes));
    }
    WarrenPubkey::from_hex(s).map_err(|_| JsonError::InvalidEndpointId(warren_contract::redact(s)))
}

#[cfg(test)]
mod tests {
    use warrenguard_wire::ExitId;

    use super::*;
    use crate::signed::{JsonEgress, JsonEndpoint, JsonLocation, json_node_to_warren};

    #[test]
    fn invalid_endpoint_id_error_redacts_the_id() {
        let bogus = format!("{}Z", "f".repeat(63));
        let msg = decode_endpoint_id(&bogus)
            .expect_err("neither SS58 nor hex must be rejected")
            .to_string();
        assert!(!msg.contains(&bogus), "full id must not leak: {msg}");
        assert!(msg.contains("ffffffff…"), "short prefix kept: {msg}");
    }

    #[test]
    fn invalid_endpoint_addr_error_redacts_the_addr() {
        let bad_addr = "999.999.999.999-evil";
        let node = JsonNode {
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
                addr: bad_addr.to_owned(),
                family: "ipv4".to_owned(),
                listeners: vec![],
            }],
            cover_domain: None,
            port_forward: None,
        };
        let msg = json_node_to_warren(node)
            .expect_err("malformed IP literal must be rejected")
            .to_string();
        assert!(!msg.contains(bad_addr), "full addr must not leak: {msg}");
        assert!(msg.contains("999.999.…"), "short prefix kept: {msg}");
    }
}
