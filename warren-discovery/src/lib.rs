//! Warren discovery: client-side verification of the three signed formats
//! the fleet is built from - the server-signed relay list
//! ([`verify_signed_relay_list`]), the offline-admin-signed exit roster
//! ([`verify_roster`]), and the multi-hop directory
//! ([`verify_multihop_directory`]) - plus the weighted exit-selection
//! engine ([`WarrenRelaySelector`]) that picks among the resulting
//! [`WarrenRelay`]s, and the server / offline-admin signing entry points
//! that produce all three formats. Single implementation shared by the
//! client SDK and the backend.
//!
//! Selection (once a list is verified) is a functional equivalent of
//! `mullvad-relay-selector` on the Warren side, without the WireGuard
//! heritage (no obfuscation retry order, no Shadowsocks/UDP2TCP/QUIC-MASQUE/
//! LWO/DAITA): geo filter, IP availability, weighted selection by `weight`.
//!
//! The caller (typically `mullvad-daemon`) consumes a `WarrenRelay` to build
//! the Warren tunnel parameters on the `talpid-warren` side, then the tunnel
//! state machine calls the Warren backend when selected.

mod envelope;
mod forum_digest;
mod json_io;
mod multihop_directory;
mod notices;
mod path_aware;
mod query;
mod relay;
mod roster;
mod rtt;
mod selector;
mod signed;

/// Directory-minting fixtures for other crates' tests (behind `test-helpers`).
#[cfg(feature = "test-helpers")]
pub use multihop_directory::test_helpers;

pub use forum_digest::{
    FORUM_DIGEST_VERSION, ForumDigestError, SignedForumDigest, UNREAD_SATURATED,
    VerifiedForumDigest, pack_unread_counts, sign_forum_digest, verify_forum_digest,
    verify_forum_digest_any,
};
pub use json_io::JsonError;
pub use multihop_directory::{
    CircuitPolicy, DirectoryError, MULTIHOP_DIRECTORY_VERSION, MultiHopDirectoryDraft, NodeEntry,
    SignedMultiHopDirectory, VerifiedEntry, VerifiedExit, VerifiedMultiHopDirectory,
    ensure_lossless_roundtrip, redact_exit_endpoints, sign_directory_draft,
    sign_multihop_directory, valid_circuits, verify_multihop_directory,
    verify_multihop_directory_any,
};
pub use notices::{
    NOTICES_VERSION, NoticesError, SignedNotices, VerifiedNotices, sign_notices,
    verify_signed_notices, verify_signed_notices_any,
};
pub use path_aware::{
    EntryPathQuality, LegQuality, PATH_QUALITY_DEGRADED_RTT_MS, PATH_QUALITY_VERSION,
    PathAwareParams, PathQualityAdvisory, entry_rtt_from, node_rtt_from, pick_circuit_by_weight,
    select_circuit_path_aware, select_entry_path_aware,
};
pub use query::{IpAvailability, LocationConstraint, WarrenRelayQuery};
pub use relay::{
    Addr, Egress, Endpoint, Exit, Family, GeoIp, Ingress, Listener, Location, WarrenRelay,
    WarrenRelayList,
};
pub use roster::{
    AuthorizeResult, ROSTER_VERSION, RosterEntry, RosterError, SignedRoster, VerifiedRoster,
    sign_roster, verify_roster, verify_roster_any,
};
pub use rtt::{DEFAULT_RTT_TTL_SECS, EndpointId, RttCache};
pub use selector::{SelectorError, WarrenRelaySelector};
pub use signed::{
    JsonEgress, JsonEndpoint, JsonListener, JsonLocation, JsonNode, SIGNED_VERSION, SignedError,
    SignedRelayList, VerifiedRelayList, sign_relay_list, unknown_signed_fields,
    verify_signed_relay_list, verify_signed_relay_list_any,
};
// The notice DTO itself lives in the contract crate (one definition for the
// backend and every SDK); re-exported because [`VerifiedNotices`] hands it
// out, so a consumer has to be able to name it without a second dependency.
pub use warren_contract::dto::{Notice, NoticeLevel};

/// Re-exports of the Warren types exposed by this crate's public API,
/// so callers (e.g. `mullvad-daemon`) can consume the selector without
/// adding `warren-protocol` as a direct dep.
pub mod warren_types {
    pub use ed25519_dalek::SigningKey;
    pub use warrenguard_wire::{ExitId, WarrenExitAddr, WarrenPubkey};
}
