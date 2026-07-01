//! Selection of a Warren exit from a `WarrenRelayList`.
//!
//! Functional equivalent of [`mullvad-relay-selector`] on the Warren
//! side, without the WireGuard heritage (no obfuscation retry order,
//! no multihop entry/exit, no Shadowsocks/UDP2TCP/QUIC-MASQUE/LWO/
//! DAITA). Selection is intentionally simpler: geo filter, IP
//! availability, weighted selection by `weight`.
//!
//! The caller (typically `mullvad-daemon`) consumes a `WarrenRelay`
//! to build the Warren tunnel parameters on the `talpid-warren` side,
//! then the tunnel state machine calls the Warren backend when
//! selected.

#![cfg_attr(not(test), warn(missing_docs))]

mod error;
mod json_io;
mod multihop_directory;
mod query;
mod relay;
mod roster;
mod selector;
mod signed;

pub use error::SelectorError;
pub use json_io::JsonError;
pub use multihop_directory::{
    DirectoryError, MULTIHOP_DIRECTORY_VERSION, MultiHopDirectoryDraft, NodeEntry,
    SignedMultiHopDirectory, VerifiedExit, VerifiedMultiHopDirectory, ensure_lossless_roundtrip,
    redact_exit_endpoints, sign_directory_draft, sign_multihop_directory,
    verify_multihop_directory_any,
};
pub use query::{IpAvailability, LocationConstraint, WarrenRelayQuery};
pub use relay::{
    Addr, Egress, Endpoint, Exit, Family, GeoIp, Ingress, Listener, Location, WarrenRelay,
    WarrenRelayList,
};
pub use roster::{
    AuthorizeResult, ROSTER_VERSION, RosterEntry, SignedRoster, VerifiedRoster, sign_roster,
    verify_roster, verify_roster_any,
};
pub use selector::WarrenRelaySelector;
pub use signed::{
    JsonEgress, JsonEndpoint, JsonListener, JsonLocation, JsonNode, SIGNED_VERSION, SignedError,
    SignedRelayList, VerifiedRelayList, sign_relay_list, verify_signed_relay_list,
    verify_signed_relay_list_any,
};

/// Re-exports of the Warren types exposed by this crate's public API,
/// so callers (e.g. `mullvad-daemon`) can consume the selector without
/// adding `warren-protocol` as a direct dep.
pub mod warren_types {
    pub use ed25519_dalek::SigningKey;
    pub use warrenguard_wire::{ExitId, WarrenExitAddr, WarrenPubkey};
}
