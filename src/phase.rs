//! Shared connection-phase contract: the single reduction of a tunnel's
//! runtime status into the coarse phase that drives the "protected" green
//! state on every Warren client surface (desktop app, browser extension, and
//! any future SDK-driven UI).
//!
//! The app renderer and the extension each reduced tunnel status to a phase on
//! their own and disagreed: the app degrades the green state when egress is
//! dead or the host is offline and has a distinct kill-switch `Blocked` phase,
//! while the extension mapped `connected` straight to `protected` with no
//! egress input and no blocked phase. A green "protected" is a security-facing
//! claim (traffic really flows through the tunnel), so the two must not drift.
//! This module is the one place that decides it, CORE-FIRST from the app's
//! production semantics, extended with the states the extension needs.
//!
//! # The `Protected` invariant
//!
//! [`ConnectionPhase::Protected`] MUST be shown only when the tunnel is
//! [`TunnelStatus::Connected`] AND egress is verified alive
//! ([`EgressEvidence::is_verified`]). "Connected" alone is not enough: the
//! daemon holds `Connected` through an offline-migration grace window and while
//! the supervisor redials, and an exit can keep the QUIC session up while it
//! has stopped forwarding, so a merely-connected session may pass no traffic. A
//! kill switch holding traffic with nothing flowing is [`ConnectionPhase::Blocked`],
//! never `Protected`: `Blocked` asserts "nothing leaks", `Protected` asserts
//! "traffic flows", and conflating them would show green while the user is
//! either leaking or dark.

use serde::{Deserialize, Serialize};

/// The coarse connection phase presented to the user. The serialized spelling
/// is the lowercase phase name, matching the string literals the TypeScript
/// clients already use, so a JSON contract lines up across languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionPhase {
    /// Traffic is in the clear: no tunnel and no kill switch (red).
    Exposed,
    /// The tunnel is coming up or going down (orange).
    Connecting,
    /// The tunnel is up AND egress is verified alive: traffic flows (green).
    Protected,
    /// The tunnel is nominally up but not passing traffic (host offline, dead
    /// egress, or redialing): green would be a lie (orange).
    Interrupted,
    /// The kill switch is holding: nothing leaks, but nothing flows (neutral).
    Blocked,
}

/// Neutral, daemon-agnostic tunnel status. It is the union of the states the
/// desktop daemon and the extension host each report, so one reduction serves
/// both. The serialized shape (a lowercase `state` tag plus camelCase fields)
/// is the cross-language spelling the shared phase-reduction fixture and the
/// TypeScript union use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum TunnelStatus {
    /// The tunnel session is established.
    Connected,
    /// The tunnel is being established.
    Connecting,
    /// The tunnel is being torn down.
    Disconnecting,
    /// An exit drain is in progress and the client is moving off it.
    Draining,
    /// The session dropped and the supervisor is redialing.
    Reconnecting,
    /// No tunnel. `locked_down` is the kill switch still holding traffic.
    Disconnected {
        /// Whether the kill switch is holding traffic while disconnected.
        #[serde(rename = "lockedDown")]
        locked_down: bool,
    },
    /// The tunnel is in an error state. `blocking_error` means the daemon
    /// failed to install the block, so traffic may be leaking.
    Error {
        /// Whether the block itself failed (traffic may leak).
        #[serde(rename = "blockingError")]
        blocking_error: bool,
    },
}

/// Liveness evidence about the egress path, gathered outside the tunnel state
/// machine (an active egress probe and the host-reachability watcher). It is
/// the extra input that keeps `Protected` honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EgressEvidence {
    /// The local host lost connectivity (for example a Wi-Fi to LTE handover)
    /// while the daemon still reports `Connected`.
    pub host_offline: bool,
    /// The exit stopped forwarding (egress-probe verdict) while the QUIC
    /// session still looks alive.
    pub exit_egress_dead: bool,
}

impl EgressEvidence {
    /// Egress is verified alive: neither the host is offline nor the exit
    /// stopped forwarding. Only then may `Connected` be shown as `Protected`.
    #[must_use]
    pub fn is_verified(self) -> bool {
        !self.host_offline && !self.exit_egress_dead
    }
}

/// Reduces a tunnel status plus egress evidence to the single phase that every
/// client presents. This is the one place the "protected" green state is
/// decided; see the module docs for the `Protected` invariant.
#[must_use]
pub fn reduce_phase(status: TunnelStatus, egress: EgressEvidence) -> ConnectionPhase {
    match status {
        TunnelStatus::Connected => {
            if egress.is_verified() {
                ConnectionPhase::Protected
            } else {
                ConnectionPhase::Interrupted
            }
        }
        TunnelStatus::Connecting | TunnelStatus::Disconnecting | TunnelStatus::Draining => {
            ConnectionPhase::Connecting
        }
        TunnelStatus::Reconnecting => ConnectionPhase::Interrupted,
        TunnelStatus::Disconnected { locked_down } => {
            if locked_down {
                ConnectionPhase::Blocked
            } else {
                ConnectionPhase::Exposed
            }
        }
        TunnelStatus::Error { blocking_error } => {
            if blocking_error {
                ConnectionPhase::Exposed
            } else {
                ConnectionPhase::Blocked
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_with_verified_egress_is_protected() {
        assert_eq!(
            reduce_phase(TunnelStatus::Connected, EgressEvidence::default()),
            ConnectionPhase::Protected
        );
    }

    #[test]
    fn connected_but_host_offline_degrades_to_interrupted() {
        let egress = EgressEvidence {
            host_offline: true,
            exit_egress_dead: false,
        };
        assert_eq!(
            reduce_phase(TunnelStatus::Connected, egress),
            ConnectionPhase::Interrupted,
            "a merely-connected session with a dead path must never read as protected"
        );
    }

    #[test]
    fn connected_but_egress_dead_degrades_to_interrupted() {
        let egress = EgressEvidence {
            host_offline: false,
            exit_egress_dead: true,
        };
        assert_eq!(
            reduce_phase(TunnelStatus::Connected, egress),
            ConnectionPhase::Interrupted
        );
    }

    #[test]
    fn transitional_states_are_connecting() {
        for status in [
            TunnelStatus::Connecting,
            TunnelStatus::Disconnecting,
            TunnelStatus::Draining,
        ] {
            assert_eq!(
                reduce_phase(status, EgressEvidence::default()),
                ConnectionPhase::Connecting,
                "{status:?} is a transitional state"
            );
        }
    }

    #[test]
    fn reconnecting_is_interrupted_not_protected() {
        assert_eq!(
            reduce_phase(TunnelStatus::Reconnecting, EgressEvidence::default()),
            ConnectionPhase::Interrupted
        );
    }

    #[test]
    fn disconnected_distinguishes_kill_switch_from_exposure() {
        assert_eq!(
            reduce_phase(
                TunnelStatus::Disconnected { locked_down: true },
                EgressEvidence::default()
            ),
            ConnectionPhase::Blocked
        );
        assert_eq!(
            reduce_phase(
                TunnelStatus::Disconnected { locked_down: false },
                EgressEvidence::default()
            ),
            ConnectionPhase::Exposed
        );
    }

    #[test]
    fn error_leaks_are_exposed_but_a_held_block_is_blocked() {
        assert_eq!(
            reduce_phase(
                TunnelStatus::Error {
                    blocking_error: true
                },
                EgressEvidence::default()
            ),
            ConnectionPhase::Exposed,
            "a failed block may be leaking, so it is exposure, not a clean block"
        );
        assert_eq!(
            reduce_phase(
                TunnelStatus::Error {
                    blocking_error: false
                },
                EgressEvidence::default()
            ),
            ConnectionPhase::Blocked
        );
    }

    #[test]
    fn phase_serializes_to_the_shared_lowercase_wire_names() {
        // Pins the cross-language spelling: the TypeScript clients key their UI
        // off these exact strings, so a rename here must break this test.
        let cases = [
            (ConnectionPhase::Exposed, "\"exposed\""),
            (ConnectionPhase::Connecting, "\"connecting\""),
            (ConnectionPhase::Protected, "\"protected\""),
            (ConnectionPhase::Interrupted, "\"interrupted\""),
            (ConnectionPhase::Blocked, "\"blocked\""),
        ];
        for (phase, expected) in cases {
            assert_eq!(serde_json::to_string(&phase).unwrap(), expected);
            let back: ConnectionPhase = serde_json::from_str(expected).unwrap();
            assert_eq!(back, phase);
        }
    }
}
