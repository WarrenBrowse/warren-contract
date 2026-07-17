//! Shared kill-switch fail-state contract: what the block must do when the
//! thing controlling it goes away.
//!
//! Every Warren client ships some form of kill switch (the desktop app's
//! firewall lockdown, the desktop daemon's pf/nft ruleset installed for a
//! rooted TUN session, wclaude's per-process fail-closed proxy), and each one
//! historically decided on its own what happens when its controller dies: the
//! app's lockdown persists after the daemon stops, the SDK desktop daemon
//! (warrend) RESTORES the firewall when its owning client vanishes (fail-open
//! for privacy), and wclaude blocks its child process structurally. Whether
//! traffic may flow after an abnormal end is a security-facing semantic, so it
//! is decided once here, CORE-FIRST from the production app's behavior, and
//! every client conforms to (or explicitly records its divergence from) this
//! matrix.
//!
//! # The unified matrix
//!
//! Only an explicit user intent may open the network. Every abnormal end of
//! the controlling process (client crash, daemon stop, uncatchable kill) must
//! leave the block HOLDING: a dying controller is precisely the moment traffic
//! the user asked to protect would otherwise leak. A host reboot clears
//! kernel firewall state, so it re-opens the network unless the user opted
//! into lockdown mode (block-before-boot).
//!
//! # Conformance status (recorded, not aspirational)
//!
//! - Desktop app: conforms (lockdown mode persists across daemon stop; the
//!   blocking firewall holds on abnormal daemon end).
//! - warrend (SDK desktop daemon): DIVERGES on [`KillswitchTrigger::OwnerConnectionLost`]
//!   and [`KillswitchTrigger::DaemonShutdown`]: its RAII teardown restores the
//!   firewall on any graceful end, trading a privacy fail-open for never
//!   stranding the host without connectivity. Closing that gap needs a
//!   recovery path (a way to lift a held block with no daemon running) and is
//!   tracked as a follow-up; the divergence is deliberate until then.
//! - wclaude: per-process fail-closed by construction (no OS ruleset exists,
//!   the wrapped process simply has no egress without the tunnel), so the
//!   matrix rows about OS rule persistence do not apply to the host.

/// Why the kill switch's controller went away (or was asked to stand down).
/// Rows assume a session was being protected when the trigger fired; that is
/// the only case where the answer matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillswitchTrigger {
    /// The user explicitly asked to disconnect.
    UserDisconnect,
    /// The controlling client (app/UI) vanished while the session was up:
    /// crash, kill, or a dropped control connection.
    OwnerConnectionLost,
    /// The daemon itself stopped gracefully (service stop, SIGTERM) while the
    /// session was up.
    DaemonShutdown,
    /// The daemon died with no chance to run teardown (SIGKILL, power loss of
    /// the process). Kernel firewall state outlives the process, so whatever
    /// was installed keeps holding.
    DaemonKilled,
    /// The host rebooted: kernel firewall state is gone unless something
    /// re-installs a block before networking comes up.
    HostReboot,
}

/// What the network must look like after the trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailPosture {
    /// Traffic flows in the clear.
    Open,
    /// The kill switch holds: nothing leaks, nothing flows.
    Blocking,
}

/// The single decision table: the posture a conforming client must reach for
/// `trigger`, given whether the user enabled lockdown mode (block even when
/// no session is up, including before boot).
#[must_use]
pub fn expected_posture(trigger: KillswitchTrigger, lockdown: bool) -> FailPosture {
    match trigger {
        // Explicit intent, and the one case where no code can hold kernel
        // state: both open the network unless the user opted into lockdown.
        KillswitchTrigger::UserDisconnect | KillswitchTrigger::HostReboot => {
            if lockdown {
                FailPosture::Blocking
            } else {
                FailPosture::Open
            }
        }
        // Any abnormal end of the controller holds the block: that is exactly
        // when traffic the user asked to protect would otherwise leak.
        KillswitchTrigger::OwnerConnectionLost
        | KillswitchTrigger::DaemonShutdown
        | KillswitchTrigger::DaemonKilled => FailPosture::Blocking,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use FailPosture::{Blocking, Open};
    use KillswitchTrigger::*;

    #[test]
    fn the_matrix_is_pinned() {
        // The full decision table. A behavior change here is a security
        // semantics change for every client and must be deliberate.
        let cases = [
            (UserDisconnect, false, Open),
            (UserDisconnect, true, Blocking),
            (OwnerConnectionLost, false, Blocking),
            (OwnerConnectionLost, true, Blocking),
            (DaemonShutdown, false, Blocking),
            (DaemonShutdown, true, Blocking),
            (DaemonKilled, false, Blocking),
            (DaemonKilled, true, Blocking),
            (HostReboot, false, Open),
            (HostReboot, true, Blocking),
        ];
        for (trigger, lockdown, expected) in cases {
            assert_eq!(
                expected_posture(trigger, lockdown),
                expected,
                "{trigger:?} with lockdown={lockdown} must be {expected:?}"
            );
        }
    }

    #[test]
    fn only_explicit_user_intent_opens_the_network_outside_reboot() {
        for trigger in [OwnerConnectionLost, DaemonShutdown, DaemonKilled] {
            for lockdown in [false, true] {
                assert_eq!(
                    expected_posture(trigger, lockdown),
                    Blocking,
                    "an abnormal controller end must never expose traffic ({trigger:?})"
                );
            }
        }
    }
}
