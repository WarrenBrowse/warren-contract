//! Path-aware multi-hop circuit selection.
//!
//! The 2026-07-13 NL degradation showed why advertised location must not
//! drive entry choice: the auto-selected entry advertised DE/Kassel but sat
//! in Helsinki behind an episodically lossy leg to the exit, and every
//! client-side probe looked clean because the client cannot observe the
//! relayed leg. The signal that catches this class lives on the relay
//! (its own QUIC path stats toward the exits), travels through the exit
//! heartbeat, and reaches clients as the **unsigned advisory** modeled
//! here ([`PathQualityAdvisory`], served at `GET /v1/multihop/path-quality`).
//!
//! # Trust model (deliberate)
//!
//! The advisory is UNSIGNED and advisory-only. It may only ever **bias the
//! order** of circuits that the operationally-verified directory and
//! [`super::multihop_directory::CircuitPolicy`] already produced; it can
//! never admit a node or a pair. A malicious advisory can therefore steer
//! clients among legitimate circuits, which is exactly the steering power
//! the server envelope already holds through the unattested `weight`
//! field (the documented accepted risk of the directory), so no new trust
//! is granted. Keeping it out of the signed formats means no
//! `SIGNED_VERSION` / directory-version rotation, and a client that never
//! fetches it (or gets garbage) simply keeps today's behavior.
//!
//! # Fallback law
//!
//! With no advisory, no fresh samples, and no client-measured RTT,
//! [`select_circuit_path_aware`] is EXACTLY [`pick_circuit_by_weight`],
//! the deterministic highest-weight pick promoted from the production
//! app daemon. Missing data is always neutral, never fatal.

use serde::{Deserialize, Serialize};

use super::multihop_directory::{
    CircuitPolicy, NodeEntry, VerifiedEntry, VerifiedExit, VerifiedMultiHopDirectory,
};

/// Version of the path-quality advisory wire format. The advisory is
/// unsigned, so unknown fields are ignored and this version only gates
/// semantics changes, never signature preimages.
pub const PATH_QUALITY_VERSION: u32 = 1;

/// A relay leg whose smoothed RTT reaches this bar is degraded. Above the
/// healthy long-haul hops the fleet actually has (Helsinki->Singapore ran
/// ~190 ms healthy), below the 333-361 ms spikes of the 2026-07-13 lossy
/// Helsinki->Amsterdam leg.
pub const PATH_QUALITY_DEGRADED_RTT_MS: u32 = 300;

/// Measured quality of one relay->exit leg, aggregated server-side from
/// the entry node's own QUIC path stats (no client identifiers exist in
/// this data: it describes infrastructure legs only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegQuality {
    /// 32-char lowercase hex of the exit node this leg reaches.
    pub exit_id: String,
    /// Smoothed round-trip time of the leg, milliseconds.
    pub rtt_ms: u32,
    /// The leg recently reached the degraded bar (RTT spike or loss burst);
    /// the server latches this across blips so clients do not flap.
    pub degraded: bool,
    /// Unix epoch seconds of the newest sample backing this entry.
    pub sampled_at: u64,
}

/// Measured leg quality of one entry node toward the exits it forwards to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPathQuality {
    /// 32-char lowercase hex of the entry node's relay id.
    pub relay_id: String,
    /// The measured legs (absent legs are simply unknown, never bad).
    pub legs: Vec<LegQuality>,
}

/// The unsigned path-quality advisory served at
/// `GET /v1/multihop/path-quality`. See the module doc for the trust
/// model; consumers treat any fetch/parse failure as "no advisory".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathQualityAdvisory {
    /// Must equal [`PATH_QUALITY_VERSION`] for these semantics.
    pub version: u32,
    /// Unix epoch seconds the server rendered this advisory.
    pub generated_at: u64,
    /// Per-entry measured legs.
    pub entries: Vec<EntryPathQuality>,
}

impl PathQualityAdvisory {
    /// The measured quality of the `relay_id -> exit_id` leg, if present.
    /// Ids are matched as case-insensitive hex.
    #[must_use]
    pub fn leg(&self, relay_id: &[u8; 16], exit_id: &[u8; 16]) -> Option<&LegQuality> {
        let relay_hex = hex::encode(relay_id);
        let exit_hex = hex::encode(exit_id);
        self.entries
            .iter()
            .find(|e| e.relay_id.eq_ignore_ascii_case(&relay_hex))?
            .legs
            .iter()
            .find(|l| l.exit_id.eq_ignore_ascii_case(&exit_hex))
    }
}

/// Tuning knobs of [`select_circuit_path_aware`]. [`Default`] is the
/// production profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathAwareParams {
    /// Cost assumed for a leg with no fresh measurement, milliseconds.
    /// Unknown must sit between measured-good and measured-bad so data
    /// improves ranking without its absence ever excluding a node.
    pub neutral_rtt_ms: u32,
    /// RTT at which the path factor halves (the `K` of `K/(K+cost)`).
    pub half_score_rtt_ms: u32,
    /// Divisor applied to a pair whose relayed leg is degraded.
    pub degraded_penalty_div: u64,
    /// A challenger must beat the incumbent's score by this margin
    /// (percent) before the selection switches circuits.
    pub switch_margin_pct: u64,
    /// A leg sample older than this is treated as absent, seconds.
    pub stale_after_secs: u64,
}

impl Default for PathAwareParams {
    fn default() -> Self {
        Self {
            neutral_rtt_ms: 60,
            half_score_rtt_ms: 50,
            degraded_penalty_div: 8,
            switch_margin_pct: 25,
            stale_after_secs: 600,
        }
    }
}

/// Deterministic `(entry_idx, exit_idx)` pick over `pairs` (indices into
/// `dir.nodes`): highest combined `entry.weight * exit.weight`, ties broken
/// by `(relay_id, exit_id)`. Deterministic on purpose (a per-call RNG
/// churned the app daemon's tunnel into a reconnect loop). `None` on empty
/// `pairs`.
///
/// This is the production selection promoted verbatim from the app family
/// (`weighted_pick_pair`); [`select_circuit_path_aware`] reduces to it when
/// no path signal is available.
#[must_use]
pub fn pick_circuit_by_weight(
    dir: &VerifiedMultiHopDirectory,
    pairs: &[(usize, usize)],
) -> Option<(usize, usize)> {
    let weight = |&(i, j): &(usize, usize)| {
        dir.nodes[i]
            .weight
            .max(1)
            .saturating_mul(dir.nodes[j].weight.max(1))
    };
    let mut ranked: Vec<(usize, usize)> = pairs.to_vec();
    ranked.sort_by(|a, b| weight(b).cmp(&weight(a)).then_with(|| tie_break(dir, a, b)));
    ranked.first().copied()
}

/// The shared deterministic tie-break: ascending `(relay_id, exit_id)` of
/// the pair's entry and exit nodes, identical to the app family's.
fn tie_break(
    dir: &VerifiedMultiHopDirectory,
    a: &(usize, usize),
    b: &(usize, usize),
) -> std::cmp::Ordering {
    dir.nodes[a.0]
        .relay
        .relay_id
        .cmp(&dir.nodes[b.0].relay.relay_id)
        .then_with(|| {
            dir.nodes[a.1]
                .exit
                .exit_id
                .as_bytes()
                .cmp(dir.nodes[b.1].exit.exit_id.as_bytes())
        })
}

/// Path-aware deterministic circuit pick: ranks `pairs` by
/// `weight_product * K/(K + path_cost_ms)` where `path_cost_ms` is the
/// client-measured RTT to the entry (`entry_rtt_ms`, neutral when unknown)
/// plus the advisory's relayed-leg RTT (neutral when absent or stale), with
/// a hard penalty on degraded legs; ties break like
/// [`pick_circuit_by_weight`].
///
/// `prev` is the currently-flying circuit as `(relay_id, exit_id)`: it is
/// retained unless it is degraded, gone from `pairs`, or beaten by more
/// than [`PathAwareParams::switch_margin_pct`], so a transient blip cannot
/// flap circuits.
///
/// `None` on empty `pairs`.
#[must_use]
pub fn select_circuit_path_aware<F>(
    dir: &VerifiedMultiHopDirectory,
    pairs: &[(usize, usize)],
    advisory: Option<&PathQualityAdvisory>,
    entry_rtt_ms: F,
    now_unix: u64,
    prev: Option<([u8; 16], [u8; 16])>,
    params: &PathAwareParams,
) -> Option<(usize, usize)>
where
    F: Fn(&NodeEntry) -> Option<u32>,
{
    let fresh_leg = |entry: &NodeEntry, exit: &NodeEntry| -> Option<&LegQuality> {
        let l = advisory?.leg(&entry.relay.relay_id, exit.exit.exit_id.as_bytes())?;
        (now_unix.saturating_sub(l.sampled_at) <= params.stale_after_secs).then_some(l)
    };
    let score = |&(i, j): &(usize, usize)| -> u128 {
        let entry = &dir.nodes[i];
        let exit = &dir.nodes[j];
        path_score(
            entry.weight.max(1).saturating_mul(exit.weight.max(1)),
            entry_rtt_ms(entry).unwrap_or(params.neutral_rtt_ms),
            fresh_leg(entry, exit).map(|l| (l.rtt_ms, l.degraded)),
            params,
        )
    };

    let mut ranked: Vec<(usize, usize)> = pairs.to_vec();
    ranked.sort_by(|a, b| score(b).cmp(&score(a)).then_with(|| tie_break(dir, a, b)));
    let best = *ranked.first()?;

    let Some((prev_relay, prev_exit)) = prev else {
        return Some(best);
    };
    let Some(&incumbent) = pairs.iter().find(|&&(i, j)| {
        dir.nodes[i].relay.relay_id == prev_relay
            && *dir.nodes[j].exit.exit_id.as_bytes() == prev_exit
    }) else {
        return Some(best);
    };
    let incumbent_degraded =
        fresh_leg(&dir.nodes[incumbent.0], &dir.nodes[incumbent.1]).is_some_and(|l| l.degraded);
    if incumbent_degraded {
        return Some(best);
    }
    let challenger_bar = score(&incumbent)
        .saturating_mul(u128::from(100 + params.switch_margin_pct))
        .checked_div(100)
        .unwrap_or(u128::MAX);
    if score(&best) > challenger_bar {
        Some(best)
    } else {
        Some(incumbent)
    }
}

/// Fixed-point scale of the path factor `K/(K+cost)` so integer scoring
/// keeps enough resolution to rank realistic weights deterministically.
const SCORE_SCALE: u128 = 1_000_000;

/// The one scoring rule both selection views share:
/// `weight * SCALE * K / (K + client_ms + leg_ms)`, with the degraded
/// divisor applied last. `leg` is the fresh advisory sample, if any; the
/// weight product is pre-saturated in u64 by the caller so the no-signal
/// ranking reproduces [`pick_circuit_by_weight`] bit-for-bit.
fn path_score(
    weight: u64,
    client_ms: u32,
    leg: Option<(u32, bool)>,
    params: &PathAwareParams,
) -> u128 {
    let (leg_ms, degraded) = leg.unwrap_or((params.neutral_rtt_ms, false));
    let k = u128::from(params.half_score_rtt_ms.max(1));
    let cost = u128::from(client_ms).saturating_add(u128::from(leg_ms));
    let mut s = u128::from(weight)
        .saturating_mul(SCORE_SCALE)
        .saturating_mul(k)
        .checked_div(k.saturating_add(cost))
        .unwrap_or(0);
    if degraded {
        s /= u128::from(params.degraded_penalty_div.max(1));
    }
    s
}

/// Path-aware ENTRY pick for one already-chosen `exit`, over the flat
/// entry projection the SDK family consumes: the same scoring and
/// hysteresis as [`select_circuit_path_aware`], gated by
/// [`CircuitPolicy::permits`] so no candidate can violate the diversity
/// rule. The advisory keys entries by node id (dual-role fleet:
/// `relay_id == exit_id`), which the flat view carries as
/// [`VerifiedEntry::exit_id`].
///
/// `prev_entry_node_id` is the currently-flying entry's node id; it is
/// retained under the same margin/degraded rules as the pair view.
/// `None` when no entry is policy-permitted for this exit.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn select_entry_path_aware<'a, F>(
    entries: &'a [VerifiedEntry],
    exit: &VerifiedExit,
    policy: &CircuitPolicy,
    advisory: Option<&PathQualityAdvisory>,
    entry_rtt_ms: F,
    now_unix: u64,
    prev_entry_node_id: Option<&[u8; 16]>,
    params: &PathAwareParams,
) -> Option<&'a VerifiedEntry>
where
    F: Fn(&VerifiedEntry) -> Option<u32>,
{
    let fresh_leg = |entry: &VerifiedEntry| -> Option<(u32, bool)> {
        let l = advisory?.leg(&entry.exit_id, &exit.exit_id)?;
        (now_unix.saturating_sub(l.sampled_at) <= params.stale_after_secs)
            .then_some((l.rtt_ms, l.degraded))
    };
    let score = |entry: &VerifiedEntry| -> u128 {
        path_score(
            entry.weight.max(1).saturating_mul(exit.weight.max(1)),
            entry_rtt_ms(entry).unwrap_or(params.neutral_rtt_ms),
            fresh_leg(entry),
            params,
        )
    };

    let mut ranked: Vec<&VerifiedEntry> =
        entries.iter().filter(|e| policy.permits(e, exit)).collect();
    ranked.sort_by(|a, b| {
        score(b)
            .cmp(&score(a))
            .then_with(|| a.exit_id.cmp(&b.exit_id))
    });
    let best = *ranked.first()?;

    let Some(prev_id) = prev_entry_node_id else {
        return Some(best);
    };
    let Some(incumbent) = ranked.iter().copied().find(|e| e.exit_id == *prev_id) else {
        return Some(best);
    };
    if fresh_leg(incumbent).is_some_and(|(_, degraded)| degraded) {
        return Some(best);
    }
    let challenger_bar = score(incumbent)
        .saturating_mul(u128::from(100 + params.switch_margin_pct))
        .checked_div(100)
        .unwrap_or(u128::MAX);
    if score(best) > challenger_bar {
        Some(best)
    } else {
        Some(incumbent)
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use warrenguard_multihop::{ExitDescriptorSigned, ExitId, RelayDescriptorSigned};

    use super::*;

    fn node(tag: u8, country: &str, weight: u64) -> NodeEntry {
        let endpoint: std::net::SocketAddr = format!("198.51.100.{tag}:443").parse().unwrap();
        NodeEntry {
            relay: RelayDescriptorSigned {
                relay_id: [tag; 16],
                relay_ed25519_pubkey: [tag; 32],
                endpoint,
                cover_domain: None,
                tcp_fallback: false,
                signature: [0; 64],
            },
            exit: ExitDescriptorSigned {
                exit_id: ExitId::from_bytes([tag; 16]),
                exit_ed25519_pubkey: [tag; 32],
                exit_x25519_multihop_pubkey: [tag; 32],
                endpoint: Some(endpoint),
                cover_domain: None,
                signature: [0; 64],
                dns_disabled: false,
                exit_mlkem768_pubkey: None,
            },
            country: country.to_owned(),
            city: "City".to_owned(),
            asn: 0,
            weight,
            attestation_hex: String::new(),
            edge_cert_sha256: None,
        }
    }

    fn dir(nodes: Vec<NodeEntry>) -> VerifiedMultiHopDirectory {
        VerifiedMultiHopDirectory {
            operational_pubkey: SigningKey::from_bytes(&[7; 32]).verifying_key(),
            nodes,
            generation: 1,
            signed_at: 0,
            expires_at: u64::MAX,
            dropped: 0,
        }
    }

    fn leg(exit_tag: u8, rtt_ms: u32, degraded: bool, sampled_at: u64) -> LegQuality {
        LegQuality {
            exit_id: hex::encode([exit_tag; 16]),
            rtt_ms,
            degraded,
            sampled_at,
        }
    }

    fn advisory_for(entries: Vec<(u8, Vec<LegQuality>)>) -> PathQualityAdvisory {
        PathQualityAdvisory {
            version: PATH_QUALITY_VERSION,
            generated_at: 1_000_000,
            entries: entries
                .into_iter()
                .map(|(tag, legs)| EntryPathQuality {
                    relay_id: hex::encode([tag; 16]),
                    legs,
                })
                .collect(),
        }
    }

    const NOW: u64 = 1_000_000;

    fn no_rtt(_: &NodeEntry) -> Option<u32> {
        None
    }

    #[test]
    fn advisory_roundtrips_and_tolerates_unknown_fields() {
        let adv = advisory_for(vec![(1, vec![leg(2, 30, false, NOW)])]);
        let json = serde_json::to_string(&adv).unwrap();
        let back: PathQualityAdvisory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, adv);

        let with_unknown = json.replacen("{", "{\"future_field\":42,", 1).replacen(
            "\"rtt_ms\"",
            "\"future_leg_field\":true,\"rtt_ms\"",
            1,
        );
        let tolerant: PathQualityAdvisory = serde_json::from_str(&with_unknown).unwrap();
        assert_eq!(tolerant, adv);
    }

    #[test]
    fn advisory_leg_lookup_matches_ids_case_insensitively() {
        let mut adv = advisory_for(vec![(0xab, vec![leg(0xcd, 25, false, NOW)])]);
        adv.entries[0].relay_id = adv.entries[0].relay_id.to_uppercase();
        adv.entries[0].legs[0].exit_id = adv.entries[0].legs[0].exit_id.to_uppercase();

        let found = adv.leg(&[0xab; 16], &[0xcd; 16]).unwrap();
        assert_eq!(found.rtt_ms, 25);
        assert!(adv.leg(&[0xab; 16], &[0xee; 16]).is_none());
        assert!(adv.leg(&[0xee; 16], &[0xcd; 16]).is_none());
    }

    #[test]
    fn weight_pick_takes_highest_product_with_id_tie_break() {
        let d = dir(vec![
            node(1, "DE", 100),
            node(2, "NL", 300),
            node(3, "SG", 100),
        ]);
        let pairs = vec![(0, 1), (0, 2), (2, 1), (2, 0)];
        // (0,1) and (2,1) tie at 100*300; entry relay_id [1;16] < [3;16].
        assert_eq!(pick_circuit_by_weight(&d, &pairs), Some((0, 1)));
    }

    #[test]
    fn weight_pick_empty_pairs_is_none() {
        let d = dir(vec![node(1, "DE", 100)]);
        assert_eq!(pick_circuit_by_weight(&d, &[]), None);
    }

    #[test]
    fn no_signal_selection_equals_weight_pick() {
        for weights in [
            [100, 100, 100],
            [1, 500, 20],
            [0, 0, 0],
            [7, 7, 900],
            [u64::MAX, 2, 3],
        ] {
            let d = dir(vec![
                node(1, "DE", weights[0]),
                node(2, "NL", weights[1]),
                node(3, "SG", weights[2]),
            ]);
            let pairs: Vec<(usize, usize)> = (0..3)
                .flat_map(|i| (0..3).filter(move |&j| j != i).map(move |j| (i, j)))
                .collect();
            assert_eq!(
                select_circuit_path_aware(
                    &d,
                    &pairs,
                    None,
                    no_rtt,
                    NOW,
                    None,
                    &PathAwareParams::default(),
                ),
                pick_circuit_by_weight(&d, &pairs),
                "weights {weights:?}"
            );
        }
    }

    #[test]
    fn fresh_low_rtt_leg_beats_high_rtt_leg() {
        // Two candidate entries toward the same exit, equal weight: the
        // measured 11 ms leg (Falkenstein-class) must beat the measured
        // 290 ms leg (sick-Helsinki-class) even though ids favor the sick
        // one on tie-break.
        let d = dir(vec![
            node(1, "FI", 100),
            node(2, "DE", 100),
            node(3, "NL", 100),
        ]);
        let pairs = vec![(0, 2), (1, 2)];
        let adv = advisory_for(vec![
            (1, vec![leg(3, 290, false, NOW)]),
            (2, vec![leg(3, 11, false, NOW)]),
        ]);
        assert_eq!(
            select_circuit_path_aware(
                &d,
                &pairs,
                Some(&adv),
                no_rtt,
                NOW,
                None,
                &PathAwareParams::default(),
            ),
            Some((1, 2))
        );
    }

    #[test]
    fn degraded_leg_is_penalized_below_healthy_alternative() {
        // The degraded leg has the LOWER smoothed RTT: without the penalty
        // it would win. The latch must push it below the healthy leg.
        let d = dir(vec![
            node(1, "FI", 100),
            node(2, "DE", 100),
            node(3, "NL", 100),
        ]);
        let pairs = vec![(0, 2), (1, 2)];
        let adv = advisory_for(vec![
            (1, vec![leg(3, 10, true, NOW)]),
            (2, vec![leg(3, 60, false, NOW)]),
        ]);
        assert_eq!(
            select_circuit_path_aware(
                &d,
                &pairs,
                Some(&adv),
                no_rtt,
                NOW,
                None,
                &PathAwareParams::default(),
            ),
            Some((1, 2))
        );
    }

    #[test]
    fn stale_leg_sample_falls_back_to_neutral() {
        // The 11 ms sample is stale: both pairs are neutral, so the pick
        // must equal the weight-only pick (tie-break on entry id).
        let d = dir(vec![
            node(1, "FI", 100),
            node(2, "DE", 100),
            node(3, "NL", 100),
        ]);
        let pairs = vec![(0, 2), (1, 2)];
        let stale = NOW - PathAwareParams::default().stale_after_secs - 1;
        let adv = advisory_for(vec![(2, vec![leg(3, 11, false, stale)])]);
        assert_eq!(
            select_circuit_path_aware(
                &d,
                &pairs,
                Some(&adv),
                no_rtt,
                NOW,
                None,
                &PathAwareParams::default(),
            ),
            pick_circuit_by_weight(&d, &pairs)
        );
    }

    #[test]
    fn client_measured_entry_rtt_biases_entry_choice() {
        let d = dir(vec![
            node(1, "FI", 100),
            node(2, "DE", 100),
            node(3, "NL", 100),
        ]);
        let pairs = vec![(0, 2), (1, 2)];
        // Client measured: 200 ms to entry 1, 15 ms to entry 2.
        let rtt = |n: &NodeEntry| -> Option<u32> {
            match n.relay.relay_id[0] {
                1 => Some(200),
                2 => Some(15),
                _ => None,
            }
        };
        assert_eq!(
            select_circuit_path_aware(
                &d,
                &pairs,
                None,
                rtt,
                NOW,
                None,
                &PathAwareParams::default(),
            ),
            Some((1, 2))
        );
    }

    #[test]
    fn unknown_data_stays_neutral_between_measured_extremes() {
        let d = dir(vec![
            node(1, "FI", 100),
            node(2, "DE", 100),
            node(3, "NL", 100),
        ]);
        let pairs = vec![(0, 2), (1, 2)];
        // Measured fast (10 ms) beats unknown ...
        let fast_on_2 = |n: &NodeEntry| (n.relay.relay_id[0] == 2).then_some(10);
        assert_eq!(
            select_circuit_path_aware(
                &d,
                &pairs,
                None,
                fast_on_2,
                NOW,
                None,
                &PathAwareParams::default(),
            ),
            Some((1, 2))
        );
        // ... and measured slow (200 ms) loses to unknown.
        let slow_on_1 = |n: &NodeEntry| (n.relay.relay_id[0] == 1).then_some(200);
        assert_eq!(
            select_circuit_path_aware(
                &d,
                &pairs,
                None,
                slow_on_1,
                NOW,
                None,
                &PathAwareParams::default(),
            ),
            Some((1, 2))
        );
    }

    #[test]
    fn hysteresis_keeps_previous_circuit_within_margin() {
        // Challenger (1,2) scores better than incumbent (0,2) but by less
        // than the 25% margin: keep the incumbent.
        let d = dir(vec![
            node(1, "FI", 100),
            node(2, "DE", 100),
            node(3, "NL", 100),
        ]);
        let pairs = vec![(0, 2), (1, 2)];
        let adv = advisory_for(vec![
            (1, vec![leg(3, 60, false, NOW)]),
            (2, vec![leg(3, 45, false, NOW)]),
        ]);
        assert_eq!(
            select_circuit_path_aware(
                &d,
                &pairs,
                Some(&adv),
                no_rtt,
                NOW,
                Some(([1; 16], [3; 16])),
                &PathAwareParams::default(),
            ),
            Some((0, 2))
        );
    }

    #[test]
    fn hysteresis_switches_when_margin_exceeded() {
        let d = dir(vec![
            node(1, "FI", 100),
            node(2, "DE", 100),
            node(3, "NL", 100),
        ]);
        let pairs = vec![(0, 2), (1, 2)];
        let adv = advisory_for(vec![
            (1, vec![leg(3, 290, false, NOW)]),
            (2, vec![leg(3, 11, false, NOW)]),
        ]);
        assert_eq!(
            select_circuit_path_aware(
                &d,
                &pairs,
                Some(&adv),
                no_rtt,
                NOW,
                Some(([1; 16], [3; 16])),
                &PathAwareParams::default(),
            ),
            Some((1, 2))
        );
    }

    #[test]
    fn hysteresis_abandons_degraded_previous() {
        // Incumbent's leg went degraded: no retention, even though the
        // challenger's advantage is within the margin.
        let d = dir(vec![
            node(1, "FI", 100),
            node(2, "DE", 100),
            node(3, "NL", 100),
        ]);
        let pairs = vec![(0, 2), (1, 2)];
        let adv = advisory_for(vec![
            (1, vec![leg(3, 60, true, NOW)]),
            (2, vec![leg(3, 60, false, NOW)]),
        ]);
        assert_eq!(
            select_circuit_path_aware(
                &d,
                &pairs,
                Some(&adv),
                no_rtt,
                NOW,
                Some(([1; 16], [3; 16])),
                &PathAwareParams::default(),
            ),
            Some((1, 2))
        );
    }

    #[test]
    fn entry_selection_gates_by_policy_and_prefers_low_rtt_leg() {
        // Node 3 (NL) is the chosen exit. Node 4 (NL) has a dream leg but
        // shares the exit's country; node 3 itself is the same node: both
        // must be policy-excluded. Between FI and DE, the measured 11 ms
        // leg must beat the 290 ms one.
        let d = dir(vec![
            node(1, "FI", 100),
            node(2, "DE", 100),
            node(3, "NL", 100),
            node(4, "NL", 100),
        ]);
        let entries = d.entries();
        let exits = d.exits();
        let policy = super::super::multihop_directory::CircuitPolicy::for_directory(&d);
        let exit = &exits[2];
        let adv = advisory_for(vec![
            (1, vec![leg(3, 290, false, NOW)]),
            (2, vec![leg(3, 11, false, NOW)]),
            (4, vec![leg(3, 1, false, NOW)]),
        ]);
        let picked = select_entry_path_aware(
            &entries,
            exit,
            &policy,
            Some(&adv),
            |_| None,
            NOW,
            None,
            &PathAwareParams::default(),
        )
        .unwrap();
        assert_eq!(picked.exit_id, [2; 16]);
    }

    #[test]
    fn entry_selection_without_signal_takes_highest_weight_then_id() {
        let d = dir(vec![
            node(1, "FI", 100),
            node(2, "DE", 500),
            node(3, "NL", 100),
        ]);
        let entries = d.entries();
        let exits = d.exits();
        let policy = super::super::multihop_directory::CircuitPolicy::for_directory(&d);
        let picked = select_entry_path_aware(
            &entries,
            &exits[2],
            &policy,
            None,
            |_| None,
            NOW,
            None,
            &PathAwareParams::default(),
        )
        .unwrap();
        assert_eq!(picked.exit_id, [2; 16], "highest weight wins");

        let d_tie = dir(vec![
            node(1, "FI", 100),
            node(2, "DE", 100),
            node(3, "NL", 100),
        ]);
        let entries_tie = d_tie.entries();
        let exits_tie = d_tie.exits();
        let picked_tie = select_entry_path_aware(
            &entries_tie,
            &exits_tie[2],
            &policy,
            None,
            |_| None,
            NOW,
            None,
            &PathAwareParams::default(),
        )
        .unwrap();
        assert_eq!(picked_tie.exit_id, [1; 16], "ties break on ascending id");
    }

    #[test]
    fn entry_selection_hysteresis_keeps_previous_within_margin() {
        let d = dir(vec![
            node(1, "FI", 100),
            node(2, "DE", 100),
            node(3, "NL", 100),
        ]);
        let entries = d.entries();
        let exits = d.exits();
        let policy = super::super::multihop_directory::CircuitPolicy::for_directory(&d);
        let adv = advisory_for(vec![
            (1, vec![leg(3, 60, false, NOW)]),
            (2, vec![leg(3, 45, false, NOW)]),
        ]);
        let kept = select_entry_path_aware(
            &entries,
            &exits[2],
            &policy,
            Some(&adv),
            |_| None,
            NOW,
            Some(&[1; 16]),
            &PathAwareParams::default(),
        )
        .unwrap();
        assert_eq!(
            kept.exit_id, [1; 16],
            "within-margin challenger is held off"
        );

        let adv_bad = advisory_for(vec![
            (1, vec![leg(3, 290, false, NOW)]),
            (2, vec![leg(3, 11, false, NOW)]),
        ]);
        let switched = select_entry_path_aware(
            &entries,
            &exits[2],
            &policy,
            Some(&adv_bad),
            |_| None,
            NOW,
            Some(&[1; 16]),
            &PathAwareParams::default(),
        )
        .unwrap();
        assert_eq!(switched.exit_id, [2; 16], "beyond-margin challenger wins");
    }

    #[test]
    fn hysteresis_ignores_vanished_previous() {
        let d = dir(vec![
            node(1, "FI", 100),
            node(2, "DE", 100),
            node(3, "NL", 100),
        ]);
        let pairs = vec![(1, 2)];
        assert_eq!(
            select_circuit_path_aware(
                &d,
                &pairs,
                None,
                no_rtt,
                NOW,
                Some(([1; 16], [3; 16])),
                &PathAwareParams::default(),
            ),
            Some((1, 2))
        );
    }
}
