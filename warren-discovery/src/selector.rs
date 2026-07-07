//! Warren relay selector.

use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::{Rng, RngExt};
use thiserror::Error;

use crate::{WarrenRelay, WarrenRelayList, WarrenRelayQuery};

/// Errors returned by [`WarrenRelaySelector::select`].
#[derive(Debug, Error)]
pub enum SelectorError {
    /// No active relay satisfies all query constraints (location,
    /// ip_availability, weight > 0, ...).
    #[error("no relay matches the query constraints")]
    NoRelayMatch,
}

/// Selects a [`WarrenRelay`] from a [`WarrenRelayList`] based on the
/// constraints of a [`WarrenRelayQuery`].
#[derive(Debug, Clone)]
pub struct WarrenRelaySelector {
    relays: WarrenRelayList,
}

impl WarrenRelaySelector {
    /// Builds a selector from a `WarrenRelayList`.
    #[must_use]
    pub fn new(relays: WarrenRelayList) -> Self {
        Self { relays }
    }

    /// Deterministically selects the first matching relay.
    ///
    /// Convenient for tests and cases where weighting is not required.
    /// For weighted selection by `weight`, use
    /// [`Self::select_with_rng`]. Unlike the weighted path, a `weight == 0`
    /// relay stays eligible here: this method never consults `weight`.
    ///
    /// # Errors
    ///
    /// Returns [`SelectorError::NoRelayMatch`] if no active relay
    /// satisfies every query constraint.
    pub fn select(&self, query: &WarrenRelayQuery) -> Result<&WarrenRelay, SelectorError> {
        self.relays
            .relays()
            .iter()
            .find(|relay| query.matches(relay))
            .ok_or(SelectorError::NoRelayMatch)
    }

    /// Selects a relay matching the query, weighted by `weight`.
    ///
    /// Draws a relay among the active candidates matching `query`,
    /// with probability proportional to its `weight`. Relays with
    /// `weight == 0` are excluded from selection even if active and
    /// matching.
    ///
    /// # Errors
    ///
    /// Returns [`SelectorError::NoRelayMatch`] if no active relay
    /// with `weight > 0` satisfies the query constraints.
    ///
    /// # Panics
    ///
    /// Never panics in practice: the early `candidates.is_empty()` check
    /// guarantees `weighted_pick`'s non-empty precondition, and the
    /// `weight > 0` filter guarantees `total_weight > 0`. The internal
    /// `unreachable!()` inside `weighted_pick` is defensive only.
    pub fn select_with_rng<R: Rng + ?Sized>(
        &self,
        query: &WarrenRelayQuery,
        rng: &mut R,
    ) -> Result<&WarrenRelay, SelectorError> {
        let candidates: Vec<&WarrenRelay> = self
            .relays
            .relays()
            .iter()
            .filter(|relay| relay.weight() > 0 && query.matches(relay))
            .collect();

        if candidates.is_empty() {
            return Err(SelectorError::NoRelayMatch);
        }

        // Delegate to the single weighting implementation so the
        // distribution (and any future overflow/precision fix) lives in
        // exactly one place, shared with the failover path.
        Ok(weighted_pick(&candidates, rng))
    }

    /// Selects a relay for a given retry attempt.
    ///
    /// The `retry_attempt` acts as a deterministic seed: the same
    /// attempt always returns the same relay (idempotent), successive
    /// attempts explore the relay space according to the weights.
    ///
    /// API mirrors Mullvad's `RelaySelector::get_relay(retry_attempt,
    /// …)` - eases integration with
    /// `mullvad-daemon::ParametersGenerator`.
    ///
    /// # Errors
    ///
    /// Returns [`SelectorError::NoRelayMatch`] if no active relay
    /// with `weight > 0` satisfies the query constraints.
    pub fn select_for_attempt(
        &self,
        query: &WarrenRelayQuery,
        retry_attempt: u32,
    ) -> Result<&WarrenRelay, SelectorError> {
        let mut rng = StdRng::seed_from_u64(u64::from(retry_attempt));
        self.select_with_rng(query, &mut rng)
    }

    /// Convenience over [`Self::select_failover_alternative`] that
    /// seeds the random pick from the `retry_attempt` counter, so the
    /// caller doesn't need to thread a rand crate through the call
    /// site (avoids cross-workspace `rand 0.9 vs 0.10` mismatches when
    /// called from `mullvad-daemon`).
    ///
    /// Behaviour is otherwise identical: same-country preference,
    /// global fallback when needed, excluded relay skipped.
    ///
    /// # Errors
    ///
    /// See [`Self::select_failover_alternative`].
    pub fn select_failover_alternative_for_attempt(
        &self,
        query: &WarrenRelayQuery,
        excluded: &WarrenRelay,
        retry_attempt: u32,
    ) -> Result<&WarrenRelay, SelectorError> {
        let mut rng = StdRng::seed_from_u64(u64::from(retry_attempt));
        self.select_failover_alternative(query, excluded, &mut rng)
    }

    /// Selects a failover alternative when the current exit has
    /// become unreachable (auto-failover).
    ///
    /// Two-stage policy:
    ///
    /// 1. **Same-country preference**: filter out `excluded_pubkey`
    ///    and try a weighted pick over relays whose
    ///    [`crate::Location::country_code`] matches the current
    ///    relay's. If at least one such relay exists, return it.
    /// 2. **Global fallback**: if no same-country alternative is
    ///    available, fall back to a weighted pick across *all*
    ///    relays satisfying `query`, still excluding
    ///    `excluded_pubkey`. The caller is expected to surface a UI
    ///    warning ("switched to a server in a different country")
    ///    when the returned relay's country differs from the
    ///    excluded one's.
    ///
    /// The function never returns the excluded relay itself, even
    /// when it is the only match.
    ///
    /// # Errors
    ///
    /// Returns [`SelectorError::NoRelayMatch`] if no eligible
    /// alternative relay exists.
    pub fn select_failover_alternative<R: Rng + ?Sized>(
        &self,
        query: &WarrenRelayQuery,
        excluded: &WarrenRelay,
        rng: &mut R,
    ) -> Result<&WarrenRelay, SelectorError> {
        // Stage 1: same-country preference (excludes current relay).
        let same_country: Vec<&WarrenRelay> = self
            .relays
            .relays()
            .iter()
            .filter(|r| r.endpoint_id() != excluded.endpoint_id())
            .filter(|r| {
                r.location().country_code() == excluded.location().country_code()
                    && r.weight() > 0
                    && query.matches(r)
            })
            .collect();
        if !same_country.is_empty() {
            return Ok(weighted_pick(&same_country, rng));
        }

        // Stage 2: global fallback (any country), still excluding the
        // failed exit's pubkey.
        let global: Vec<&WarrenRelay> = self
            .relays
            .relays()
            .iter()
            .filter(|r| r.endpoint_id() != excluded.endpoint_id())
            .filter(|r| r.weight() > 0 && query.matches(r))
            .collect();
        if global.is_empty() {
            return Err(SelectorError::NoRelayMatch);
        }
        Ok(weighted_pick(&global, rng))
    }
}

/// Weighted random pick over a non-empty candidate slice, shared by
/// [`WarrenRelaySelector::select_with_rng`] and the failover path.
///
/// # Panics
///
/// Panics if `candidates` is empty (caller's invariant). The internal
/// `unreachable!` covers the byzantine case of `sum(weights) <= roll`,
/// which is statically impossible.
fn weighted_pick<'a, R: Rng + ?Sized>(
    candidates: &[&'a WarrenRelay],
    rng: &mut R,
) -> &'a WarrenRelay {
    assert!(
        !candidates.is_empty(),
        "weighted_pick MUST be called with at least one candidate"
    );
    // `weight` is untrusted wire data (u64): summing in u64 can overflow
    // (two relays near u64::MAX) which panics in debug and, in release,
    // can wrap to a total of 0 and make `random_range(0..0)` panic. u128
    // cannot overflow for any combination of u64 weights.
    let total_weight: u128 = candidates.iter().map(|r| u128::from(r.weight())).sum();
    let mut roll = rng.random_range(0..total_weight);
    for relay in candidates {
        let w = u128::from(relay.weight());
        if roll < w {
            return relay;
        }
        roll -= w;
    }
    unreachable!("weighted_pick invariant violated: sum(weights) <= roll");
}

#[cfg(test)]
mod tests {
    use warrenguard_wire::{ExitId, WarrenPubkey};

    use super::*;
    use crate::{Addr, Ingress, Listener, Location};

    fn relay(seed: u8, weight: u64) -> WarrenRelay {
        WarrenRelay::from_public(
            WarrenPubkey::from_bytes([seed; 32]),
            ExitId::from_bytes([seed; 16]),
            Location::new("fr", "Paris"),
            weight,
            true,
            vec![Ingress::new(
                Addr::new("1.2.3.4".parse().unwrap(), None),
                vec![Listener::new(443, "quic", "h3")],
            )],
            true,
            false,
        )
    }

    #[test]
    fn weighted_pick_does_not_panic_on_u64_max_weight_sum() {
        // Regression: two relays at u64::MAX overflow a u64 weight sum
        // (debug panic; release wraps and can make random_range(0..0)
        // panic). Must draw a valid pick instead.
        let list = WarrenRelayList::new(vec![relay(1, u64::MAX), relay(2, u64::MAX)]);
        let selector = WarrenRelaySelector::new(list);
        let mut rng = StdRng::seed_from_u64(0);
        let picked = selector
            .select_with_rng(&WarrenRelayQuery::any(), &mut rng)
            .expect("a weighted pick must succeed without overflow");
        assert!(
            picked.exit_id() == ExitId::from_bytes([1; 16])
                || picked.exit_id() == ExitId::from_bytes([2; 16]),
            "pick must be one of the two candidates"
        );
    }
}
