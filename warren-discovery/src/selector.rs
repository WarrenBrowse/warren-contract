//! Warren relay selector.

use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::{Rng, RngExt};

use crate::{SelectorError, WarrenRelay, WarrenRelayList, WarrenRelayQuery};

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
    /// [`Self::select_with_rng`].
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
    /// guarantees [`weighted_pick`]'s non-empty precondition, and the
    /// `weight > 0` filter guarantees `total_weight > 0`. The internal
    /// `unreachable!()` inside [`weighted_pick`] is defensive only.
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

/// Weighted random pick over a non-empty candidate slice.
///
/// Pulled out of [`WarrenRelaySelector::select_with_rng`] so the
/// failover path can reuse the same weighting logic without
/// duplicating the loop.
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
    let total_weight: u64 = candidates.iter().map(|r| r.weight()).sum();
    let mut roll = rng.random_range(0..total_weight);
    for relay in candidates {
        if roll < relay.weight() {
            return relay;
        }
        roll -= relay.weight();
    }
    unreachable!("weighted_pick invariant violated: sum(weights) <= roll");
}
