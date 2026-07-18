//! Client-side entry-RTT store: the client-measured half of the path-aware
//! selection signal, single-homed next to its consumer
//! ([`crate::select_entry_path_aware`] / [`crate::select_circuit_path_aware`]).
//!
//! Promoted from the SDK proximity cache (doc 52 §6.2 client) so every
//! consumer (app daemon, SDK, bindings) shares ONE measurement store, ONE
//! staleness rule, and ONE endpoint keying. Feeding is transport-only: the
//! tunnel layer reports `(entry pubkey, rtt_ms)` at connection lifecycle
//! points (post-handshake, close) and the embedder records it here; each fed
//! sample is already smoothed by the transport (quinn srtt), so this store
//! only blends across sessions.
//!
//! Design invariants:
//! - **Zero data == today.** An entry with no fresh sample reads as `None`,
//!   which the selector scores at its neutral baseline, so an empty store
//!   yields exactly the weight-only selection.
//! - **Never excludes.** The store only biases ordering; a missing or bad
//!   RTT can never remove a directory-verified candidate.
//! - **Pure and time-injected.** No clock is read here; the caller passes
//!   `now_unix_secs`, so the cache is deterministically testable.

use std::collections::HashMap;

/// The stable identity keying measurements: the node's Ed25519 endpoint
/// pubkey (the multihop directory's `relay_ed25519_pubkey`, equal to the
/// circuit view's dialed first-hop pubkey), so a measurement taken on any
/// dial path keys the same node and survives an endpoint-address change.
pub type EndpointId = [u8; 32];

/// Default freshness window for a measured RTT (24 h), matching the doc's
/// per-exit local cache TTL of 24 h. Also the blend window of
/// [`RttCache::record`]: one TTL is the single staleness notion.
pub const DEFAULT_RTT_TTL_SECS: u64 = 24 * 60 * 60;

/// One smoothed round-trip time toward an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RttSample {
    rtt_ms: u32,
    measured_at_unix: u64,
}

/// Per-endpoint store of the smoothed measured RTT, with TTL expiry.
///
/// Populated by the tunnel layer after a handshake completes and when a
/// session closes; read by the selectors. Process-lifetime: no persistence.
#[derive(Debug, Clone, Default)]
pub struct RttCache {
    samples: HashMap<EndpointId, RttSample>,
}

impl RttCache {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the RTT measured to `endpoint_id` at `now_unix_secs`. A fresh
    /// previous sample (within [`DEFAULT_RTT_TTL_SECS`], the store's one
    /// staleness notion) is EWMA-blended by integer midpoint, so a single
    /// outlier connection moves the stored value halfway, never all the
    /// way; a stale or absent previous sample is replaced outright.
    pub fn record(&mut self, endpoint_id: EndpointId, rtt_ms: u32, now_unix_secs: u64) {
        let smoothed = self
            .fresh_rtt_ms(endpoint_id, now_unix_secs, DEFAULT_RTT_TTL_SECS)
            .map_or(rtt_ms, |prev| prev.midpoint(rtt_ms));
        self.samples.insert(
            endpoint_id,
            RttSample {
                rtt_ms: smoothed,
                measured_at_unix: now_unix_secs,
            },
        );
    }

    /// Fresh RTT for `endpoint_id`: the sample if it was measured within
    /// `ttl_secs` of `now_unix_secs`, else `None` (stale or never
    /// measured). Does not mutate; expiry is evaluated at read time.
    #[must_use]
    pub fn fresh_rtt_ms(
        &self,
        endpoint_id: EndpointId,
        now_unix_secs: u64,
        ttl_secs: u64,
    ) -> Option<u32> {
        self.samples.get(&endpoint_id).and_then(|s| {
            let age = now_unix_secs.saturating_sub(s.measured_at_unix);
            (age < ttl_secs).then_some(s.rtt_ms)
        })
    }

    /// Drop samples older than `ttl_secs` relative to `now_unix_secs`.
    /// Optional housekeeping; `fresh_rtt_ms` already ignores stale ones.
    pub fn prune(&mut self, now_unix_secs: u64, ttl_secs: u64) {
        self.samples
            .retain(|_, s| now_unix_secs.saturating_sub(s.measured_at_unix) < ttl_secs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eid(b: u8) -> EndpointId {
        [b; 32]
    }

    #[test]
    fn cache_returns_fresh_sample_and_expires_stale_one() {
        let mut cache = RttCache::new();
        cache.record(eid(1), 42, 1_000);
        assert_eq!(
            cache.fresh_rtt_ms(
                eid(1),
                1_000 + DEFAULT_RTT_TTL_SECS - 1,
                DEFAULT_RTT_TTL_SECS
            ),
            Some(42)
        );
        assert_eq!(
            cache.fresh_rtt_ms(eid(1), 1_000 + DEFAULT_RTT_TTL_SECS, DEFAULT_RTT_TTL_SECS),
            None
        );
        assert_eq!(
            cache.fresh_rtt_ms(eid(9), 1_000, DEFAULT_RTT_TTL_SECS),
            None
        );
    }

    #[test]
    fn repeat_measurement_within_ttl_smooths_toward_latest() {
        // Cross-session EWMA: a fresh previous sample is midpoint-blended,
        // so one outlier connection moves the stored value halfway, never
        // all the way.
        let mut cache = RttCache::new();
        cache.record(eid(1), 100, 1_000);
        cache.record(eid(1), 20, 1_050);
        assert_eq!(
            cache.fresh_rtt_ms(eid(1), 1_060, DEFAULT_RTT_TTL_SECS),
            Some(60)
        );
        cache.record(eid(1), 20, 1_100);
        assert_eq!(
            cache.fresh_rtt_ms(eid(1), 1_110, DEFAULT_RTT_TTL_SECS),
            Some(40),
            "repeated agreeing samples converge on the measured value"
        );
    }

    #[test]
    fn stale_previous_sample_is_replaced_not_blended() {
        // Past the TTL the old sample is dead data: blending it in would
        // resurrect it past its own staleness rule.
        let mut cache = RttCache::new();
        cache.record(eid(1), 100, 1_000);
        cache.record(eid(1), 20, 1_000 + DEFAULT_RTT_TTL_SECS);
        assert_eq!(
            cache.fresh_rtt_ms(
                eid(1),
                1_000 + DEFAULT_RTT_TTL_SECS + 1,
                DEFAULT_RTT_TTL_SECS
            ),
            Some(20)
        );
    }

    #[test]
    fn prune_drops_only_stale_samples() {
        let mut cache = RttCache::new();
        cache.record(eid(1), 10, 1_000);
        cache.record(eid(2), 10, 5_000);
        cache.prune(1_000 + DEFAULT_RTT_TTL_SECS, DEFAULT_RTT_TTL_SECS);
        assert_eq!(
            cache.fresh_rtt_ms(eid(1), 5_000, DEFAULT_RTT_TTL_SECS),
            None
        );
        assert_eq!(
            cache.fresh_rtt_ms(eid(2), 5_000, DEFAULT_RTT_TTL_SECS),
            Some(10)
        );
    }
}
