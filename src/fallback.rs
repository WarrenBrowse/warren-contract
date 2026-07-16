//! Anti-censorship HTTP fallback: the canonical order in which a client
//! re-attempts a blocked control-plane request across hosts and SNI settings.
//!
//! When the primary API host is unreachable (a connect-level failure, the shape
//! of an on-path block), a client retries the same request against alternative
//! hosts and finally without SNI, so a censor that filters on the primary
//! hostname or on the SNI it sees is defeated. The engine (`warren-api-client`),
//! the Rust SDK and the TypeScript stack each grew their own attempt sequence
//! and they diverged (the SDK also tried alternatives without SNI, a fourth
//! step the production client never had). The sequence is a cross-language
//! behavior contract, so it is fixed here once, CORE-FIRST from the production
//! `warren-api-client`. The transports stay per-stack; only the order is shared.

use serde::{Deserialize, Serialize};

/// One connection attempt in the fallback sequence: which host to dial and
/// whether TLS SNI is sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackCandidate {
    /// Host to dial for this attempt.
    pub host: String,
    /// Whether the TLS ClientHello carries an SNI extension. The final no-SNI
    /// attempt defeats SNI-based blocking; it requires a server certificate
    /// accepted for the primary name even though no SNI is offered.
    pub sni: bool,
}

impl FallbackCandidate {
    fn new(host: &str, sni: bool) -> Self {
        Self {
            host: host.to_owned(),
            sni,
        }
    }
}

/// Builds the canonical anti-censorship attempt sequence for a control-plane
/// request:
///
/// 1. primary host, SNI on
/// 2. each alternative host in order, SNI on
/// 3. primary host, SNI off
///
/// The client tries them in order and stops at the first that connects; when
/// every attempt fails at connect time it reports all hosts blocked. The
/// divergent four-step variant (alternatives without SNI) is intentionally NOT
/// produced: without a certificate valid for the alternative names under no
/// SNI it cannot succeed, and it only widens the request fan-out.
#[must_use]
pub fn fallback_candidates(
    primary_host: &str,
    alternative_hosts: &[String],
) -> Vec<FallbackCandidate> {
    let mut out = Vec::with_capacity(2 + alternative_hosts.len());
    out.push(FallbackCandidate::new(primary_host, true));
    for host in alternative_hosts {
        out.push(FallbackCandidate::new(host, true));
    }
    out.push(FallbackCandidate::new(primary_host, false));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_alternatives_the_sequence_is_primary_sni_then_primary_no_sni() {
        let seq = fallback_candidates("api.example.com", &[]);
        assert_eq!(
            seq,
            vec![
                FallbackCandidate::new("api.example.com", true),
                FallbackCandidate::new("api.example.com", false),
            ]
        );
    }

    #[test]
    fn alternatives_come_after_primary_sni_and_before_primary_no_sni() {
        let alts = ["alt1.example.net".to_owned(), "alt2.example.org".to_owned()];
        let seq = fallback_candidates("api.example.com", &alts);
        assert_eq!(
            seq,
            vec![
                FallbackCandidate::new("api.example.com", true),
                FallbackCandidate::new("alt1.example.net", true),
                FallbackCandidate::new("alt2.example.org", true),
                FallbackCandidate::new("api.example.com", false),
            ],
            "the canonical order is primary+SNI, each alt+SNI, then primary no-SNI"
        );
    }

    #[test]
    fn no_sni_is_only_ever_attempted_against_the_primary_host() {
        // Pins the CORE-FIRST 3-step shape against the divergent 4-step SDK
        // variant: an alternative host must never appear without SNI.
        let alts = ["alt1.example.net".to_owned(), "alt2.example.org".to_owned()];
        let seq = fallback_candidates("api.example.com", &alts);
        for candidate in seq.iter().filter(|c| !c.sni) {
            assert_eq!(
                candidate.host, "api.example.com",
                "no-SNI must only be tried against the primary host"
            );
        }
        assert_eq!(
            seq.last(),
            Some(&FallbackCandidate::new("api.example.com", false)),
            "the sequence ends with the primary host without SNI"
        );
    }
}
