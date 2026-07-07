//! Warren client<->server contract: the single source of truth the client SDK
//! and the backend both depend on, so the wire contract cannot drift.
//!
//! - [`ss58`]: wallet-identity address codec (Warren prefix `13295`, `wb…`).
//! - [`auth`]: the `X-Warren-*` request-signing rule (header names,
//!   canonical message, client-side signer).
//! - [`dto`]: the HTTP `/v1` API request/response types.
//! - [`release`]: the offline-signed exit-release manifest (fleet update
//!   authority).
//!
//! The `warren-discovery` workspace member (crate `warren-discovery-core`)
//! carries the signed relay list / roster / multi-hop directory formats and
//! the relay selector.

pub mod auth;
pub mod dto;
pub mod release;
pub mod ss58;

/// Redacts an untrusted input for error display: at most the first 8
/// chars, then an ellipsis. No-log discipline: a value that failed
/// validation can be identity material (pubkey, address) or a mispasted
/// secret, so an error message must never echo it in full.
#[must_use]
pub fn redact(s: &str) -> String {
    const KEEP: usize = 8;
    if s.chars().count() <= KEEP {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(KEEP).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::redact;

    #[test]
    fn redact_keeps_short_values_intact() {
        assert_eq!(redact("wb"), "wb");
        assert_eq!(redact("12345678"), "12345678");
    }

    #[test]
    fn redact_truncates_long_values_to_a_prefix() {
        assert_eq!(redact("123456789"), "12345678…");
        let key = "a".repeat(64);
        assert_eq!(redact(&key), format!("{}…", "a".repeat(8)));
    }
}
