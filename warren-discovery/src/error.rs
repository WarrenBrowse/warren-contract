//! `warren-relay-selector` errors.

use thiserror::Error;

/// Errors returned by [`crate::WarrenRelaySelector::select`].
#[derive(Debug, Error)]
pub enum SelectorError {
    /// No active relay satisfies all query constraints (location,
    /// ip_availability, weight > 0, ...).
    #[error("no relay matches the query constraints")]
    NoRelayMatch,
}
