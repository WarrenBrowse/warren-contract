//! Warren client<->server contract: the single source of truth the client SDK
//! and the backend both depend on, so the wire contract cannot drift.
//!
//! - [`ss58`]: wallet-identity address codec (Warren prefix `13295`, `wb…`).
//! - [`dto`]: the HTTP `/v1` API request/response types.

pub mod dto;
pub mod ss58;
