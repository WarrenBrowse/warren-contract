//! Warren product / deployment anchors: the endpoints, the pinned keys, and the
//! single environment-variable name that overrides each one.
//!
//! Each of these is re-declared today across the app, iOS, the SDK family, the
//! TypeScript stack, the browser extension and the backend, and overridden by
//! several competing env-var names (`WARREN_API_URL` vs `WARREN_API_BASE`; four
//! different names for the server pin). A key rotation is therefore a
//! multi-repo edit where any missed copy fails closed. Declaring each anchor and
//! its ONE canonical override name here lets every consumer converge on a single
//! source of truth. The values are the production-proven ones the app already
//! ships; a generic deployer overrides them through the env names below.

/// Production Warren HTTP API base URL (the `/v1` control plane).
pub const API_URL: &str = "https://api.warrenbrowse.com";

/// The one environment variable that overrides [`API_URL`]. The Dart/TS/
/// extension stacks historically read `WARREN_API_BASE`; this is the canonical
/// name they converge on.
pub const API_URL_ENV: &str = "WARREN_API_URL";

/// Ed25519 public key (64-char lowercase hex) that signs the `SignedRelayList`
/// served at `GET {API_URL}/v1/exits`. Clients pin it when verifying the
/// fetched or baked relay list, rejecting a list signed by any other key, so a
/// compromised or impersonating API cannot substitute the exit set.
pub const SERVER_PUBKEY_HEX: &str =
    "4c2c9253c426ae4db4cc88703f9ac802a020420c7fea6479c87af530ada72c3e";

/// The one environment variable that overrides [`SERVER_PUBKEY_HEX`]. Supersedes
/// the historical `WARREN_API_SERVER_PUBKEY` / `WARREN_SERVER_PIN` /
/// `WARREN_SERVER_PUBKEY_PIN` spellings.
pub const SERVER_PUBKEY_HEX_ENV: &str = "WARREN_SERVER_PUBKEY_HEX";

/// Ed25519 public key (64-char lowercase hex) of the multi-hop directory
/// **root** trust anchor: the offline key at the head of the directory PKI
/// chain (root, operational, per-node). Clients pin it so a directory that does
/// not chain to the Warren root is rejected.
pub const MULTIHOP_ROOT_PUBKEY_HEX: &str =
    "33cd9279ad06d1ee884235e763b876fa70598094944bdcfb82375bd9aaa67b08";

/// The one environment variable that overrides [`MULTIHOP_ROOT_PUBKEY_HEX`]
/// (bench / key rotation). Supersedes the `WARREN_MULTIHOP_ROOT_PIN` spelling.
pub const MULTIHOP_ROOT_PUBKEY_ENV: &str = "WARREN_MULTIHOP_ROOT_PUBKEY";

/// Checkout / subscription-purchase site (warren-checkout). One home so a
/// client never sends the user to a stale `warrenbrowse.com/pricing` variant.
pub const CHECKOUT_URL: &str = "https://checkout.warrenbrowse.com/";

#[cfg(test)]
mod tests {
    use super::*;

    fn is_ed25519_pin(hex_str: &str) -> bool {
        hex_str.len() == 64
            && hex_str
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            && hex::decode(hex_str).map(|b| b.len()) == Ok(32)
    }

    #[test]
    fn pins_are_valid_ed25519_public_keys() {
        assert!(
            is_ed25519_pin(SERVER_PUBKEY_HEX),
            "server pin must be 32-byte lowercase hex (a rotation typo must not slip through)"
        );
        assert!(
            is_ed25519_pin(MULTIHOP_ROOT_PUBKEY_HEX),
            "multihop root pin must be 32-byte lowercase hex"
        );
    }

    #[test]
    fn urls_are_https() {
        for url in [API_URL, CHECKOUT_URL] {
            assert!(url.starts_with("https://"), "{url} must be https");
        }
    }

    #[test]
    fn override_env_names_are_the_single_canonical_spelling() {
        // Pins the one-name-per-anchor contract: a regression to a competing
        // spelling (e.g. WARREN_API_BASE) breaks this test on purpose.
        assert_eq!(API_URL_ENV, "WARREN_API_URL");
        assert_eq!(SERVER_PUBKEY_HEX_ENV, "WARREN_SERVER_PUBKEY_HEX");
        assert_eq!(MULTIHOP_ROOT_PUBKEY_ENV, "WARREN_MULTIHOP_ROOT_PUBKEY");
    }
}
