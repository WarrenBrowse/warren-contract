//! The `X-Warren-*` request-signing rule: the header names and the canonical
//! message that the client signs and the server verifies. Defined once here so
//! the two sides cannot drift (a mismatch makes every signature fail).

/// SS58 address (`wb…`) of the signing wallet.
pub const HEADER_PUBKEY: &str = "X-Warren-PubKey";
/// Ed25519 signature of [`canonical_message`], 128 hex chars.
pub const HEADER_SIGNATURE: &str = "X-Warren-Sig";
/// Unix epoch-seconds the message was built with.
pub const HEADER_TIMESTAMP: &str = "X-Warren-Timestamp";
/// Per-request random nonce (hex), anti-replay.
pub const HEADER_NONCE: &str = "X-Warren-Nonce";

/// Builds the canonical message that is signed and verified.
///
/// Format frozen: never change without rotating to `/v2`. Must stay strictly
/// identical on both sides, otherwise no signature verifies.
#[must_use]
pub fn canonical_message(
    method: &str,
    path: &str,
    timestamp: u64,
    nonce_hex: &str,
    body_hash_hex: &str,
) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(
        method.len() + path.len() + 20 + nonce_hex.len() + body_hash_hex.len() + 4,
    );
    s.push_str(method);
    s.push('\n');
    s.push_str(path);
    s.push('\n');
    write!(&mut s, "{timestamp}").expect("write to String is infallible");
    s.push('\n');
    s.push_str(nonce_hex);
    s.push('\n');
    s.push_str(body_hash_hex);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_message_is_byte_stable() {
        assert_eq!(
            canonical_message("GET", "/v1/exits", 42, "abcd1234", "ff00"),
            "GET\n/v1/exits\n42\nabcd1234\nff00"
        );
    }
}
