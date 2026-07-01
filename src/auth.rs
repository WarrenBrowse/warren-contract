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

/// A signed request's client-side authentication material, ready to attach as
/// the four `X-Warren-*` headers. Produced by [`sign_request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSignature {
    /// Signer pubkey as a Warren SS58 address (`wb…`).
    pub pubkey_ss58: String,
    /// Ed25519 signature of the canonical message, 128 hex chars (64 bytes).
    pub signature_hex: String,
    /// Unix epoch-seconds timestamp the canonical message was built with.
    pub timestamp: u64,
    /// Random 32-hex-char nonce (16 bytes).
    pub nonce_hex: String,
}

impl RequestSignature {
    /// The four `X-Warren-*` headers as `(name, value)` pairs, in a stable
    /// order, ready to be attached to an HTTP request.
    #[must_use]
    pub fn headers(&self) -> [(&'static str, String); 4] {
        [
            (HEADER_PUBKEY, self.pubkey_ss58.clone()),
            (HEADER_SIGNATURE, self.signature_hex.clone()),
            (HEADER_TIMESTAMP, self.timestamp.to_string()),
            (HEADER_NONCE, self.nonce_hex.clone()),
        ]
    }
}

/// Computes the client-side signature material for a Warren API request.
///
/// `timestamp`/`nonce` are inputs (not a clock/RNG) to stay deterministic and
/// FFI-friendly. Single definition, so the SDK and backend clients cannot drift.
#[must_use]
pub fn sign_request(
    signing_key: &ed25519_dalek::SigningKey,
    method: &str,
    path: &str,
    body: &[u8],
    timestamp: u64,
    nonce: [u8; 16],
) -> RequestSignature {
    use ed25519_dalek::Signer as _;
    use sha2::{Digest as _, Sha256};

    let nonce_hex = hex::encode(nonce);
    let body_hash_hex = hex::encode(Sha256::digest(body));
    let canonical = canonical_message(method, path, timestamp, &nonce_hex, &body_hash_hex);
    let signature_hex = hex::encode(signing_key.sign(canonical.as_bytes()).to_bytes());
    RequestSignature {
        pubkey_ss58: crate::ss58::encode(&signing_key.verifying_key().to_bytes()),
        signature_hex,
        timestamp,
        nonce_hex,
    }
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

    #[test]
    fn sign_request_signature_verifies_against_the_canonical_message() {
        use ed25519_dalek::{Signature, SigningKey, Verifier as _};

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let body = br#"{"voucher":"abc"}"#;
        let sig = sign_request(
            &key,
            "POST",
            "/v1/session/open",
            body,
            1_700_000_000,
            [0x11; 16],
        );

        assert_eq!(
            sig.pubkey_ss58,
            crate::ss58::encode(&key.verifying_key().to_bytes())
        );
        assert_eq!(sig.nonce_hex, "11".repeat(16));

        let body_hash_hex = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(body));
        let canonical = canonical_message(
            "POST",
            "/v1/session/open",
            sig.timestamp,
            &sig.nonce_hex,
            &body_hash_hex,
        );
        let signature = Signature::from_slice(&hex::decode(&sig.signature_hex).unwrap()).unwrap();
        key.verifying_key()
            .verify(canonical.as_bytes(), &signature)
            .expect("signature must verify against the canonical message");
    }
}
