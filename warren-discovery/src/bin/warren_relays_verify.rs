//! Build-time verifier for a signed `warren-relays.json`.
//!
//! Used by the warren-app release "bake" step: after fetching
//! `GET {WARREN_API_URL}/v1/exits` into a file, this binary verifies the
//! Ed25519 signature against the **pinned** production server pubkey
//! before the file is embedded into the shipped client as the bootstrap
//! cache. The build fails (non-zero exit) on any verification error, so a
//! corrupted / unsigned / wrong-key list can never be baked into a
//! release.
//!
//! Verification is delegated to the same `verify_signed_relay_list` the
//! daemon uses at runtime, so the canonicalization (frozen byte order)
//! stays authoritative and cannot drift from a hand-rolled re-implementation.
//!
//! Usage:
//! ```bash
//! warren_relays_verify <file.json> --expected-pubkey <64-hex>
//! ```
//! Exit codes: `0` verified, `2` bad args, `1` verification failed.

use std::process::ExitCode;

use warren_discovery_core::{SignedError, verify_signed_relay_list};

/// Verifies `raw` against `expected_pubkey_hex` and returns the number of
/// relays in the verified list. Kept separate from `main` so it is
/// unit-testable.
///
/// # Errors
/// Propagates [`SignedError`] from [`verify_signed_relay_list`] (bad
/// version, pubkey mismatch, or signature failure).
fn verify(raw: &str, expected_pubkey_hex: &str) -> Result<usize, SignedError> {
    verify_signed_relay_list(raw, Some(expected_pubkey_hex)).map(|v| v.relays.len())
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut file: Option<String> = None;
    let mut expected: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--expected-pubkey" => expected = args.next(),
            other if file.is_none() && !other.starts_with("--") => file = Some(other.to_owned()),
            other => {
                eprintln!("unknown arg: {other}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(file), Some(expected)) = (file, expected) else {
        eprintln!("usage: warren_relays_verify <file.json> --expected-pubkey <64-hex>");
        return ExitCode::from(2);
    };
    let raw = match std::fs::read_to_string(&file) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot read {file}: {e}");
            return ExitCode::from(2);
        }
    };
    match verify(&raw, &expected) {
        Ok(n) => {
            if n == 0 {
                // A signed-but-empty list is valid yet useless as a
                // bootstrap; warn loudly but do not fail the build (all
                // exits could be transiently down at bake time).
                eprintln!("warning: verified list is EMPTY (0 relays) - baking an empty bootstrap");
            }
            eprintln!("ok: signature verified, {n} relay(s)");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("VERIFICATION FAILED: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::verify;
    use ed25519_dalek::SigningKey;
    use warren_discovery_core::warren_types::{ExitId, WarrenPubkey};
    use warren_discovery_core::{
        JsonEgress, JsonEndpoint, JsonListener, JsonLocation, JsonNode, sign_relay_list,
    };

    fn signed_body(server_key: &SigningKey) -> String {
        let signed = sign_relay_list(
            vec![JsonNode {
                id: hex::encode(WarrenPubkey::from_bytes([5; 32]).as_bytes()),
                exit_id: ExitId::from_bytes([5; 16]),
                location: JsonLocation {
                    country: "sg".to_owned(),
                    city: "Singapore".to_owned(),
                },
                weight: 100,
                active: true,
                egress: JsonEgress {
                    ipv4: true,
                    ipv6: false,
                },
                endpoints: vec![JsonEndpoint {
                    addr: "198.51.100.1".to_owned(),
                    family: "ipv4".to_owned(),
                    listeners: vec![JsonListener {
                        port: 443,
                        transport: "quic".to_owned(),
                        alpn: "h3".to_owned(),
                    }],
                }],
                cover_domain: None,
                port_forward: None,
                tcp_fallback: None,
            }],
            server_key,
            1,
            1_700_000_000,
            1_700_086_400,
        );
        serde_json::to_string(&signed).expect("serialize")
    }

    #[test]
    fn verify_accepts_correct_pin_and_counts_relays() {
        let key = SigningKey::from_bytes(&[0xab; 32]);
        let pin = hex::encode(key.verifying_key().to_bytes());
        let n = verify(&signed_body(&key), &pin).expect("must verify");
        assert_eq!(n, 1);
    }

    #[test]
    fn verify_rejects_wrong_pin() {
        // List self-signed by an attacker key must fail against the
        // legitimate pinned key - the whole point of build-time verify.
        let attacker = SigningKey::from_bytes(&[0x11; 32]);
        let legit_pin = hex::encode(
            SigningKey::from_bytes(&[0xab; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(verify(&signed_body(&attacker), &legit_pin).is_err());
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let key = SigningKey::from_bytes(&[0xab; 32]);
        let pin = hex::encode(key.verifying_key().to_bytes());
        let tampered = signed_body(&key).replace("198.51.100.1", "203.0.113.9");
        assert!(verify(&tampered, &pin).is_err());
    }
}
