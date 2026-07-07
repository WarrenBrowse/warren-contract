//! Shared plumbing for the three signed envelopes (relay list, roster,
//! multi-hop directory): hex-decode of pubkeys/signatures, the pinned-set
//! membership check and its redacted mismatch strings, and the
//! pre-authentication input-size gate. Kept `pub(crate)` so each format
//! keeps its own public error type while the actual decode/pin logic lives
//! in exactly one place.

use ed25519_dalek::{Signature, VerifyingKey};

/// Caps how much untrusted JSON a verify_* entry point parses before any
/// signature check runs. Bounds the pre-auth allocation an unauthenticated
/// payload can force; sized far above the largest plausible fleet document.
pub(crate) const MAX_VERIFY_INPUT_LEN: usize = 4 * 1024 * 1024;

/// Decode failure common to every hex-encoded pubkey/signature field. Each
/// format maps this into its own public error type.
#[derive(Debug)]
pub(crate) enum DecodeError {
    InvalidHex,
    PubkeyNotOnCurve,
}

pub(crate) fn decode_verifying_key(hex_str: &str) -> Result<VerifyingKey, DecodeError> {
    let bytes: [u8; 32] = hex::decode(hex_str)
        .map_err(|_| DecodeError::InvalidHex)?
        .try_into()
        .map_err(|_| DecodeError::InvalidHex)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| DecodeError::PubkeyNotOnCurve)
}

pub(crate) fn decode_signature(hex_str: &str) -> Result<Signature, DecodeError> {
    let bytes: [u8; 64] = hex::decode(hex_str)
        .map_err(|_| DecodeError::InvalidHex)?
        .try_into()
        .map_err(|_| DecodeError::InvalidHex)?;
    Ok(Signature::from_bytes(&bytes))
}

/// `true` if `pubkey_hex` case-insensitively matches at least one entry of
/// `pinned` (empty `pinned` = TOFU, always allowed).
pub(crate) fn pin_allows(pinned: &[&str], pubkey_hex: &str) -> bool {
    pinned.is_empty() || pinned.iter().any(|p| p.eq_ignore_ascii_case(pubkey_hex))
}

/// Redacted `(got, expected)` pair for a pin-mismatch error, joining the
/// pinned set with commas. Was verbatim-duplicated across the three formats.
pub(crate) fn redact_pin_mismatch(pinned: &[&str], got_hex: &str) -> (String, String) {
    let got = warren_contract::redact(got_hex);
    let expected = pinned
        .iter()
        .map(|p| warren_contract::redact(p))
        .collect::<Vec<_>>()
        .join(",");
    (got, expected)
}
