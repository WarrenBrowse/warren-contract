//! The API's signature over its route KEM key (warren-core doc 107 section
//! 6.5), carried in the `route_admission` block of the session token
//! directory as [`RouteKemSignature`].
//!
//! ```text
//! message = "warren/route-kem-sig/v1" (23 bytes) || version:u32 BE
//!        || kem_key_id:u8 || kem_pubkey:[u8; 32] || valid_until:u64 BE   68 bytes
//! ```
//!
//! Anchors and route locators are sealed to that key, so whoever can serve a
//! key of its own opens them and links a device's main session to its routes.
//! The signature is made with the API's Ed25519 server key, the key whose
//! public half every client already pins for the signed relay list and the
//! multi-hop directory envelope: a party that can serve the document but does
//! not hold that key (a TLS interception, a CDN or proxy in front of the API)
//! cannot vouch for a key. The route KEM key is derived from that same server
//! key, so nothing short of the server key opens what is sealed to it anyway.
//!
//! `max_routes_per_anchor` and `exit_ids_hex` are not covered: a forged value
//! there can only make a client try route admission where it fails, or not
//! try it, and the exit list changes with every heartbeat.
//!
//! The layout is frozen by `vectors/route_kem_signature_v1.json`.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

use crate::dto::{RouteAdmissionInfo, RouteKemSignature};

/// Domain separator opening the signed message. Distinct from the HKDF info
/// `warren/route-kem/v1` the API derives the KEM key with.
pub const DOMAIN: &[u8] = b"warren/route-kem-sig/v1";

/// Length of the signed message.
pub const MESSAGE_LEN: usize = DOMAIN.len() + 4 + 1 + 32 + 8;

const SIGNATURE_LEN: usize = 64;

/// Why a route KEM key is not vouched for. Every variant means the same thing
/// to a client: route admission is unavailable, and routes run on tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RouteKemSignatureError {
    /// The block carries no signature (a server that predates it).
    #[error("route KEM key is not signed")]
    Unsigned,
    /// The signature is not 64 bytes of hex.
    #[error("route KEM key signature is malformed")]
    Malformed,
    /// The signature no longer vouches for the key: `now >= valid_until`.
    #[error("route KEM key signature has expired")]
    Expired,
    /// No pinned server key verifies the signature over this block.
    #[error("route KEM key signature does not verify under a pinned server key")]
    BadSignature,
    /// The caller pinned no server key, so no signature can be trusted.
    #[error("no server key is pinned to verify the route KEM key")]
    NoPinnedKey,
}

/// The 68-byte message the API signs.
#[must_use]
pub fn signed_message(
    version: u32,
    kem_key_id: u8,
    kem_pubkey: &[u8; 32],
    valid_until: u64,
) -> [u8; MESSAGE_LEN] {
    let mut message = [0u8; MESSAGE_LEN];
    let (domain, rest) = message.split_at_mut(DOMAIN.len());
    domain.copy_from_slice(DOMAIN);
    let (v, rest) = rest.split_at_mut(4);
    v.copy_from_slice(&version.to_be_bytes());
    rest[0] = kem_key_id;
    let (key, until) = rest[1..].split_at_mut(32);
    key.copy_from_slice(kem_pubkey);
    until.copy_from_slice(&valid_until.to_be_bytes());
    message
}

fn message_of(info: &RouteAdmissionInfo, valid_until: u64) -> [u8; MESSAGE_LEN] {
    let mut kem_pubkey = [0u8; 32];
    // `PubkeyHex` holds 64 lowercase hex characters by construction.
    hex::decode_to_slice(info.kem_pubkey_hex.as_str(), &mut kem_pubkey)
        .expect("PubkeyHex is 32 bytes of hex by construction");
    signed_message(info.version, info.kem_key_id, &kem_pubkey, valid_until)
}

/// Signs the route KEM key of `info` with the API server key, valid until
/// `valid_until` (exclusive, unix seconds). The caller stores the result in
/// [`RouteAdmissionInfo::kem_signature`]; any signature already there is
/// ignored.
#[must_use]
pub fn sign(
    info: &RouteAdmissionInfo,
    server_key: &SigningKey,
    valid_until: u64,
) -> RouteKemSignature {
    let signature = server_key.sign(&message_of(info, valid_until));
    RouteKemSignature {
        valid_until,
        signature_hex: hex::encode(signature.to_bytes()),
    }
}

/// Checks that one of `pinned_server_keys` (64-char hex Ed25519 keys, the
/// same pins the client verifies the signed directories against) signed the
/// route KEM key of `info`, and that the signature still holds at
/// `now_unix_secs`. A pin that does not decode is skipped. The checks run in
/// the order of the variants of [`RouteKemSignatureError`].
///
/// # Errors
///
/// [`RouteKemSignatureError`]: the client must not seal to this key.
pub fn verify(
    info: &RouteAdmissionInfo,
    pinned_server_keys: &[&str],
    now_unix_secs: u64,
) -> Result<(), RouteKemSignatureError> {
    let signed = info
        .kem_signature
        .as_ref()
        .ok_or(RouteKemSignatureError::Unsigned)?;
    let mut signature = [0u8; SIGNATURE_LEN];
    hex::decode_to_slice(&signed.signature_hex, &mut signature)
        .map_err(|_| RouteKemSignatureError::Malformed)?;
    if now_unix_secs >= signed.valid_until {
        return Err(RouteKemSignatureError::Expired);
    }
    if pinned_server_keys.is_empty() {
        return Err(RouteKemSignatureError::NoPinnedKey);
    }
    let message = message_of(info, signed.valid_until);
    let signature = Signature::from_bytes(&signature);
    let vouched = pinned_server_keys.iter().any(|pin| {
        let mut key = [0u8; 32];
        hex::decode_to_slice(pin, &mut key).is_ok()
            && VerifyingKey::from_bytes(&key)
                .is_ok_and(|key| key.verify_strict(&message, &signature).is_ok())
    });
    if vouched {
        Ok(())
    } else {
        Err(RouteKemSignatureError::BadSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{ExitId, PubkeyHex, ROUTE_ADMISSION_VERSION};

    const SERVER_SEED: [u8; 32] = [0x44; 32];
    const NOW: u64 = 1_800_000_000;

    fn info() -> RouteAdmissionInfo {
        RouteAdmissionInfo {
            version: ROUTE_ADMISSION_VERSION,
            kem_key_id: 1,
            kem_pubkey_hex: PubkeyHex::try_from("5a".repeat(32).as_str()).unwrap(),
            max_routes_per_anchor: 32,
            exit_ids_hex: vec![ExitId::from_bytes([1; 16])],
            kem_signature: None,
        }
    }

    fn pin() -> String {
        hex::encode(
            SigningKey::from_bytes(&SERVER_SEED)
                .verifying_key()
                .as_bytes(),
        )
    }

    fn signed(valid_until: u64) -> RouteAdmissionInfo {
        let mut info = info();
        info.kem_signature = Some(sign(
            &info,
            &SigningKey::from_bytes(&SERVER_SEED),
            valid_until,
        ));
        info
    }

    #[test]
    fn a_signed_block_verifies_until_its_validity_ends() {
        let info = signed(NOW + 10);
        assert_eq!(verify(&info, &[&pin()], NOW + 9), Ok(()));
        assert_eq!(
            verify(&info, &[&pin()], NOW + 10),
            Err(RouteKemSignatureError::Expired)
        );
    }

    #[test]
    fn the_exit_list_and_route_limit_are_not_signed() {
        let mut info = signed(NOW + 10);
        info.max_routes_per_anchor = 1;
        info.exit_ids_hex.clear();
        assert_eq!(verify(&info, &[&pin()], NOW), Ok(()));
    }

    #[test]
    fn a_non_hex_signature_is_malformed() {
        let mut info = signed(NOW + 10);
        info.kem_signature.as_mut().unwrap().signature_hex = "zz".repeat(64);
        assert_eq!(
            verify(&info, &[&pin()], NOW),
            Err(RouteKemSignatureError::Malformed)
        );
    }
}
