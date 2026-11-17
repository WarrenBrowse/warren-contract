//! The wallet holder's signature over a device revocation (warren-core doc
//! 115, audit finding X-01), carried as [`DeviceRevocation`] in the body of
//! `DELETE /v1/devices/{device_id}` and in the 403 `device_revoked` body.
//!
//! ```text
//! message = "warren/device-revocation/v1" (27 bytes) || wallet_pubkey:[u8; 32]
//!        || device_id:[u8; 16] || revoked_at:u64 BE                    83 bytes
//! ```
//!
//! A revoked device erases its identity on `device_revoked`. A bare answer
//! proves nothing about who asked: whoever can answer for the API, or write
//! its revocation column, could make every client erase its phrase. So the
//! holder signs the revocation with the wallet key, the X-Warren signing key
//! every device of the account holds, and the revoked device verifies the
//! statement with its own copy of that key and its own device id before it
//! erases anything. Any failure means: disconnect and keep the identity.
//!
//! The wallet key is in the message so a statement binds one account; the
//! device id binds one install, so the API cannot serve one device's genuine
//! revocation to a sibling. Nothing expires: a revocation is permanent.
//!
//! The layout is frozen by `vectors/device_revocation_v1.json`.

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};

use crate::dto::{DEVICE_ID_LEN, DeviceId, DeviceRefusal, DeviceRevocation};

/// Domain separator opening the signed message.
pub const DOMAIN: &[u8] = b"warren/device-revocation/v1";

/// Length of the signed message.
pub const MESSAGE_LEN: usize = DOMAIN.len() + 32 + DEVICE_ID_LEN + 8;

const SIGNATURE_LEN: usize = 64;

/// Why a revoked device must not erase its identity. Every variant means the
/// same thing to the client: disconnect, keep the identity, say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DeviceRevocationError {
    /// The refusal carries no statement: a server that predates it, or a
    /// revocation made by a client that did not sign one.
    #[error("device revocation is not signed")]
    Unsigned,
    /// The signature is not 64 bytes of hex.
    #[error("device revocation signature is malformed")]
    Malformed,
    /// The wallet key did not sign this revocation of this device.
    #[error("device revocation does not verify under this wallet for this device")]
    BadSignature,
    /// The refusal is not `device_revoked`.
    #[error("not a device_revoked refusal")]
    NotRevoked,
}

/// The 83-byte message the wallet key signs.
#[must_use]
pub fn signed_message(
    wallet: &VerifyingKey,
    device_id: &DeviceId,
    revoked_at_unix_secs: u64,
) -> [u8; MESSAGE_LEN] {
    let mut message = [0u8; MESSAGE_LEN];
    let (domain, rest) = message.split_at_mut(DOMAIN.len());
    domain.copy_from_slice(DOMAIN);
    let (key, rest) = rest.split_at_mut(32);
    key.copy_from_slice(wallet.as_bytes());
    let (device, at) = rest.split_at_mut(DEVICE_ID_LEN);
    device.copy_from_slice(device_id.as_bytes());
    at.copy_from_slice(&revoked_at_unix_secs.to_be_bytes());
    message
}

/// Signs the revocation of `device_id` with the wallet key, as the revoking
/// device does before it sends `DELETE /v1/devices/{device_id}`.
#[must_use]
pub fn sign(
    wallet: &SigningKey,
    device_id: &DeviceId,
    revoked_at_unix_secs: u64,
) -> DeviceRevocation {
    let message = signed_message(&wallet.verifying_key(), device_id, revoked_at_unix_secs);
    DeviceRevocation {
        revoked_at_unix_secs,
        signature_hex: hex::encode(wallet.sign(&message).to_bytes()),
    }
}

/// Checks that `wallet` signed the revocation of `device_id` in `statement`.
/// The API runs it on the request body against the signing wallet and the
/// path's device id; the revoked device runs it through [`verify_refusal`].
///
/// # Errors
///
/// [`DeviceRevocationError::Malformed`] or
/// [`DeviceRevocationError::BadSignature`].
pub fn verify(
    statement: &DeviceRevocation,
    wallet: &VerifyingKey,
    device_id: &DeviceId,
) -> Result<(), DeviceRevocationError> {
    let mut signature = [0u8; SIGNATURE_LEN];
    hex::decode_to_slice(&statement.signature_hex, &mut signature)
        .map_err(|_| DeviceRevocationError::Malformed)?;
    let message = signed_message(wallet, device_id, statement.revoked_at_unix_secs);
    wallet
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| DeviceRevocationError::BadSignature)
}

/// What the device `device_id` of `wallet` may conclude from a 403 refusal:
/// `Ok(())` only for a `device_revoked` carrying a statement this wallet
/// signed for this device, the one case in which it may erase its identity.
///
/// # Errors
///
/// [`DeviceRevocationError`]: disconnect and keep the identity.
pub fn verify_refusal(
    refusal: &DeviceRefusal,
    wallet: &VerifyingKey,
    device_id: &DeviceId,
) -> Result<(), DeviceRevocationError> {
    if refusal.error != DeviceRefusal::REVOKED {
        return Err(DeviceRevocationError::NotRevoked);
    }
    let statement = refusal
        .revocation
        .as_ref()
        .ok_or(DeviceRevocationError::Unsigned)?;
    verify(statement, wallet, device_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    #[test]
    fn an_unregistered_refusal_never_allows_an_erase() {
        let wallet = key(1);
        let id = DeviceId::from_bytes([2; DEVICE_ID_LEN]);
        let mut refusal = DeviceRefusal::unregistered();
        refusal.revocation = Some(sign(&wallet, &id, 10));
        assert_eq!(
            verify_refusal(&refusal, &wallet.verifying_key(), &id),
            Err(DeviceRevocationError::NotRevoked)
        );
    }

    #[test]
    fn a_statement_verifies_only_for_its_wallet_and_device() {
        let wallet = key(1);
        let id = DeviceId::from_bytes([2; DEVICE_ID_LEN]);
        let statement = sign(&wallet, &id, 10);
        assert_eq!(verify(&statement, &wallet.verifying_key(), &id), Ok(()));
        assert_eq!(
            verify(&statement, &key(3).verifying_key(), &id),
            Err(DeviceRevocationError::BadSignature)
        );
        assert_eq!(
            verify(
                &statement,
                &wallet.verifying_key(),
                &DeviceId::from_bytes([4; DEVICE_ID_LEN])
            ),
            Err(DeviceRevocationError::BadSignature)
        );
    }
}
