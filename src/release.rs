//! Signed exit-release manifest: the update authority for the exit fleet.
//!
//! An exit only swaps its binary for a manifest that (a) verifies against
//! the OFFLINE admin roster key pinned on the node, (b) carries a
//! `generation` strictly above the last one the node applied
//! (anti-rollback), and (c) has not passed `expires_at` (anti-freeze /
//! anti-replay). warren-api merely stores and relays the manifest: a
//! compromised backend cannot mint one.
//!
//! Signature preimage: the canonical `serde_json` encoding of the
//! manifest fields WITHOUT `signature_hex`, in declaration order. Same
//! recipe as the signed relay list; any field reorder/rename/retype is a
//! wire break and requires bumping [`RELEASE_MANIFEST_VERSION`], never
//! mutating the v1 shape (golden vector pins it).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::redact;

/// Current manifest format version.
pub const RELEASE_MANIFEST_VERSION: u32 = 1;

/// Maximum accepted `json` input length for [`verify_release_manifest`].
/// The parse runs before any signature check, so this caps what an
/// unauthenticated payload can make the verifier allocate; a real
/// manifest is well under 1 KiB.
pub const MAX_MANIFEST_JSON_LEN: usize = 64 * 1024;

/// Signed release manifest (full wire form, embedded verbatim in the
/// exit heartbeat response and stored by warren-api).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedReleaseManifest {
    /// Must equal [`RELEASE_MANIFEST_VERSION`].
    pub version: u32,
    /// Target build identifier, strict-matched against
    /// `warren-exit --version` after the swap (e.g. `v0.7.0-3-gabc1234`).
    pub release_version: String,
    /// Rollout channel (`stable`, `canary`, ...). Informational for the
    /// node; cohort routing is server-side state.
    pub channel: String,
    /// Lowercase hex SHA-256 of the musl binary this manifest authorizes.
    pub binary_sha256_hex: String,
    /// Exact byte size of the binary (second cheap integrity gate).
    pub binary_size: u64,
    /// Monotonic authority version. A node MUST reject a manifest whose
    /// `generation` is not strictly above the last one it applied
    /// (TUF rollback defense). Operator rollbacks re-sign the previous
    /// release under a NEW generation.
    pub generation: u64,
    /// Unix epoch seconds at which the manifest was signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which the manifest MUST NOT be trusted.
    pub expires_at: u64,
    /// 64-char hex of the signing `VerifyingKey`; must match the pin on
    /// the node (`WARREN_ADMIN_ROSTER_PUBKEY`).
    pub signer_pubkey_hex: String,
    /// 128-char hex Ed25519 signature over the canonical preimage.
    pub signature_hex: String,
}

/// Signature preimage. **Critical field order**: must match
/// [`SignedReleaseManifest`] minus `signature_hex` so the canonical
/// bytes are exactly the signed JSON prefix. Any mutation = format
/// version rotation.
#[derive(Serialize)]
struct UnsignedReleaseManifest<'a> {
    version: u32,
    release_version: &'a str,
    channel: &'a str,
    binary_sha256_hex: &'a str,
    binary_size: u64,
    generation: u64,
    signed_at: u64,
    expires_at: u64,
    signer_pubkey_hex: &'a str,
}

/// Single home of the preimage bytes: both [`sign_release_manifest`] and
/// [`verify_release_manifest`] derive them from the same struct, so the
/// two sides cannot diverge on what is signed.
///
/// # Panics
///
/// Panics if `serde_json::to_vec` fails, which is infallible for this
/// owned-scalar schema.
fn canonical_preimage(m: &SignedReleaseManifest) -> Vec<u8> {
    let unsigned = UnsignedReleaseManifest {
        version: m.version,
        release_version: &m.release_version,
        channel: &m.channel,
        binary_sha256_hex: &m.binary_sha256_hex,
        binary_size: m.binary_size,
        generation: m.generation,
        signed_at: m.signed_at,
        expires_at: m.expires_at,
        signer_pubkey_hex: &m.signer_pubkey_hex,
    };
    serde_json::to_vec(&unsigned).expect("UnsignedReleaseManifest JSON serialization is infallible")
}

/// Result of a successful [`verify_release_manifest`]. The crate stays
/// pure (no clock): expiry and generation floors are enforced by the
/// caller with [`VerifiedRelease::is_expired`] and its persisted
/// high-water mark.
#[derive(Debug, Clone)]
pub struct VerifiedRelease {
    /// Target build identifier.
    pub release_version: String,
    /// Rollout channel.
    pub channel: String,
    /// Hex SHA-256 the staged binary must match.
    pub binary_sha256_hex: String,
    /// Exact binary size in bytes.
    pub binary_size: u64,
    /// Monotonic authority version (anti-rollback high-water mark).
    pub generation: u64,
    /// Unix epoch seconds the manifest was signed.
    pub signed_at: u64,
    /// Unix epoch seconds after which the manifest is stale.
    pub expires_at: u64,
}

impl VerifiedRelease {
    /// True if `now_unix_secs` is at or past the signed expiry.
    #[must_use]
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.expires_at
    }
}

/// Errors of the signed release manifest format.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReleaseError {
    /// Invalid JSON or unexpected structure.
    #[error("invalid signed release manifest: {0}")]
    Json(#[from] serde_json::Error),
    /// `version != RELEASE_MANIFEST_VERSION`.
    #[error(
        "unsupported release manifest version: {got} (expected {})",
        RELEASE_MANIFEST_VERSION
    )]
    UnsupportedVersion {
        /// Version actually received.
        got: u32,
    },
    /// The declared signer pubkey does not match the pinned one.
    /// Both values are redacted (no-log discipline).
    #[error("release signer pubkey mismatch: got {got}, expected {expected}")]
    SignerPubkeyMismatch {
        /// Redacted prefix of the pubkey announced in the manifest.
        got: String,
        /// Redacted prefix of the pinned pubkey.
        expected: String,
    },
    /// Invalid hex for `signer_pubkey_hex` or `signature_hex`.
    #[error("invalid hex encoding")]
    InvalidHex,
    /// Signer pubkey is not a valid Ed25519 point.
    #[error("release signer pubkey is not a valid Ed25519 point")]
    PubkeyNotOnCurve,
    /// Signature does not verify against the canonical preimage.
    #[error("release manifest signature verification failed")]
    BadSignature,
    /// Input longer than [`MAX_MANIFEST_JSON_LEN`], rejected before
    /// parsing (pre-authentication allocation cap).
    #[error("signed release manifest input too large: {got} bytes")]
    InputTooLarge {
        /// Length actually received.
        got: usize,
    },
}

/// Signs a release manifest. Offline signer side only (`wapi
/// admin-sign-release`); the key never lives on warren-api.
///
/// # Panics
///
/// Panics if `serde_json::to_vec(&UnsignedReleaseManifest)` fails,
/// which is infallible for this owned-scalar schema.
#[must_use]
#[allow(clippy::too_many_arguments)] // mirrors sign_relay_list; a builder would obscure the frozen field order
pub fn sign_release_manifest(
    release_version: &str,
    channel: &str,
    binary_sha256_hex: &str,
    binary_size: u64,
    generation: u64,
    signed_at: u64,
    expires_at: u64,
    signer_key: &SigningKey,
) -> SignedReleaseManifest {
    let signer_pubkey_hex = hex::encode(signer_key.verifying_key().as_bytes());
    let mut manifest = SignedReleaseManifest {
        version: RELEASE_MANIFEST_VERSION,
        release_version: release_version.to_owned(),
        channel: channel.to_owned(),
        binary_sha256_hex: binary_sha256_hex.to_owned(),
        binary_size,
        generation,
        signed_at,
        expires_at,
        signer_pubkey_hex,
        signature_hex: String::new(),
    };
    let signature = signer_key.sign(&canonical_preimage(&manifest));
    manifest.signature_hex = hex::encode(signature.to_bytes());
    manifest
}

/// Verifies a signed release manifest against the pinned signer pubkey.
///
/// The pin is mandatory: every consumer of a manifest (warren-api,
/// warren-exit, warren-updater) knows exactly which key is allowed to
/// authorize releases; there is no TOFU mode for binaries.
///
/// # Errors
///
/// - [`ReleaseError::Json`]: invalid JSON.
/// - [`ReleaseError::UnsupportedVersion`]: format version mismatch.
/// - [`ReleaseError::SignerPubkeyMismatch`]: signer != pinned key.
/// - [`ReleaseError::InvalidHex`] / [`ReleaseError::PubkeyNotOnCurve`]:
///   malformed key/signature material.
/// - [`ReleaseError::BadSignature`]: signature does not verify.
/// - [`ReleaseError::InputTooLarge`]: input over [`MAX_MANIFEST_JSON_LEN`].
pub fn verify_release_manifest(
    json: &str,
    pinned_signer_pubkey_hex: &str,
) -> Result<VerifiedRelease, ReleaseError> {
    if json.len() > MAX_MANIFEST_JSON_LEN {
        return Err(ReleaseError::InputTooLarge { got: json.len() });
    }
    let signed: SignedReleaseManifest = serde_json::from_str(json)?;
    if signed.version != RELEASE_MANIFEST_VERSION {
        return Err(ReleaseError::UnsupportedVersion {
            got: signed.version,
        });
    }
    if !signed
        .signer_pubkey_hex
        .eq_ignore_ascii_case(pinned_signer_pubkey_hex)
    {
        return Err(ReleaseError::SignerPubkeyMismatch {
            got: redact(&signed.signer_pubkey_hex),
            expected: redact(pinned_signer_pubkey_hex),
        });
    }

    let pubkey_bytes: [u8; 32] = hex::decode(&signed.signer_pubkey_hex)
        .map_err(|_| ReleaseError::InvalidHex)?
        .try_into()
        .map_err(|_| ReleaseError::InvalidHex)?;
    let pubkey =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| ReleaseError::PubkeyNotOnCurve)?;
    let sig_bytes: [u8; 64] = hex::decode(&signed.signature_hex)
        .map_err(|_| ReleaseError::InvalidHex)?
        .try_into()
        .map_err(|_| ReleaseError::InvalidHex)?;
    let signature = Signature::from_bytes(&sig_bytes);

    pubkey
        .verify_strict(&canonical_preimage(&signed), &signature)
        .map_err(|_| ReleaseError::BadSignature)?;

    Ok(VerifiedRelease {
        release_version: signed.release_version,
        channel: signed.channel,
        binary_sha256_hex: signed.binary_sha256_hex,
        binary_size: signed.binary_size,
        generation: signed.generation,
        signed_at: signed.signed_at,
        expires_at: signed.expires_at,
    })
}
