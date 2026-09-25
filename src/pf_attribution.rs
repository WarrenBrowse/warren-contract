//! Port-forward attribution: the tag warren-api mints with every port
//! entitlement, and the envelope that carries entitlement and tag together in
//! the NAT-PMP credential trailer (warren-core doc 105, section 3).
//!
//! ```text
//! tag      = version:u8 (=1) || epoch:u64 BE || nonce:[u8; 24]
//!         || ciphertext:[u8; 48] || signature:[u8; 64]          145 bytes
//! envelope = version:u8 (=1) || token:[u8; 354] || tag:[u8; 145]  500 bytes
//! ```
//!
//! The ciphertext is XChaCha20-Poly1305 under `k_enc` of the 32-byte account
//! pubkey, with [`aad`] as associated data. The signature is Ed25519 under
//! `k_sign` over [`signing_preimage`]. Both layouts are frozen by
//! `vectors/pf_attribution.json`.
//!
//! # Where each half of the crypto lives
//!
//! Parsing, the signature check and the two byte layouts are here for every
//! consumer, so the API that signs and the exit that verifies compose the
//! preimage from one definition. Sealing and opening are here too, behind the
//! `seal` feature, so the ciphertext the API mints is replayed against the
//! corpus vector by the same code that defines the layout. The feature keeps
//! the AEAD out of every consumer that has no business opening a tag: the SDK
//! and the exit build without it, and only warren-api, the one process that
//! derives `k_enc`, turns it on. Deriving `k_enc` and `k_sign` from the API
//! signing key (HKDF-SHA256 with [`HKDF_INFO_AEAD`] and [`HKDF_INFO_SIGN`]) is
//! warren-api's own business; only the info strings are shared here so they
//! cannot be respelled.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use zeroize::Zeroizing;

use crate::dto::PubkeyHex;

/// Domain separator prefixed to both the AEAD associated data and the
/// signature preimage.
pub const DOMAIN: &[u8] = b"warren/pf-attribution/v1";
/// HKDF-SHA256 info deriving the tag encryption key `k_enc` from the API
/// signing key.
pub const HKDF_INFO_AEAD: &[u8] = b"warren/pf-attribution/aead/v1";
/// HKDF-SHA256 info deriving the tag signing key `k_sign` from the API
/// signing key.
pub const HKDF_INFO_SIGN: &[u8] = b"warren/pf-attribution/sign/v1";

/// The only tag version this build mints and accepts.
pub const TAG_VERSION: u8 = 1;
/// XChaCha20-Poly1305 nonce length, fresh per tag.
pub const NONCE_LEN: usize = 24;
/// Plaintext length: the account's Ed25519 public key.
pub const ACCOUNT_PUBKEY_LEN: usize = 32;
/// Sealed account pubkey plus the 16-byte Poly1305 tag.
pub const CIPHERTEXT_LEN: usize = ACCOUNT_PUBKEY_LEN + 16;
/// Ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;
/// Full tag length.
pub const TAG_LEN: usize = 1 + 8 + NONCE_LEN + CIPHERTEXT_LEN + SIGNATURE_LEN;
/// Length of [`aad`].
pub const AAD_LEN: usize = DOMAIN.len() + 1 + 8;
/// Length of [`signing_preimage`].
pub const SIGNING_PREIMAGE_LEN: usize = AAD_LEN + NONCE_LEN + CIPHERTEXT_LEN;

/// The only envelope version this build composes and accepts.
pub const ENVELOPE_VERSION: u8 = 1;
/// Length of the Privacy Pass entitlement the envelope carries: an RFC 9578
/// type `0x0002` token over a 2048-bit RSA key (2 + 32 + 32 + 32 + 256). Equal
/// to `warrenguard_token::TOKEN_LEN`, which a test asserts; declared here so
/// the contract does not pull the RSA stack into every consumer.
pub const TOKEN_LEN: usize = 354;
/// Full envelope length. Fits the NAT-PMP credential trailer cap (512 B).
pub const ENVELOPE_LEN: usize = 1 + TOKEN_LEN + TAG_LEN;

const EPOCH_AT: usize = 1;
const NONCE_AT: usize = EPOCH_AT + 8;
const CIPHERTEXT_AT: usize = NONCE_AT + NONCE_LEN;
const SIGNATURE_AT: usize = CIPHERTEXT_AT + CIPHERTEXT_LEN;

/// Why an attribution tag was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AttributionTagError {
    /// The tag is not exactly [`TAG_LEN`] bytes.
    #[error("attribution tag is {actual} bytes, expected {TAG_LEN}")]
    WrongLength {
        /// Length received.
        actual: usize,
    },
    /// The version byte is not [`TAG_VERSION`].
    #[error("unsupported attribution tag version {0}")]
    UnsupportedVersion(u8),
    /// The signature does not verify under the published attribution key.
    #[error("attribution tag signature does not verify")]
    BadSignature,
    /// The published attribution key is not a valid Ed25519 public key.
    #[error("attribution verifying key is not a valid Ed25519 public key")]
    InvalidVerifyingKey,
    /// The ciphertext does not open under the key given (only produced by
    /// `AttributionTag::open`, behind the `seal` feature).
    #[error("attribution tag does not open under this key")]
    Undecryptable,
}

/// The AEAD associated data: `DOMAIN || version || epoch BE`. Binds the
/// sealed pubkey to its tag version and entitlement epoch.
#[must_use]
pub fn aad(epoch: u64) -> [u8; AAD_LEN] {
    let mut out = [0u8; AAD_LEN];
    out[..DOMAIN.len()].copy_from_slice(DOMAIN);
    out[DOMAIN.len()] = TAG_VERSION;
    out[DOMAIN.len() + 1..].copy_from_slice(&epoch.to_be_bytes());
    out
}

/// The Ed25519 signature preimage:
/// `DOMAIN || version || epoch BE || nonce || ciphertext`.
#[must_use]
pub fn signing_preimage(
    epoch: u64,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8; CIPHERTEXT_LEN],
) -> [u8; SIGNING_PREIMAGE_LEN] {
    let mut out = [0u8; SIGNING_PREIMAGE_LEN];
    out[..AAD_LEN].copy_from_slice(&aad(epoch));
    out[AAD_LEN..AAD_LEN + NONCE_LEN].copy_from_slice(nonce);
    out[AAD_LEN + NONCE_LEN..].copy_from_slice(ciphertext);
    out
}

/// Decodes the attribution verifying key published in the port-entitlement
/// key directory.
///
/// # Errors
///
/// [`AttributionTagError::InvalidVerifyingKey`] when the 32 bytes are not a
/// valid Ed25519 public key.
pub fn verifying_key(published: &PubkeyHex) -> Result<VerifyingKey, AttributionTagError> {
    let raw: [u8; 32] = hex::decode(published.as_str())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(AttributionTagError::InvalidVerifyingKey)?;
    VerifyingKey::from_bytes(&raw).map_err(|_| AttributionTagError::InvalidVerifyingKey)
}

/// A parsed port-forward attribution tag: well-formed and of a known version,
/// not yet verified (see [`AttributionTag::verify`]).
///
/// Its wire form in the `/v1` DTOs is base64url without padding.
#[derive(Clone, PartialEq, Eq)]
pub struct AttributionTag([u8; TAG_LEN]);

impl AttributionTag {
    /// Parses a tag from its exact wire bytes.
    ///
    /// # Errors
    ///
    /// [`AttributionTagError::WrongLength`] unless `bytes` is exactly
    /// [`TAG_LEN`] long, then [`AttributionTagError::UnsupportedVersion`]
    /// unless the version byte is [`TAG_VERSION`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AttributionTagError> {
        let raw: [u8; TAG_LEN] =
            bytes
                .try_into()
                .map_err(|_| AttributionTagError::WrongLength {
                    actual: bytes.len(),
                })?;
        if raw[0] != TAG_VERSION {
            return Err(AttributionTagError::UnsupportedVersion(raw[0]));
        }
        Ok(Self(raw))
    }

    /// The exact wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; TAG_LEN] {
        &self.0
    }

    /// Tag version (always [`TAG_VERSION`] once parsed).
    #[must_use]
    pub fn version(&self) -> u8 {
        self.0[0]
    }

    /// The entitlement epoch this tag was minted for. The exit refuses a tag
    /// whose epoch differs from the token's.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        let mut be = [0u8; 8];
        be.copy_from_slice(&self.0[EPOCH_AT..NONCE_AT]);
        u64::from_be_bytes(be)
    }

    /// The AEAD nonce.
    #[must_use]
    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        self.0[NONCE_AT..CIPHERTEXT_AT]
            .try_into()
            .unwrap_or_else(|_| unreachable!("fixed offsets inside a fixed-size array"))
    }

    /// The sealed account pubkey.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8; CIPHERTEXT_LEN] {
        self.0[CIPHERTEXT_AT..SIGNATURE_AT]
            .try_into()
            .unwrap_or_else(|_| unreachable!("fixed offsets inside a fixed-size array"))
    }

    /// The Ed25519 signature.
    #[must_use]
    pub fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        self.0[SIGNATURE_AT..]
            .try_into()
            .unwrap_or_else(|_| unreachable!("fixed offsets inside a fixed-size array"))
    }

    /// The preimage this tag's signature covers.
    #[must_use]
    pub fn signing_preimage(&self) -> [u8; SIGNING_PREIMAGE_LEN] {
        signing_preimage(self.epoch(), self.nonce(), self.ciphertext())
    }

    /// Checks the signature under the published attribution key. Strict
    /// verification: a non-canonical or small-order signature is refused.
    ///
    /// # Errors
    ///
    /// [`AttributionTagError::BadSignature`] when the signature does not
    /// verify, which covers any altered byte and any other key.
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), AttributionTagError> {
        let signature = Signature::from_bytes(self.signature());
        key.verify_strict(&self.signing_preimage(), &signature)
            .map_err(|_| AttributionTagError::BadSignature)
    }
}

impl fmt::Debug for AttributionTag {
    /// Version and epoch only. The rest is unlinkable without `k_enc`, but a
    /// tag is still never logged (doc 105 section 4).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttributionTag")
            .field("version", &self.version())
            .field("epoch", &self.epoch())
            .finish_non_exhaustive()
    }
}

impl serde::Serialize for AttributionTag {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de> serde::Deserialize<'de> for AttributionTag {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(d)?;
        let raw = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| serde::de::Error::custom("attribution tag is not base64url"))?;
        Self::from_bytes(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "seal")]
mod seal_impl {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::{OsRng, RngCore};
    use zeroize::Zeroizing;

    use super::{
        ACCOUNT_PUBKEY_LEN, AttributionTag, AttributionTagError, CIPHERTEXT_AT, CIPHERTEXT_LEN,
        NONCE_AT, NONCE_LEN, SIGNATURE_AT, TAG_LEN, TAG_VERSION, aad, signing_preimage,
    };

    /// Mints the attribution tag of one entitlement: seals `account_pubkey`
    /// under `k_enc` with a fresh random nonce, and signs the result under
    /// `k_sign`.
    ///
    /// The nonce is drawn here, never taken from the caller: it is what makes
    /// two tags of one account unlinkable, and a reused one under the same
    /// `k_enc` yields identical ciphertexts that any exit could match.
    #[must_use]
    pub fn seal(
        k_enc: &[u8; 32],
        k_sign: &SigningKey,
        epoch: u64,
        account_pubkey: &[u8; ACCOUNT_PUBKEY_LEN],
    ) -> AttributionTag {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        seal_with_nonce(k_enc, k_sign, epoch, &nonce, account_pubkey)
    }

    /// [`seal`] with a caller-chosen nonce, for replaying the corpus vector
    /// only. Never mint a production tag with it.
    #[doc(hidden)]
    #[must_use]
    pub fn seal_with_nonce(
        k_enc: &[u8; 32],
        k_sign: &SigningKey,
        epoch: u64,
        nonce: &[u8; NONCE_LEN],
        account_pubkey: &[u8; ACCOUNT_PUBKEY_LEN],
    ) -> AttributionTag {
        let cipher = XChaCha20Poly1305::new(k_enc.into());
        let mut ciphertext = [0u8; CIPHERTEXT_LEN];
        ciphertext[..ACCOUNT_PUBKEY_LEN].copy_from_slice(account_pubkey);
        let tag = cipher
            .encrypt_in_place_detached(
                XNonce::from_slice(nonce),
                &aad(epoch),
                &mut ciphertext[..ACCOUNT_PUBKEY_LEN],
            )
            .unwrap_or_else(|_| unreachable!("32 bytes is far below the AEAD length limit"));
        ciphertext[ACCOUNT_PUBKEY_LEN..].copy_from_slice(&tag);

        let signature = k_sign.sign(&signing_preimage(epoch, nonce, &ciphertext));
        let mut out = [0u8; TAG_LEN];
        out[0] = TAG_VERSION;
        out[1..NONCE_AT].copy_from_slice(&epoch.to_be_bytes());
        out[NONCE_AT..CIPHERTEXT_AT].copy_from_slice(nonce);
        out[CIPHERTEXT_AT..SIGNATURE_AT].copy_from_slice(&ciphertext);
        out[SIGNATURE_AT..].copy_from_slice(&signature.to_bytes());
        AttributionTag(out)
    }

    impl AttributionTag {
        /// Recovers the account pubkey sealed in this tag.
        ///
        /// The AEAD authenticates the ciphertext, its epoch and its version
        /// under `k_enc`, which only warren-api derives, so a tag that opens
        /// was minted by this API. The signature check is for verifiers
        /// without `k_enc`, the exits.
        ///
        /// # Errors
        ///
        /// [`AttributionTagError::Undecryptable`] when the tag was sealed
        /// under another key or any authenticated byte was altered.
        pub fn open(
            &self,
            k_enc: &[u8; 32],
        ) -> Result<Zeroizing<[u8; ACCOUNT_PUBKEY_LEN]>, AttributionTagError> {
            let cipher = XChaCha20Poly1305::new(k_enc.into());
            let ciphertext = self.ciphertext();
            let mut plaintext = Zeroizing::new([0u8; ACCOUNT_PUBKEY_LEN]);
            plaintext.copy_from_slice(&ciphertext[..ACCOUNT_PUBKEY_LEN]);
            cipher
                .decrypt_in_place_detached(
                    XNonce::from_slice(self.nonce()),
                    &aad(self.epoch()),
                    plaintext.as_mut_slice(),
                    Tag::from_slice(&ciphertext[ACCOUNT_PUBKEY_LEN..]),
                )
                .map_err(|_| AttributionTagError::Undecryptable)?;
            Ok(plaintext)
        }
    }
}

#[cfg(feature = "seal")]
pub use seal_impl::{seal, seal_with_nonce};

/// Why an entitlement envelope was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// The envelope is not exactly [`ENVELOPE_LEN`] bytes. A bare token, as
    /// a client predating the envelope sends it, lands here.
    #[error("entitlement envelope is {actual} bytes, expected {ENVELOPE_LEN}")]
    WrongLength {
        /// Length received.
        actual: usize,
    },
    /// The envelope version byte is not [`ENVELOPE_VERSION`].
    #[error("unsupported entitlement envelope version {0}")]
    UnsupportedVersion(u8),
    /// The token handed to [`EntitlementEnvelope::new`] is not exactly
    /// [`TOKEN_LEN`] bytes.
    #[error("entitlement token is {actual} bytes, expected {TOKEN_LEN}")]
    TokenLength {
        /// Length received.
        actual: usize,
    },
    /// The embedded tag does not parse.
    #[error("entitlement envelope carries an invalid attribution tag")]
    Tag(#[source] AttributionTagError),
}

/// One port entitlement and its attribution tag, as presented in the NAT-PMP
/// credential trailer. Parsing checks the layout and the tag version; the
/// exit still verifies the tag signature and spends the token.
#[derive(Clone, PartialEq, Eq)]
pub struct EntitlementEnvelope {
    token: Zeroizing<[u8; TOKEN_LEN]>,
    tag: AttributionTag,
}

impl EntitlementEnvelope {
    /// Pairs an unblinded entitlement with the tag minted beside it.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::TokenLength`] unless `token` is exactly
    /// [`TOKEN_LEN`] bytes.
    pub fn new(token: &[u8], tag: AttributionTag) -> Result<Self, EnvelopeError> {
        let token: [u8; TOKEN_LEN] = token.try_into().map_err(|_| EnvelopeError::TokenLength {
            actual: token.len(),
        })?;
        Ok(Self {
            token: Zeroizing::new(token),
            tag,
        })
    }

    /// Parses an envelope from the trailer bytes.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::WrongLength`] unless `bytes` is exactly
    /// [`ENVELOPE_LEN`] long, then [`EnvelopeError::UnsupportedVersion`], then
    /// [`EnvelopeError::Tag`] when the embedded tag does not parse.
    pub fn parse(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() != ENVELOPE_LEN {
            return Err(EnvelopeError::WrongLength {
                actual: bytes.len(),
            });
        }
        if bytes[0] != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion(bytes[0]));
        }
        let (token, tag) = bytes[1..].split_at(TOKEN_LEN);
        let tag = AttributionTag::from_bytes(tag).map_err(EnvelopeError::Tag)?;
        Self::new(token, tag)
    }

    /// The exact trailer bytes, wiped when dropped since they carry the
    /// token.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<[u8; ENVELOPE_LEN]> {
        let mut out = Zeroizing::new([0u8; ENVELOPE_LEN]);
        out[0] = ENVELOPE_VERSION;
        out[1..=TOKEN_LEN].copy_from_slice(self.token.as_slice());
        out[1 + TOKEN_LEN..].copy_from_slice(self.tag.as_bytes());
        out
    }

    /// The entitlement, the only part the exit sends to the API to spend.
    #[must_use]
    pub fn token(&self) -> &[u8; TOKEN_LEN] {
        &self.token
    }

    /// The attribution tag.
    #[must_use]
    pub fn tag(&self) -> &AttributionTag {
        &self.tag
    }
}

impl fmt::Debug for EntitlementEnvelope {
    /// Never the token: it is a bearer credential worth a port to whoever
    /// reads a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EntitlementEnvelope")
            .field("token", &"<redacted>")
            .field("tag", &self.tag)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const EPOCH: u64 = 0x0102_0304_0506_0708;

    /// A tag built by hand from the layout, signed by a throwaway key, so
    /// these tests do not depend on the `seal` feature.
    fn signed_tag(key: &SigningKey) -> AttributionTag {
        let nonce = [0x11; NONCE_LEN];
        let ciphertext = [0x22; CIPHERTEXT_LEN];
        let signature = key.sign(&signing_preimage(EPOCH, &nonce, &ciphertext));
        let mut raw = vec![TAG_VERSION];
        raw.extend_from_slice(&EPOCH.to_be_bytes());
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&ciphertext);
        raw.extend_from_slice(&signature.to_bytes());
        AttributionTag::from_bytes(&raw).expect("hand-built tag parses")
    }

    #[test]
    fn layout_lengths_are_the_documented_ones() {
        assert_eq!(TAG_LEN, 145);
        assert_eq!(ENVELOPE_LEN, 500);
        assert_eq!(AAD_LEN, 33);
        assert_eq!(SIGNING_PREIMAGE_LEN, 105);
    }

    #[test]
    fn epoch_is_read_big_endian() {
        let tag = signed_tag(&SigningKey::from_bytes(&[7; 32]));
        assert_eq!(tag.epoch(), EPOCH);
        assert_eq!(&tag.as_bytes()[1..9], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn debug_shows_neither_nonce_ciphertext_nor_signature() {
        let tag = signed_tag(&SigningKey::from_bytes(&[7; 32]));
        let rendered = format!("{tag:?}");
        assert!(rendered.contains("epoch"), "{rendered}");
        assert!(
            !rendered.contains('['),
            "no byte array (nonce, ciphertext, signature) may be rendered: {rendered}"
        );
    }

    #[test]
    fn envelope_debug_redacts_the_token() {
        let tag = signed_tag(&SigningKey::from_bytes(&[7; 32]));
        let envelope = EntitlementEnvelope::new(&[0xab; TOKEN_LEN], tag).expect("envelope");
        let rendered = format!("{envelope:?}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            !rendered.contains('['),
            "no token byte may be rendered: {rendered}"
        );
    }

    #[test]
    fn envelope_new_refuses_a_token_of_the_wrong_length() {
        let tag = signed_tag(&SigningKey::from_bytes(&[7; 32]));
        assert_eq!(
            EntitlementEnvelope::new(&[0; TOKEN_LEN - 1], tag),
            Err(EnvelopeError::TokenLength {
                actual: TOKEN_LEN - 1
            })
        );
    }

    #[test]
    fn tag_serde_is_base64url_without_padding_and_round_trips() {
        let tag = signed_tag(&SigningKey::from_bytes(&[7; 32]));
        let json = serde_json::to_string(&tag).expect("serialize");
        assert_eq!(
            json,
            format!("\"{}\"", URL_SAFE_NO_PAD.encode(tag.as_bytes()))
        );
        assert!(!json.contains('=') && !json.contains('+') && !json.contains('/'));
        let back: AttributionTag = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, tag);
    }

    #[test]
    fn tag_serde_refuses_a_malformed_tag_without_echoing_it() {
        let short = URL_SAFE_NO_PAD.encode([TAG_VERSION; 10]);
        let err = serde_json::from_str::<AttributionTag>(&format!("\"{short}\""))
            .expect_err("a 10-byte tag must not deserialize");
        assert!(err.to_string().contains("10 bytes"), "{err}");
        assert!(!err.to_string().contains(&short), "{err}");

        let err = serde_json::from_str::<AttributionTag>("\"not base64!\"")
            .expect_err("non-base64 must not deserialize");
        assert!(!err.to_string().contains("not base64!"), "{err}");
    }

    #[test]
    fn verifying_key_decodes_the_published_hex() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let published = PubkeyHex::try_from(hex::encode(key.verifying_key().as_bytes()).as_str())
            .expect("valid hex");
        let decoded = verifying_key(&published).expect("valid key");
        signed_tag(&key)
            .verify(&decoded)
            .expect("the decoded key verifies what its signing key signed");
    }

    #[test]
    fn verifying_key_refuses_bytes_that_are_not_a_curve_point() {
        // y = 2 has no x on edwards25519, so this is well-formed hex that
        // decompresses to nothing.
        let mut raw = [0u8; 32];
        raw[0] = 2;
        let published = PubkeyHex::try_from(hex::encode(raw).as_str()).expect("valid hex");
        assert_eq!(
            verifying_key(&published),
            Err(AttributionTagError::InvalidVerifyingKey)
        );
    }
}
