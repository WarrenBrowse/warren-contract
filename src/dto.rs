//! Shared wire-format DTOs for `warren-api` (HTTP server) and
//! `warren-api-client` (HTTP client). Pulled out of the two crates to
//! eliminate the drift surface: every wire DTO is defined exactly once
//! here, so a missed field can no longer break compatibility silently
//! between the two sides.
//!
//! This crate intentionally keeps a minimal dependency footprint
//! (`serde` only): both the server (which would otherwise force an
//! `axum` + SQL transitive on every client) and the client (which would
//! otherwise pay the cost of compiling the server) can depend on it
//! cheaply.
//!
//! # House rule: encoding an absent optional field
//!
//! New optional fields use `#[serde(default, skip_serializing_if =
//! "Option::is_none")]` (absent on the wire when `None`). A minority of
//! older fields serialize `null` or use empty-string-as-absent; those
//! encodings are frozen wire behavior for their DTOs, do not copy them
//! into new fields.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
pub use warrenguard_wire::ExitId;

use crate::release::SignedReleaseManifest;

// ---------------------------------------------------------------------------
// Validation newtypes. Owning the shape rules here lets every DTO that
// embeds these fields get serde-level validation for free: a malformed
// `pubkey_hex` is rejected before the handler runs.
// ---------------------------------------------------------------------------

const PUBKEY_HEX_LEN: usize = 64;
const TOKEN_ID_HEX_LEN: usize = 12;
const COUNTRY_CODE_LEN: usize = 2;

fn default_true() -> bool {
    true
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

// The validating `TryFrom<&str>` stays hand-written per newtype (it is
// the type's whole contract); everything downstream of it is identical
// plumbing, generated here so the four newtypes cannot drift apart.
macro_rules! validated_string_impls {
    ($ty:ident) => {
        impl $ty {
            /// Borrowed view of the raw validated string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $ty {
            type Error = ValidationError;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::try_from(s.as_str())
            }
        }

        impl FromStr for $ty {
            type Err = ValidationError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::try_from(s)
            }
        }

        impl From<$ty> for String {
            fn from(v: $ty) -> Self {
                v.0
            }
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl std::ops::Deref for $ty {
            type Target = str;
            fn deref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

/// Errors raised by the validation newtypes when they receive a
/// malformed string. The payload carries only a redacted prefix of the
/// input (see [`crate::redact`]): a rejected value can be identity
/// material or a mispasted secret, so it is never echoed in full
/// (no-log discipline).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ValidationError {
    /// Pubkey string is not 64 lowercase hex chars.
    #[error("invalid pubkey hex: {0}")]
    InvalidPubkey(String),
    /// Pubkey string is not a valid Warren SS58 address (`wb…`): bad
    /// base58, wrong network prefix, or checksum mismatch.
    #[error("invalid Warren SS58 pubkey: {0}")]
    InvalidPubkeySs58(String),
    /// Token id is not 12 lowercase hex chars.
    #[error("invalid token id: {0}")]
    InvalidTokenId(String),
    /// Country code is not 2 ASCII letters.
    #[error("invalid country code: {0}")]
    InvalidCountryCode(String),
    /// Payment-method string is not one of the known wire tokens.
    #[error("unknown payment method: {0}")]
    InvalidPaymentMethod(String),
    /// A CRL revocation reason contains a line break, which would make
    /// the signed canonical message ambiguous (see
    /// [`crl_canonical_message`]).
    #[error("CRL reason contains a line break: {0}")]
    InvalidCrlReason(String),
}

/// Currency of the received payment. Used by the pricing policy to map
/// `amount_units -> duration_secs`. Wire form is uppercase ASCII
/// (`"EUR"`, `"SAT"`, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[allow(clippy::upper_case_acronyms)]
pub enum Currency {
    /// Euro (ISO 4217), smallest unit: cent.
    EUR,
    /// US dollar (ISO 4217), smallest unit: cent.
    USD,
    /// Bitcoin, denominated in whole BTC.
    BTC,
    /// Monero, denominated in whole XMR.
    XMR,
    /// Bitcoin satoshi (the on-wire unit for Lightning amounts).
    SAT,
    /// Romanian leu (ISO 4217), smallest unit: ban.
    RON,
    /// Canadian dollar (ISO 4217), smallest unit: cent.
    CAD,
    /// Pound sterling (ISO 4217), smallest unit: penny.
    GBP,
    /// Swiss franc (ISO 4217), smallest unit: rappen.
    CHF,
}

impl Currency {
    /// Uppercase ASCII wire token (`"EUR"`, `"SAT"`, ...).
    #[must_use]
    pub fn as_wire(&self) -> &'static str {
        match self {
            Self::EUR => "EUR",
            Self::USD => "USD",
            Self::BTC => "BTC",
            Self::XMR => "XMR",
            Self::SAT => "SAT",
            Self::RON => "RON",
            Self::CAD => "CAD",
            Self::GBP => "GBP",
            Self::CHF => "CHF",
        }
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire())
    }
}

/// Public lookup id of an enrollment token. 12 lowercase hex chars
/// (= 48 bits of entropy). Safe to log; never carries secret material.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TokenId(String);

impl TokenId {
    /// Build directly from already-trusted bytes. Used by the
    /// enrollment crate which produces the bytes itself.
    ///
    /// # Panics
    ///
    /// Panics if `hex` is not 12 lowercase hex chars: the caller
    /// promised trusted input, so a malformed value is a broken
    /// invariant, not a recoverable error.
    #[doc(hidden)]
    #[must_use]
    pub fn from_hex_validated(hex: String) -> Self {
        assert!(
            is_lower_hex(&hex, TOKEN_ID_HEX_LEN),
            "TokenId::from_hex_validated requires 12 lowercase hex chars"
        );
        Self(hex)
    }
}

impl TryFrom<&str> for TokenId {
    type Error = ValidationError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if !is_lower_hex(s, TOKEN_ID_HEX_LEN) {
            return Err(ValidationError::InvalidTokenId(crate::redact(s)));
        }
        Ok(Self(s.to_owned()))
    }
}

validated_string_impls!(TokenId);

/// Ed25519 public key, hex-encoded. 64 lowercase hex chars. The
/// canonical Warren identity surface for users, exits, and admins.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PubkeyHex(String);

impl TryFrom<&str> for PubkeyHex {
    type Error = ValidationError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if !is_lower_hex(s, PUBKEY_HEX_LEN) {
            return Err(ValidationError::InvalidPubkey(crate::redact(s)));
        }
        Ok(Self(s.to_owned()))
    }
}

validated_string_impls!(PubkeyHex);

impl AsRef<[u8]> for PubkeyHex {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Warren wallet/account identity public key, SS58-encoded (`wb…`). This
/// is the canonical string surface for the **identity** pubkey that signs
/// requests via the `X-Warren-PubKey` header - the wallet user, and any
/// exit/admin that authenticates through the shared verifier. The same 32
/// raw Ed25519 bytes back it; only the text encoding is SS58 (network
/// prefix `13295`, Blake2b checksum).
///
/// Construction validates the full address (base58 + prefix + checksum)
/// via the canonical [`crate::ss58`] codec, so a malformed
/// pubkey is rejected at `serde_json::from_str` time rather than at apply
/// time on a store-lookup path. Category-C infrastructure pubkeys (exit
/// descriptor keys, relay keys, HPKE keys) stay hex - see [`PubkeyHex`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PubkeySs58(String);

impl PubkeySs58 {
    /// Decode the address back to the 32 raw Ed25519 bytes at the crypto
    /// boundary. Infallible because the value was validated on
    /// construction; a failure here would mean the invariant was broken.
    ///
    /// # Panics
    ///
    /// Panics if the stored address is not a valid Warren SS58 address,
    /// which cannot happen for a value built through the validating
    /// constructors.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        crate::ss58::decode(&self.0)
            .expect("PubkeySs58 holds a validated SS58 address by construction")
    }
}

impl TryFrom<&str> for PubkeySs58 {
    type Error = ValidationError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if crate::ss58::is_valid(s) {
            Ok(Self(s.to_owned()))
        } else {
            Err(ValidationError::InvalidPubkeySs58(crate::redact(s)))
        }
    }
}

validated_string_impls!(PubkeySs58);

/// ISO 3166-1 alpha-2 country code (2 ASCII letters, uppercased on
/// construction so the lookup is canonical).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CountryCode(String);

impl TryFrom<&str> for CountryCode {
    type Error = ValidationError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        if s.len() != COUNTRY_CODE_LEN || !s.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(ValidationError::InvalidCountryCode(crate::redact(s)));
        }
        Ok(Self(s.to_ascii_uppercase()))
    }
}

validated_string_impls!(CountryCode);

// ---------------------------------------------------------------------------
// Payment method.
// ---------------------------------------------------------------------------

/// Payment method tag echoed by the admin voucher endpoints.
/// `#[serde(rename_all = "lowercase")]` is part of the wire contract -
/// any case change is a breaking compat regression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PaymentMethod {
    /// Bitcoin Lightning Network.
    Lightning,
    /// Monero.
    Monero,
    /// Bank card (Stripe).
    Card,
    /// Physical cash.
    Cash,
    /// On-chain Bitcoin.
    Bitcoin,
    /// Manual admin creation (tests, staging, free comps).
    Manual,
    /// Apple App Store (StoreKit 2).
    #[serde(rename = "appstore")]
    AppStore,
    /// Google Play Store (Play Billing).
    #[serde(rename = "googleplay")]
    GooglePlay,
    /// PayPal (processed through Stripe).
    Paypal,
}

impl PaymentMethod {
    /// Parse a lowercase wire string into the matching variant.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidPaymentMethod`] carrying only a
    /// redacted prefix of the input: the value is untrusted and could be
    /// a mispasted secret (no-log discipline).
    pub fn from_wire(s: &str) -> Result<Self, ValidationError> {
        match s {
            "lightning" => Ok(Self::Lightning),
            "monero" => Ok(Self::Monero),
            "card" => Ok(Self::Card),
            "cash" => Ok(Self::Cash),
            "bitcoin" => Ok(Self::Bitcoin),
            "manual" => Ok(Self::Manual),
            "appstore" => Ok(Self::AppStore),
            "googleplay" => Ok(Self::GooglePlay),
            "paypal" => Ok(Self::Paypal),
            other => Err(ValidationError::InvalidPaymentMethod(crate::redact(other))),
        }
    }

    /// Lowercase wire form (`"lightning"`, ...).
    #[must_use]
    pub fn as_wire(&self) -> &'static str {
        match self {
            Self::Lightning => "lightning",
            Self::Monero => "monero",
            Self::Card => "card",
            Self::Cash => "cash",
            Self::Bitcoin => "bitcoin",
            Self::Manual => "manual",
            Self::AppStore => "appstore",
            Self::GooglePlay => "googleplay",
            Self::Paypal => "paypal",
        }
    }
}

impl std::fmt::Display for PaymentMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_wire())
    }
}

// ---------------------------------------------------------------------------
// Mobile payments (Apple StoreKit 2 + Google Play Billing).
// ---------------------------------------------------------------------------

/// `POST /v1/payments/apple/init` response. The client passes this
/// token to StoreKit as the `appAccountToken` UUID when initiating the
/// in-app purchase. Apple includes it verbatim in the signed JWS
/// transaction so the backend can map the receipt back to the Warren
/// pubkey without Apple ever seeing the pubkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitApplePaymentResponse {
    /// UUID v4 string (lowercase, hyphenated) to pass to StoreKit.
    pub app_account_token: String,
}

/// `POST /v1/payments/apple/check` request body. The client extracts
/// the JWS representation from the verified StoreKit transaction and
/// sends it here for server-side validation + subscription credit.
#[derive(Clone, Serialize, Deserialize)]
pub struct CheckApplePaymentRequest {
    /// JWS string from `Transaction.jwsRepresentation` (StoreKit 2).
    pub jws_transaction: String,
}

impl fmt::Debug for CheckApplePaymentRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckApplePaymentRequest")
            .field("jws_transaction", &"<redacted>")
            .finish()
    }
}

/// `POST /v1/payments/google/init` response. The client passes this
/// id to the Play Billing Library as the `obfuscatedAccountId` so the
/// backend can map the purchase token back to the Warren pubkey.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitGooglePaymentResponse {
    /// Opaque identifier for the Play Billing flow.
    pub obfuscated_account_id: String,
}

/// `POST /v1/payments/google/acknowledge` request body.
#[derive(Clone, Serialize, Deserialize)]
pub struct AcknowledgeGooglePaymentRequest {
    /// Opaque token from `Purchase.getPurchaseToken()`.
    pub purchase_token: String,
}

impl fmt::Debug for AcknowledgeGooglePaymentRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcknowledgeGooglePaymentRequest")
            .field("purchase_token", &"<redacted>")
            .finish()
    }
}

/// Shared response for both Apple and Google payment check/acknowledge
/// endpoints. Same shape as the register response but kept distinct
/// for forward-compatibility (mobile may carry extra fields later).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobilePaymentResponse {
    /// Unix epoch seconds at which the subscription now expires.
    pub expires_at: u64,
}

// ---------------------------------------------------------------------------
// IP check endpoint.
// ---------------------------------------------------------------------------

/// `GET /v1/check` response. Tells the client whether its public IP
/// belongs to a Warren exit (i.e. the VPN tunnel is active and
/// traffic exits through the Warren network).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResponse {
    /// Client's public IP as seen by the server.
    pub ip: String,
    /// `true` when `ip` matches a currently registered Warren exit.
    pub is_exit: bool,
    /// Country of the matching exit (ISO 3166-1 alpha-2), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_country: Option<CountryCode>,
    /// City of the matching exit, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_city: Option<String>,
}

// ---------------------------------------------------------------------------
// Subscription endpoints.
// ---------------------------------------------------------------------------

/// `POST /v1/register` request body.
///
/// Binds an Ed25519 pubkey to a voucher, creating or extending a
/// subscription. No auth required - the `voucher_secret` is the proof
/// of purchase.
///
/// # Wire contract
///
/// - `pubkey_ss58`: Warren SS58 address (`wb…`) of the Ed25519 public
///   key to bind.
/// - `voucher_secret`: Crockford-32 voucher in dashed display form
///   `XXXX-XXXX-XXXX-XXXX` (19 chars) or raw 16-char form - the
///   server normalizes both. 80 bits of entropy.
/// - `referral_code`: optional `wref-<16hex>` code; when valid the
///   referrer receives a bonus extension on their own subscription.
///
/// # Errors returned by the server
///
/// | Status | Meaning |
/// |--------|---------|
/// | 400 | Voucher unknown or malformed. |
/// | 409 | Voucher already redeemed, or pubkey already registered. |
/// | 410 | Voucher was cancelled by an admin. |
/// | 429 | Rate limit exceeded on this endpoint. |
#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterAccountRequest {
    /// Ed25519 public key to bind, as a Warren SS58 address (`wb…`).
    pub pubkey_ss58: PubkeySs58,
    /// Plain-text voucher secret. Accepts both the dashed display
    /// form `XXXX-XXXX-XXXX-XXXX` and the raw 16-char form; the
    /// server normalizes via `warren_api::normalize_voucher_secret`
    /// before hashing. Crockford-32 alphabet, 80 bits of entropy.
    pub voucher_secret: String,
    /// Optional referral code (`wref-<16hex>`). Omitted from the wire
    /// when `None` to keep the serialized form compact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referral_code: Option<String>,
}

impl fmt::Debug for RegisterAccountRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterAccountRequest")
            .field("pubkey_ss58", &self.pubkey_ss58)
            // Redacted: the secret must never appear in logs.
            .field("voucher_secret", &"<redacted>")
            .field(
                "referral_code",
                // Presence is safe to log; the value is withheld.
                &self.referral_code.as_deref().map(|_| "<present>"),
            )
            .finish()
    }
}

/// `POST /v1/register` response (HTTP 201 Created).
///
/// Carries the subscription expiry so the client can display it
/// without making a separate `GET /v1/subscription` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterAccountResponse {
    /// Unix epoch seconds at which the new subscription expires.
    pub expires_at: u64,
    /// Seconds THIS redemption added to the account (the voucher's own
    /// granted duration), independent of any pre-existing balance. The
    /// client shows it as "X was added"; deriving it from
    /// `expires_at - now` would instead report the account's TOTAL
    /// remaining time and mislead a user who still had time left.
    /// `#[serde(default)]` keeps wire-compat with servers that pre-date
    /// the field (an older server yields 0, so the client falls back to
    /// showing no added-duration line rather than a wrong number).
    #[serde(default)]
    pub added_secs: u64,
}

/// `GET /v1/subscription` response.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SubscriptionResponse {
    /// Unix epoch seconds at which the subscription expires.
    pub expires_at: u64,
}

/// `GET /v1/subscribers/active` response. Returned to exits polling for
/// the current allowlist of authorized client pubkeys. Bumping
/// `generation` is the canonical signal that the list has changed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveSubscribersResponse {
    /// Monotonic counter from the subscription store. Strictly
    /// increases on every mutation; stable across pure reads.
    pub generation: u64,
    /// Unix epoch seconds at handling time on the server.
    pub now_unix_secs: u64,
    /// Subscriber SS58 addresses with `expires_at > now_unix_secs`,
    /// sorted ascending. Typed as `PubkeySs58` so a malformed pubkey is
    /// rejected at `serde_json::from_str` time, not at apply time on the
    /// exit's allowlist path.
    pub active_pubkeys: Vec<PubkeySs58>,
}

/// `GET /v1/subscribers/active?since_generation=N` response when the
/// store can serve the requested incremental range. The exit applies
/// `added` (insert / overwrite) then `removed` (revoke) to its local
/// allowlist in event order, then jumps its known generation to
/// `to_generation`.
///
/// When the store cannot serve the requested range (log truncated,
/// `since_generation > current`), the server falls back to the full
/// [`ActiveSubscribersResponse`] payload and flags it with the response
/// header `X-Warren-Snapshot-Fallback: true`; the client must apply
/// it as a full replacement rather than as a delta.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscribersDeltaResponse {
    /// `since_generation` the consumer sent. Echoed for sanity-check.
    pub from_generation: u64,
    /// Current store generation. The consumer jumps to this value on
    /// successful apply.
    pub to_generation: u64,
    /// Unix epoch seconds at handling time on the server.
    pub now_unix_secs: u64,
    /// New subscriptions, in order of generation.
    pub added: Vec<SubscriberDeltaAdd>,
    /// Retired subscriber SS58 addresses, in order of generation. Typed
    /// as `PubkeySs58` so a malformed pubkey is rejected at
    /// `serde_json::from_str` time, not at apply time.
    pub removed: Vec<PubkeySs58>,
}

/// One added entry in [`SubscribersDeltaResponse::added`]. We carry
/// `expires_at` so the local allowlist can honour TTL even when the
/// backend is unreachable (fail-open contract).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriberDeltaAdd {
    /// Subscriber SS58 address (`wb…`).
    pub pubkey_ss58: PubkeySs58,
    /// Unix epoch seconds at which the subscription expires.
    pub expires_at: u64,
}

/// Signed Certificate Revocation List. Polled separately
/// from `/v1/subscribers/active` so urgent revocations propagate even
/// when the main allowlist sync is degraded (fail-open
/// path). The CRL is the authoritative source for explicit blocks
/// (compromised pubkey, abuse, chargeback); it MUST be honoured by
/// the exit before the allowlist check.
///
/// Authenticity: the response is signed by the admin Ed25519 key so
/// the exit can validate it offline. The `signature` covers
/// canonical(version, generated_at_unix_secs, revocations) per
/// [`crl_canonical_message`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrlResponse {
    /// Monotonic counter bumped on every revocation insert. Consumers
    /// use it to deduplicate polls.
    pub version: u64,
    /// Server-side unix-secs at signing time.
    pub generated_at_unix_secs: u64,
    /// Revocations in insertion order.
    pub revocations: Vec<CrlEntry>,
    /// Admin pubkey that signed the payload, as a Warren SS58 address
    /// (`wb…`). The consumer matches it against its locally-configured
    /// admin pubkey before trusting the signature.
    pub admin_pubkey_ss58: String,
    /// Ed25519 signature over [`crl_canonical_message`] of this
    /// response. 128 hex chars (64 raw bytes).
    pub signature_hex: String,
}

/// One revocation entry inside a [`CrlResponse`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrlEntry {
    /// Revoked subscriber SS58 address (`wb…`): typed as `PubkeySs58`
    /// so a malformed pubkey in the
    /// signed CRL payload is rejected at deserialization time before
    /// the exit applies it to its allowlist.
    pub pubkey_ss58: PubkeySs58,
    /// Unix-secs of the admin revocation action.
    pub revoked_at_unix_secs: u64,
    /// Short tag describing why the revocation was issued (e.g.
    /// `"chargeback"`, `"abuse"`, `"compromised"`). Free-form except
    /// line breaks, which are rejected at deserialization because they
    /// would make [`crl_canonical_message`] ambiguous.
    #[serde(deserialize_with = "deserialize_single_line_reason")]
    pub reason: String,
}

/// Reject line breaks in a CRL `reason` at the serde boundary: the
/// canonical message delimits entries with `\n`, so a reason embedding
/// one would let two different revocation lists collide on the same
/// signed preimage.
fn deserialize_single_line_reason<'de, D>(d: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    if s.contains(['\n', '\r']) {
        return Err(serde::de::Error::custom(ValidationError::InvalidCrlReason(
            crate::redact(&s),
        )));
    }
    Ok(s)
}

/// Build the canonical byte string the admin signs to authenticate a
/// [`CrlResponse`]. The format is `"v1\n" + version + "\n" +
/// generated_at + "\n" + entry_lines`, where each entry contributes
/// `<pubkey>:<revoked_at>:<reason>\n`. Entries are sorted by pubkey
/// for determinism so the signer and the verifier see byte-identical
/// inputs.
///
/// The leading `"v1\n"` is a version tag. Bumping the canonical
/// format requires a new tag (`"v2\n"`) and a coordinated rollout;
/// never mutate v1.
///
/// Injectivity relies on `reason` being line-break-free, which the
/// serde boundary enforces (see [`CrlEntry::reason`] and
/// [`AdminCrlRevokeRequest::reason`]); `:` inside a reason is harmless
/// because the two fixed-shape fields before it disambiguate the line.
#[must_use]
pub fn crl_canonical_message(
    version: u64,
    generated_at_unix_secs: u64,
    revocations: &[CrlEntry],
) -> Vec<u8> {
    debug_assert!(
        revocations.iter().all(|e| !e.reason.contains(['\n', '\r'])),
        "CRL reason with a line break breaks preimage injectivity"
    );
    let mut sorted: Vec<&CrlEntry> = revocations.iter().collect();
    sorted.sort_by(|a, b| a.pubkey_ss58.cmp(&b.pubkey_ss58));
    let mut out = String::with_capacity(64 + revocations.len() * 100);
    out.push_str("v1\n");
    out.push_str(&version.to_string());
    out.push('\n');
    out.push_str(&generated_at_unix_secs.to_string());
    out.push('\n');
    for e in sorted {
        out.push_str(e.pubkey_ss58.as_str());
        out.push(':');
        out.push_str(&e.revoked_at_unix_secs.to_string());
        out.push(':');
        out.push_str(&e.reason);
        out.push('\n');
    }
    out.into_bytes()
}

/// `POST /v1/admin/subscribers/crl/revoke` body. Admin pins a
/// pubkey on the CRL with a free-form reason. The server bumps the
/// CRL `version`, appends the entry, and re-signs the payload with
/// the admin signing key bound at startup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminCrlRevokeRequest {
    /// Subscriber to revoke, as a Warren SS58 address (`wb…`).
    pub pubkey_ss58: PubkeySs58,
    /// Short tag (e.g. `"abuse"`, `"chargeback"`). Line breaks are
    /// rejected at deserialization (see [`CrlEntry::reason`]).
    #[serde(deserialize_with = "deserialize_single_line_reason")]
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Exit registration + enrollment.
// ---------------------------------------------------------------------------

/// A dial listener on an endpoint: `port` + wire `transport` + `alpn`
/// (the connection-type / obfuscation token the app surfaces).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterListener {
    /// Listening port.
    pub port: u16,
    /// Wire transport (`quic`, future `masque`, ...).
    pub transport: String,
    /// ALPN token offered in the handshake (`h3`).
    pub alpn: String,
}

/// One address the exit declares (v6 node model). `geoip` is NOT sent by
/// the exit; the API derives it from `addr`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterEndpoint {
    /// IP literal (no port; ports live in `listeners`).
    pub addr: String,
    /// `"ipv4"` / `"ipv6"`; must match `addr`. Intentionally a `String`,
    /// not an enum: it is redundant with `addr` (belt-and-suspenders so a
    /// mislabel cannot dodge a family filter) and lives in the Ed25519
    /// signing preimage downstream, so converting the type would churn the
    /// signed wire format for no behavioural gain. Validated against `addr`
    /// at the parse boundary.
    pub family: String,
    /// `true` if clients dial this address. Defaults `true` (the common
    /// single-IP node).
    #[serde(default = "default_true")]
    pub ingress: bool,
    /// `true` if the node egresses internet traffic from this source IP
    /// (probed). Defaults `true`.
    #[serde(default = "default_true")]
    pub egress: bool,
    /// Dial listeners; empty for egress-only endpoints.
    #[serde(default)]
    pub listeners: Vec<RegisterListener>,
}

/// `POST /v1/exits/register` body (consumed by warren-exit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterExitRequest {
    /// Addresses the exit uses (1..N). Family is explicit, egress is
    /// per-endpoint, and ports/transports live in each endpoint's
    /// `listeners`.
    pub endpoints: Vec<RegisterEndpoint>,
    /// ISO 3166-1 alpha-2 country code.
    pub country: CountryCode,
    /// City name.
    pub city: String,
    /// Selector weight (relative weight applied at relay selection
    /// time; 0 = drain).
    pub weight: u64,
    /// `false` to drain the exit for ops without removing it from the
    /// list. `#[serde(default)]` defaulting to `true` keeps wire-compat
    /// with older clients that pre-date the drain flag.
    #[serde(default = "default_true")]
    pub active: bool,
    /// 16-byte stable identifier the exit operator persists across
    /// pubkey rotations. It is the anchor for TOFU
    /// pubkey pinning. The server treats it as authoritative when the
    /// exit supplies one; when absent (legacy exit binary), the server
    /// looks up the value previously stored at enroll-time or
    /// generates a fresh one and binds it to the exit's pubkey for
    /// future heartbeats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_id: Option<ExitId>,
    /// 64-char hex of the exit's X25519 HPKE multi-hop recipient pubkey
    /// (`exit_x25519_multihop_pubkey`). Published so warren-api can mint
    /// signed multi-hop exit descriptors for the dynamic directory
    /// without an out-of-band step. Bound to the exit's authenticated
    /// Ed25519 identity by the signed request. Absent for legacy exits
    /// (the node then appears single-hop only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_x25519_multihop_pubkey_hex: Option<String>,
    /// Build identifier of the running exit binary (e.g.
    /// `v0.3.7` or `v0.3.7-2-gabc1234`), surfaced in the admin panel
    /// so the operator can verify fleet deployment state at a glance.
    /// Optional for wire-compat: legacy exit binaries omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Live count of client device-sessions this exit is currently
    /// serving (one per `(pubkey, device)`; ADR 36 §6 operator visibility:
    /// lets the admin watch a drained exit empty out before
    /// decommissioning). `None` from a legacy exit, or a serve path whose
    /// live count is not yet wired (multi-hop), so the field is omitted
    /// rather than reported as a misleading `0`. Live data: the latest
    /// heartbeat wins (never preserved across an omitting heartbeat).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_sessions: Option<u32>,
    /// v6 X.509 cover-domain SNI (wg-0005): the hostname on the exit's real
    /// certificate. When set, warren-api publishes it in the signed roster so
    /// clients dial it and validate the chain via WebPKI instead of pinning the
    /// exit RPK. `None` (legacy / RPK exits) is omitted from the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover_domain: Option<String>,
    /// Where the node stands in the fleet-update sequence (doc 54): the
    /// rollout controller advances the per-node state machine on this
    /// report. `None` from an exit that pre-dates the update agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_status: Option<ExitUpdateStatus>,
    /// Per-node telemetry aggregates carried by the heartbeat (doc 52).
    /// `None` from a legacy exit. Counters are cumulative since process
    /// start: the server derives rates by delta and treats a decreasing
    /// counter as a process restart. Node-level aggregates only, never
    /// per-client data (doc 52 invariant I2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<ExitTelemetry>,
    /// First-boot hardware qualification verdict (doc 57). Reported once the
    /// node's self-bench has run (a few seconds after boot); `None` before then
    /// and from an exit binary that pre-dates the self-bench. Sticky server-side
    /// (a heartbeat that omits it must not blank a stored verdict).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hwqual: Option<ExitHwQual>,
    /// Whether this exit runs a NAT-PMP (RFC 6886) port-forwarding gateway
    /// (`--enable-natpmp`, doc 79). Warren is mono-IP, so this announces a
    /// per-exit capability toggle ("port forwarding enabled here"), not a
    /// second IP: some exits disable NAT-PMP, and the client must only
    /// offer/prefer port forwarding where it is actually active. Sticky
    /// server-side like `hwqual` (a heartbeat that omits it must not blank a
    /// stored value). `None` from an exit binary that pre-dates the flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_forward: Option<bool>,
}

/// Telemetry block of the exit heartbeat (doc 52 §4). Datapath and QUIC
/// counters are always present (zero-valued when idle); system gauges are
/// optional because /proc sampling can be unavailable or disabled.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ExitTelemetry {
    /// Datapath bytes to clients, summed over the node.
    pub bytes_tx_total: u64,
    /// Datapath bytes from clients, summed over the node.
    pub bytes_rx_total: u64,
    /// Datapath datagrams to clients, summed over the node.
    pub datagrams_tx_total: u64,
    /// Datapath datagrams from clients, summed over the node.
    pub datagrams_rx_total: u64,
    /// Live datapath connections. Distinct from `active_sessions`
    /// (device-sessions) reported at the request level.
    pub clients_connected: u32,
    /// QUIC handshakes accepted since process start.
    pub handshakes_total: u64,
    /// QUIC handshakes that failed since process start.
    pub handshake_failures_total: u64,
    /// RTT percentiles over the live QUIC connections at sample time,
    /// aggregated node-wide (never per client).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_p50_ms: Option<u32>,
    /// 95th percentile RTT (same aggregation as `rtt_p50_ms`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_p95_ms: Option<u32>,
    /// Packets QUIC declared lost, summed over live connections.
    pub quic_lost_packets_total: u64,
    /// Congestion events, summed over live connections.
    pub quic_congestion_events_total: u64,
    /// Whole-box CPU utilisation percentage over the last sample tick.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<f32>,
    /// Resident set size of the exit process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mem_rss_bytes: Option<u64>,
    /// 1-minute load average, scaled by 1000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load1_milli: Option<u32>,
    /// Public-NIC counters (whole interface, not just the tunnel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nic_tx_bytes_total: Option<u64>,
    /// Public-NIC receive counter (whole interface).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nic_rx_bytes_total: Option<u64>,
    /// Public-NIC capacity in Mbit/s when the node knows it; otherwise the
    /// fleet spec supplies it server-side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nic_speed_mbps: Option<u32>,
    /// Seconds since the exit process started.
    pub uptime_secs: u64,
    /// Clients still connected while this exit drains (ADR 36 §6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_clients_remaining: Option<u32>,
}

/// Go/no-go verdict of the exit's first-boot hardware qualification (doc 57).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitHwQualVerdict {
    /// The hardware is fit for a production exit slot.
    Go,
    /// The hardware is NOT fit (see `ExitHwQual::reasons`).
    NoGo,
}

/// First-boot hardware qualification of an exit node (doc 57). The node
/// self-benches its OWN hardware once and reports the verdict so the control
/// plane and the admin panel can decide whether the server is fit for a
/// production exit slot. Contains only hardware characteristics: no user data,
/// no traffic, no secrets (no-log safe, doc 52 invariant I2 style). Reported on
/// the heartbeat; `None` from an exit that pre-dates the self-bench.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExitHwQual {
    /// Go/no-go for a production exit slot.
    pub verdict: ExitHwQualVerdict,
    /// Informational capacity class: `entry` / `standard` / `high` / `unfit`.
    pub capacity_class: String,
    /// Conservative estimated clean single-tunnel throughput (Gbit/s). A
    /// labelled heuristic, not a guarantee.
    pub est_clean_tunnel_gbps: f32,
    /// Semicolon-joined NO_GO reasons; empty on GO.
    #[serde(default)]
    pub reasons: String,
    /// CPU model string, e.g. `AMD EPYC 4484PX 12-Core Processor`.
    pub cpu_model: String,
    /// Logical core count.
    pub cpu_cores: u32,
    /// Whether the CPU exposes AES-NI (hardware AES). Absent = crypto wall.
    pub aes_ni: bool,
    /// AES-256-GCM single-thread throughput at 16 KiB blocks (Gbit/s).
    pub aes256gcm_gbps_per_core: f32,
    /// Public NIC interface name.
    pub nic_iface: String,
    /// NIC link speed (Mbit/s); 0 when unknown.
    pub nic_speed_mbps: u32,
    /// Single-core UDP loopback packet rate: the datapath predictor.
    pub udp_loopback_pps: u32,
    /// Single-core UDP loopback throughput (Gbit/s).
    pub udp_loopback_gbps: f32,
    /// Unix epoch seconds when the bench ran.
    pub measured_at: u64,
}

impl ExitHwQual {
    /// Minimum single-core UDP-loopback packet rate for a prod exit: below this
    /// the datapath predicts under ~1.3 Gbit/s clean single-tunnel (doc 57 §3).
    pub const MIN_UDP_PPS: u32 = 120_000;
    /// Minimum NIC link speed for a prod exit (Mbit/s).
    pub const MIN_NIC_MBPS: u32 = 1000;
    /// Minimum logical cores.
    pub const MIN_CORES: u32 = 2;

    /// Pure go/no-go evaluation from the raw hardware metrics (doc 57 §3). Sets
    /// `verdict`, `reasons`, `capacity_class` and `est_clean_tunnel_gbps`; the
    /// caller fills the measured fields first. Kept pure and total for testing.
    #[must_use]
    pub fn evaluate(mut self) -> Self {
        let mut reasons: Vec<&str> = Vec::new();
        if !self.aes_ni {
            reasons.push("no AES-NI (userspace QUIC crypto would bottleneck)");
        }
        if self.nic_speed_mbps < Self::MIN_NIC_MBPS {
            reasons.push("NIC below 1 Gbit/s (need >=1G for a prod exit)");
        }
        if self.cpu_cores < Self::MIN_CORES {
            reasons.push("fewer than 2 cores");
        }
        if self.udp_loopback_pps < Self::MIN_UDP_PPS {
            reasons.push("UDP loopback below 120k pps (datapath too slow)");
        }
        self.verdict = if reasons.is_empty() {
            ExitHwQualVerdict::Go
        } else {
            ExitHwQualVerdict::NoGo
        };
        self.reasons = reasons.join("; ");
        self.capacity_class = match self.verdict {
            ExitHwQualVerdict::NoGo => "unfit",
            ExitHwQualVerdict::Go
                if self.nic_speed_mbps >= 10_000 && self.udp_loopback_pps >= 250_000 =>
            {
                "high"
            }
            ExitHwQualVerdict::Go if self.nic_speed_mbps >= 2500 => "standard",
            ExitHwQualVerdict::Go => "entry",
        }
        .to_string();
        // Estimated clean single-tunnel = min(NIC, single-core datapath x the
        // measured multi-queue uplift ~2x), 0 on NO_GO.
        self.est_clean_tunnel_gbps = if self.verdict == ExitHwQualVerdict::NoGo {
            0.0
        } else {
            let nic = self.nic_speed_mbps as f32 / 1000.0;
            (self.udp_loopback_gbps * 2.0).min(nic)
        };
        self
    }

    /// Human-readable one-liner for logs and the admin panel. Hardware only, so
    /// it is safe to log (no-log discipline).
    #[must_use]
    pub fn summary(&self) -> String {
        let verdict = match self.verdict {
            ExitHwQualVerdict::Go => "GO",
            ExitHwQualVerdict::NoGo => "NO_GO",
        };
        let reasons = if self.reasons.is_empty() {
            String::new()
        } else {
            format!(" [{}]", self.reasons)
        };
        format!(
            "{verdict}: {}-class, {}c {}, NIC {}Mb/s, AES-NI {} ({:.1}Gb/s/core), UDP-loop {}pps/{:.2}Gb/s, est ~{:.1}Gb/s clean single-tunnel{reasons}",
            self.capacity_class,
            self.cpu_cores,
            self.cpu_model,
            self.nic_speed_mbps,
            if self.aes_ni { "yes" } else { "no" },
            self.aes256gcm_gbps_per_core,
            self.udp_loopback_pps,
            self.udp_loopback_gbps,
            self.est_clean_tunnel_gbps,
        )
    }
}

/// `POST /v1/exits/register` response body (ADR 36). The heartbeat is the
/// piggyback channel that tells the exit whether it has been drained for
/// maintenance: when `drain` is `Some`, the exit signals its connected
/// clients to migrate (in-band `ExitDraining`) and hard-closes the
/// stragglers at the deadline. Absent (`None`) on a normal heartbeat.
///
/// Forward compatible: `drain` is `#[serde(default)]`, so adding more
/// directive fields later, or a present body that omits `drain`,
/// deserializes cleanly to `drain = None`. (Client and API are always
/// redeployed together per the pre-production doctrine, so the legacy
/// 204-empty-body case never coexists with this 200-JSON one: an empty
/// body would NOT parse as a default struct, by design we never hit it.)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterExitResponse {
    /// Present iff the operator has drained this exit. Carries the
    /// deadline + opaque reason the exit relays to clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain: Option<DrainDirective>,
    /// Present iff the rollout controller wants this node on another
    /// release (doc 54). The signed manifest is embedded verbatim: the
    /// node re-verifies it against its pinned offline signer key, so
    /// the transport (and warren-api itself) adds no update authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<SignedReleaseManifest>,
}

/// Where an exit's update agent stands, reported on each heartbeat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitUpdateStatus {
    /// Current agent state.
    pub state: ExitUpdateState,
    /// Release the agent is working toward (or last applied), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,
    /// Redacted failure summary when `state` is `failed` (never carries
    /// identity material or secrets; no-log discipline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Update-agent states (doc 54 §4). Wire values are lowercase
/// snake_case; new states may be appended, so consumers must treat the
/// enum as open-ended: an unrecognized wire token deserializes to
/// [`ExitUpdateState::Unknown`] instead of failing the whole heartbeat
/// (a newer exit must never break an older server's parse).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExitUpdateState {
    /// No update in flight; running == last authorized release.
    Idle,
    /// Manifest accepted; downloading / hashing the binary.
    Staging,
    /// Binary staged and verified; waiting for the privileged swapper.
    Staged,
    /// The privileged updater is installing + restarting the service.
    Swapping,
    /// Running binary matches the manifest's release.
    Applied,
    /// The update could not be applied (see `error`).
    Failed,
    /// Applied in RAM but the A/B slot persist is pending (e.g. GRUB
    /// nodes where the automated slot bake is not yet safe).
    PersistPending,
    /// Catch-all for a state minted by a newer peer. Receive-side only:
    /// nothing ever serializes it deliberately.
    #[serde(other)]
    Unknown,
}

/// Maintenance-drain directive handed to an exit on its heartbeat
/// (ADR 36). Mirrors `WarrenControlMessage::ExitDraining`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainDirective {
    /// Absolute Unix epoch seconds after which the exit hard-closes
    /// still-connected clients.
    pub deadline_unix_secs: u64,
    /// Opaque reason (`0` = maintenance).
    pub reason_code: u8,
}

/// `POST /v1/exits/enroll` request body (consumed by warren-exit).
#[derive(Clone, Serialize, Deserialize)]
pub struct EnrollExitRequest {
    /// Single-use enrollment token (`wkey-exit-<id>-<secret>`).
    pub token: String,
}

impl fmt::Debug for EnrollExitRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollExitRequest")
            // Redacted: the single-use secret must never appear in logs.
            .field("token", &"<redacted>")
            .finish()
    }
}

/// `POST /v1/exits/enroll` response body. The scope is authoritative;
/// the exit must advertise this on subsequent register heartbeats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollExitResponse {
    /// Public id of the consumed token (audit reference).
    pub token_id: TokenId,
    /// Scope inherited from the token at creation time.
    pub scope_country: CountryCode,
    /// Scope inherited from the token.
    pub scope_city: String,
    /// Scope inherited from the token.
    pub scope_weight: u64,
}

// ---------------------------------------------------------------------------
// Admin: subscriptions.
// ---------------------------------------------------------------------------

/// Admin row of one subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSubscriptionRow {
    /// Subscriber SS58 address (`wb…`).
    pub pubkey_ss58: PubkeySs58,
    /// Unix epoch seconds of expiry.
    pub expires_at: u64,
    /// Server-derived activity flag (`expires_at > now`).
    pub is_active: bool,
}

/// Response for `GET /v1/admin/subscriptions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSubscriptionsResponse {
    /// All known subscriptions.
    pub subscriptions: Vec<AdminSubscriptionRow>,
    /// Total count.
    pub total: u64,
}

// ---------------------------------------------------------------------------
// Admin: exits.
// ---------------------------------------------------------------------------

/// Admin view of an exit's API-resolved geoip for one endpoint address.
/// This is the egress IP's real-world geolocation (what geo-restricted
/// services see), kept internal and **never** published on the public
/// `/v1/exits` list - only surfaced to the admin panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminExitGeoIp {
    /// ISO 3166-1 alpha-2 country code (as resolved by the GeoIP DB).
    pub country: String,
    /// City name (as resolved).
    pub city: String,
    /// Autonomous System number, when resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// DB edition + date the resolution came from (e.g.
    /// `GeoLite2-City-2026-06`).
    pub source: String,
}

/// Admin view of one dial listener on an exit endpoint. Field-identical
/// to [`RegisterListener`] today but kept distinct so the admin view
/// can grow fields the exit-facing type never carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminExitListener {
    /// Listening port.
    pub port: u16,
    /// Wire transport (`quic`, ...).
    pub transport: String,
    /// ALPN token offered in the handshake (`h3`).
    pub alpn: String,
}

/// Admin view of one exit endpoint, with the full per-endpoint metadata
/// the public list intentionally drops (direction flags, listeners,
/// resolved geoip).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminExitEndpoint {
    /// IP literal (no port; ports live in `listeners`).
    pub addr: String,
    /// `"ipv4"` / `"ipv6"`.
    pub family: String,
    /// `true` if clients dial this address.
    pub ingress: bool,
    /// `true` if the exit egresses internet traffic from this source IP.
    pub egress: bool,
    /// Dial listeners (empty for an egress-only endpoint).
    pub listeners: Vec<AdminExitListener>,
    /// API-resolved geoip of `addr`, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip: Option<AdminExitGeoIp>,
}

/// Admin row of one exit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminExitRow {
    /// Exit signing identity, as a Warren SS58 address (`wb…`). This is
    /// the exit's auth/registry identity (the `X-Warren-PubKey` value it
    /// signs heartbeats with), not its TLS descriptor key.
    pub pubkey_ss58: PubkeySs58,
    /// Stable operator-assigned identifier (16-byte hex). Persists
    /// across legitimate pubkey rotations so the admin panel can
    /// track an exit's lifecycle independently of its current
    /// signing key.
    pub exit_id: ExitId,
    /// Public addresses where the exit accepts traffic, flattened to
    /// `addr:port` dial sockets (kept for the existing panel column and
    /// back-compat). The full per-endpoint detail is in `endpoints`.
    pub ip_addrs: Vec<String>,
    /// Structural roles derived from the endpoints (`entry` / `relay` /
    /// `exit`). The public list drops this; the admin panel shows it.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Full per-endpoint detail (direction flags, listeners, resolved
    /// geoip) - the admin superset the public `/v1/exits` list omits.
    #[serde(default)]
    pub endpoints: Vec<AdminExitEndpoint>,
    /// ISO 3166-1 alpha-2 country code.
    pub country: CountryCode,
    /// City name.
    pub city: String,
    /// Selector weight.
    pub weight: u64,
    /// Active flag (false = drained).
    pub active: bool,
    /// Unix epoch of last heartbeat.
    pub last_seen: u64,
    /// Server-derived staleness.
    pub seconds_since_last_seen: u64,
    /// 64-char hex of the exit's X25519 HPKE multi-hop recipient pubkey,
    /// if the exit published one on heartbeat. Consumed by the offline
    /// `wapi admin-publish-multihop-directory` tool to mint signed
    /// multi-hop exit descriptors. `None` for legacy single-hop exits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_x25519_multihop_pubkey_hex: Option<String>,
    /// Build identifier the exit advertised on its last heartbeat
    /// (e.g. `v0.3.7-2-gabc1234`). `None` for legacy exit binaries
    /// that pre-date version reporting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Live client-session count the exit last reported (ADR 36 §6):
    /// the operator watches this drop to 0 on a drained exit before
    /// cutting it. `None` if the exit does not report it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_sessions: Option<u32>,
    /// X.509 cover domain the exit registered (ADR-0004), if any. Consumed by
    /// the offline `wapi admin-publish-multihop-directory` tool to stamp the
    /// `cover_domain` onto both the relay and exit descriptors so multi-hop
    /// clients dial the node in X.509 mode. `None` for RPK exits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cover_domain: Option<String>,
    /// First-boot hardware qualification verdict the exit last reported
    /// (doc 57), surfaced on the admin exit-detail page. `None` if the node has
    /// not reported one (legacy binary, or the self-bench has not run yet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hwqual: Option<ExitHwQual>,
}

/// Admin row of one uploaded exit release (doc 54).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminReleaseRow {
    /// Target build identifier.
    pub version: String,
    /// Rollout channel.
    pub channel: String,
    /// Hex SHA-256 of the authorized binary.
    pub binary_sha256_hex: String,
    /// Exact binary size in bytes.
    pub binary_size: u64,
    /// Monotonic manifest generation.
    pub generation: u64,
    /// Unix epoch seconds after which the manifest is stale.
    pub expires_at: u64,
    /// Unix epoch seconds the release was uploaded.
    pub created_at: u64,
    /// True once the binary bytes were uploaded and hash-verified.
    pub binary_uploaded: bool,
}

/// Response for `GET /v1/admin/releases`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminReleasesResponse {
    /// Catalog, newest generation first.
    pub releases: Vec<AdminReleaseRow>,
}

/// Request for `POST /v1/admin/releases`: the offline-signed manifest,
/// embedded verbatim. The server re-verifies the signature against its
/// pinned release-signer key before cataloguing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCreateReleaseRequest {
    /// Signed manifest produced by `wapi admin-sign-release`.
    pub manifest: SignedReleaseManifest,
}

/// Request for `POST /v1/admin/rollouts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCreateRolloutRequest {
    /// Target release version (must be catalogued with its binary).
    pub version: String,
    /// Canary node override. `None` lets the server pick the
    /// least-loaded active exit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary_pubkey_ss58: Option<PubkeySs58>,
}

/// One node row inside an admin rollout view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminRolloutNodeRow {
    /// Node pubkey (SS58).
    pub pubkey_ss58: PubkeySs58,
    /// True for the canary node.
    pub is_canary: bool,
    /// State-machine token (`waiting`, `pending`, `draining`,
    /// `swapping`, `verifying`, `done`, `failed`, `rolled_back`).
    /// Deliberately a `String`, not an enum: the vocabulary is owned by
    /// the server-side controller and only displayed by the admin
    /// panel, so a new state must not break an older panel's parse.
    pub state: String,
    /// Version the node ran before the rollout (rollback target).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_version: Option<String>,
    /// Redacted failure summary when `state` is `failed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Unix epoch seconds of the last transition.
    pub updated_at: u64,
}

/// Admin view of one rollout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminRolloutResponse {
    /// Store-assigned identifier.
    pub id: i64,
    /// Target release version.
    pub version: String,
    /// Whole-rollout status token (`active`, `completed`,
    /// `rolled_back`, `aborted`). A `String` for the same reason as
    /// [`AdminRolloutNodeRow::state`]: server-owned, display-only
    /// vocabulary.
    pub status: String,
    /// Unix epoch seconds the rollout was created.
    pub created_at: u64,
    /// Per-node rows, canary first.
    pub nodes: Vec<AdminRolloutNodeRow>,
}

/// One audit line for `GET /v1/admin/rollouts/audit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminRolloutAuditRow {
    /// Unix epoch seconds of the action.
    pub at: u64,
    /// Who acted: a redacted admin pubkey prefix, `controller` (the
    /// background rollout controller), or `node` (a node self-reporting
    /// an update failure).
    pub actor: String,
    /// Action token.
    pub action: String,
    /// Free-form JSON detail, re-serialized as a string.
    pub detail_json: String,
}

/// Response for `GET /v1/admin/rollouts/audit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminRolloutAuditResponse {
    /// Most recent lines, newest first.
    pub rows: Vec<AdminRolloutAuditRow>,
}

/// Response for `GET /v1/admin/exits`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminExitsResponse {
    /// Every registered exit, including drained / stale.
    pub exits: Vec<AdminExitRow>,
    /// Total count.
    pub total: u64,
}

/// Response for `GET /v1/admin/version` (served by both `warren-api`
/// and `warren-admin`). Lets an operator verify which commit is
/// *actually* running in production. Gated behind the admin
/// signed-request envelope so the exact build is never disclosed to
/// anonymous probes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminVersionResponse {
    /// Which binary answered: `"warren-api"` or `"warren-admin"`.
    pub service: String,
    /// Release identifier tracking the git tags (e.g. `v0.3.1` or
    /// `v0.3.0-7-g4d607b92`). The authoritative "which release is
    /// deployed" string - unlike `version`, it follows the release tags.
    ///
    /// `#[serde(default)]`: this field was added after the first
    /// deployment of the version endpoint, so a newer client must still
    /// decode an OLDER server's response (which omits it). An empty
    /// `release` therefore means "deployed build predates this field".
    #[serde(default)]
    pub release: String,
    /// Crate semver from `Cargo.toml` (e.g. `0.3.0`). Internal crate
    /// version; may lag the release line - prefer `release`.
    pub version: String,
    /// Full 40-char git commit SHA, or `"unknown"` if the build had no
    /// SHA injected (no `.git` and no `WARREN_GIT_SHA` build arg).
    pub git_sha: String,
    /// First 12 chars of the commit SHA, or `"unknown"`.
    pub git_short: String,
    /// UTC RFC3339 build timestamp, or `"unknown"`.
    pub build_time: String,
    /// Server clock (Unix seconds) at response time. Proves the answer
    /// is fresh (the process is alive now), not a cached artifact.
    pub now_unix_secs: u64,
}

// ---------------------------------------------------------------------------
// Admin: vouchers.
// ---------------------------------------------------------------------------

/// Admin row of one voucher (hash only - never the secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminVoucherRow {
    /// SHA-256 of the secret, hex-encoded.
    pub secret_hash_hex: String,
    /// Subscription duration this voucher grants.
    pub duration_secs: u64,
    /// Payment channel.
    pub payment_method: PaymentMethod,
    /// Unix epoch of issuance.
    pub created_at: u64,
    /// Some(unix) once redeemed.
    pub redeemed_at: Option<u64>,
    /// Whether someone has claimed it.
    pub is_redeemed: bool,
    /// Redeeming wallet SS58 address (`wb…`) if redeemed.
    pub redeemed_by_pubkey_ss58: Option<PubkeySs58>,
    /// `Some(unix)` once the admin cancelled the voucher; future
    /// `/v1/register` attempts with the matching secret return 410.
    /// `#[serde(default)]` keeps wire-compat with older servers that
    /// pre-date the cancel feature.
    #[serde(default)]
    pub cancelled_at: Option<u64>,
    /// How many distinct accounts may redeem this voucher, each at most
    /// once. `Some(1)` = classic single-use; `None` = unlimited
    /// campaign. Defaults to `Some(1)` when the server pre-dates
    /// campaign vouchers (everything it mints is single-use).
    #[serde(default = "default_single_use")]
    pub max_redemptions: Option<u64>,
    /// `Some(unix)` deadline after which the voucher is no longer
    /// redeemable. Campaign vouchers always carry one.
    #[serde(default)]
    pub valid_until: Option<u64>,
    /// Distinct accounts that consumed this voucher through the
    /// multi-redemption gate (always 0 for single-use vouchers, whose
    /// consumption is `redeemed_at`/`is_redeemed`).
    #[serde(default)]
    pub redemptions_count: u64,
}

/// Serde default for [`AdminVoucherRow::max_redemptions`]: a server
/// that omits the field pre-dates campaigns and only mints single-use.
fn default_single_use() -> Option<u64> {
    Some(1)
}

/// Response for `GET /v1/admin/vouchers`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminVouchersResponse {
    /// Every voucher record (hash-only).
    pub vouchers: Vec<AdminVoucherRow>,
    /// Total count.
    pub total: u64,
}

// ---------------------------------------------------------------------------
// Admin: paginated Billing views (subscribers + credits + detail).
// ---------------------------------------------------------------------------

/// One page of subscribers for `GET /v1/admin/subscribers`.
///
/// Unlike [`AdminSubscriptionsResponse`] (which ships the whole table),
/// this is the scale-hardened view: the server filters, orders and
/// slices so the payload stays bounded at thousands of subscribers.
/// Rows are ordered `expires_at DESC, pubkey_ss58 ASC`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSubscribersPageResponse {
    /// This page's subscriber rows.
    pub subscribers: Vec<AdminSubscriptionRow>,
    /// Total rows matching the filter across every page (page-count UI).
    pub total: u64,
    /// Zero-based offset this page started at (echoed back).
    pub offset: u64,
    /// Page size requested (echoed back).
    pub limit: u32,
}

/// One page of credits (vouchers) for `GET /v1/admin/credits`.
///
/// Rows are ordered `created_at DESC`. The default status filter is
/// "open" (un-redeemed, un-cancelled) - the actionable credits; redeemed
/// vouchers surface under their subscriber's detail instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCreditsPageResponse {
    /// This page's voucher rows (hash-only).
    pub credits: Vec<AdminVoucherRow>,
    /// Total rows matching the filter across every page.
    pub total: u64,
    /// Zero-based offset this page started at (echoed back).
    pub offset: u64,
    /// Page size requested (echoed back).
    pub limit: u32,
}

/// Response for `GET /v1/admin/subscribers/{pubkey_ss58}` - the
/// server-side join behind the subscriber detail page: the subscription
/// itself, every credit that funded it, and its active port-forwards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminSubscriberDetailResponse {
    /// The subscription (expiry + active flag).
    pub subscription: AdminSubscriptionRow,
    /// Vouchers redeemed by this subscriber, most recently redeemed
    /// first. Empty when the subscription was created by other means
    /// (e.g. a direct register without a voucher).
    pub funding_vouchers: Vec<AdminVoucherRow>,
    /// Port-forward allocations currently owned by this subscriber.
    pub port_forwards: Vec<AdminPortForwardRow>,
}

/// Request body for `POST /v1/admin/vouchers`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCreateVoucherRequest {
    /// Subscription duration the voucher will grant.
    pub duration_secs: u64,
    /// Payment channel.
    pub payment_method: PaymentMethod,
    /// Account quota: absent = 1 (single-use), N >= 1 otherwise.
    /// Mutually exclusive with `unlimited_redemptions`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_redemptions: Option<u64>,
    /// `true` = no account quota (the mandatory deadline is the
    /// limiter). Mutually exclusive with `max_redemptions`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unlimited_redemptions: bool,
    /// Redemption deadline (unix seconds). MANDATORY whenever the
    /// quota is not 1; the server refuses a deadline-less campaign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until_unix_secs: Option<u64>,
}

/// Response from `POST /v1/admin/vouchers`. The secret is shown
/// **once** - never re-derivable from the hash.
#[derive(Clone, Serialize, Deserialize)]
pub struct AdminCreateVoucherResponse {
    /// Plain-text Crockford-32 voucher in dashed display form
    /// `XXXX-XXXX-XXXX-XXXX` (19 chars). Shown to the human **once**.
    pub voucher_secret: String,
    /// SHA-256 hex of the secret (audit identifier).
    pub secret_hash_hex: String,
    /// Echo of the granted duration.
    pub duration_secs: u64,
    /// Echo of the account quota (`None` = unlimited). Defaults to
    /// single-use when the server pre-dates campaign vouchers.
    #[serde(default = "default_single_use")]
    pub max_redemptions: Option<u64>,
    /// Echo of the redemption deadline, when one was set.
    #[serde(default)]
    pub valid_until_unix_secs: Option<u64>,
}

impl fmt::Debug for AdminCreateVoucherResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminCreateVoucherResponse")
            // Redacted: the show-once secret must never appear in logs.
            .field("voucher_secret", &"<redacted>")
            .field("secret_hash_hex", &self.secret_hash_hex)
            .field("duration_secs", &self.duration_secs)
            .field("max_redemptions", &self.max_redemptions)
            .field("valid_until_unix_secs", &self.valid_until_unix_secs)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Admin: port-forward allocations.
// ---------------------------------------------------------------------------

/// Admin row of one port-forward allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPortForwardRow {
    /// Owning client pubkey. `None` when the exit pushed the
    /// snapshot before its tunnel session map had resolved the
    /// (IPv4 -> pubkey) mapping for this internal IP, or when the
    /// mapping has been torn down between allocation and capture.
    /// The admin UI renders such rows as "unknown".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_pubkey_ss58: Option<PubkeySs58>,
    /// Hosting exit signing identity, as a Warren SS58 address (`wb…`).
    pub exit_pubkey_ss58: PubkeySs58,
    /// Allocated port.
    pub port: u16,
    /// Unix epoch of expiry.
    pub expires_at: u64,
    /// Unix epoch at which the hosting exit assembled the snapshot
    /// this row was carried in. Drives the admin "last sync N
    /// seconds ago" badge. Optional for wire-compat with pre-mirror
    /// servers; pre-mirror builds emit `None` and the UI then hides
    /// the freshness column.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_last_sync_unix_secs: Option<u64>,
}

/// Response for `GET /v1/admin/port-forward/allocations`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPortForwardsResponse {
    /// All active allocations.
    pub allocations: Vec<AdminPortForwardRow>,
    /// Total count.
    pub total: u64,
}

/// Admin row of one exit's NAT-PMP allocator counters. The
/// human-readable companion to the Prometheus exporter: it carries the
/// same per-exit `ExitPortForwardMetrics` block so the admin panel can
/// render a port-pressure view (how often clients hit a port conflict
/// when a followed port cannot be kept on a new exit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPortForwardMetricsRow {
    /// Hosting exit signing identity, as a Warren SS58 address (`wb…`).
    pub exit_pubkey_ss58: PubkeySs58,
    /// Latest allocator counters this exit reported.
    pub metrics: ExitPortForwardMetrics,
}

/// Response for `GET /v1/admin/port-forward/metrics.json` - the JSON
/// companion of the Prometheus `metrics` endpoint, structured so the
/// admin panel can render the per-exit port-pressure counters. Exits
/// that never pushed a metrics block are absent (no phantom zeros).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPortForwardMetricsResponse {
    /// Per-exit allocator counters.
    pub metrics: Vec<AdminPortForwardMetricsRow>,
    /// Total count.
    pub total: u64,
}

// ---------------------------------------------------------------------------
// Exit -> API port-forward sync push.
//
// The NAT-PMP server on the exit owns the source of truth for active
// mappings (RAM, no-log). The API only mirrors the snapshot so that the
// admin panel can display it and so `release_all_for_client` (account
// delete) can trigger a revocation broadcast. This DTO carries one full
// snapshot per push; the API replaces its mirror atomically on receipt.
// ---------------------------------------------------------------------------

/// Transport protocol carried in an Exit -> API allocation row.
///
/// Mirrors `warrenguard_natpmp_server::Proto`. Kept here to avoid pulling
/// the server crate into clients that only consume the wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortForwardProto {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

/// One active NAT-PMP allocation as observed by the exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitPortForwardAllocation {
    /// Internal tunnel IP of the owning client (10.66.x.y).
    pub internal_ip: std::net::Ipv4Addr,
    /// Allocated external port (49152-65535).
    pub external_port: u16,
    /// Client-bound port the DNAT redirects to.
    pub internal_port: u16,
    /// Transport protocol.
    pub proto: PortForwardProto,
    /// Mapping expiration as unix epoch seconds (wall clock, NOT
    /// `Instant`). The exit converts its internal `Instant` to wall
    /// clock at capture time so the API can decide staleness without
    /// trusting the exit's monotonic clock.
    pub expires_at_unix_secs: u64,
    /// SS58 address of the client owning the mapping, resolved via the
    /// tunnel peer map. May be `None` if the exit could not resolve
    /// it at capture time (transient race during connection
    /// teardown); the API renders such rows as "unknown" in the
    /// admin view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_pubkey_ss58: Option<PubkeySs58>,
}

/// Monotonic event counters from the exit's NAT-PMP allocator,
/// pushed to the API alongside each sync snapshot so the admin
/// `/metrics` endpoint can expose them in Prometheus text format.
/// Counters only ever increment; the API stores the latest value
/// per exit and renders the union across exits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitPortForwardMetrics {
    /// Successful allocations since the exit booted.
    #[serde(default)]
    pub allocations_total: u64,
    /// Successful releases (organic or eviction-triggered).
    #[serde(default)]
    pub releases_total: u64,
    /// Forced releases triggered by an allowlist eviction or an
    /// admin revoke. Subset of `releases_total`.
    #[serde(default)]
    pub evictions_total: u64,
    /// Allocate attempts refused because of the per-client quota.
    #[serde(default)]
    pub quota_exceeded_total: u64,
    /// Allocate attempts refused because of the per-source rate
    /// limit.
    #[serde(default)]
    pub rate_limited_total: u64,
    /// Allocate attempts refused because the port pool is full.
    #[serde(default)]
    pub exhausted_total: u64,
}

/// Body of `POST /v1/exits/port-forward/sync`. The exit signs the
/// request like any other Ed25519 endpoint (X-Warren-PubKey carries the
/// exit identity); the API uses the signing pubkey to scope the mirror
/// to that exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitPortForwardSyncRequest {
    /// Random nonce identifying the exit *process instance*. Drawn
    /// once at process start and constant for the lifetime of that
    /// process. It lets the API distinguish "a newer push from the
    /// same running exit" (compare `generation`) from "the exit
    /// restarted" (the `instance_id` changed, so `generation` reset
    /// to 0 and must NOT be compared against the previous instance's
    /// counter). Without it, a restart freezes the admin mirror until
    /// the fresh per-process counter out-grows the pre-restart one
    /// (days). `#[serde(default)]` keeps the wire format
    /// backward-compatible with pre-instance-id exits, which then
    /// fall back to the legacy generation-only behaviour.
    #[serde(default)]
    pub instance_id: u64,
    /// Monotonic counter incremented on every push by the exit,
    /// *within a single process instance* (resets to 0 on restart -
    /// see `instance_id`). The API drops `generation <= last_seen`
    /// for the same `instance_id` to ignore out-of-order retries.
    pub generation: u64,
    /// Wall-clock time at which the exit assembled the snapshot.
    /// Used by the admin UI to display "last sync N seconds ago".
    pub captured_at_unix_secs: u64,
    /// Every active mapping at capture time. An empty vec is a valid
    /// snapshot meaning "no port forwards on this exit right now".
    pub allocations: Vec<ExitPortForwardAllocation>,
    /// Optional allocator counters snapshot. Optional so the wire
    /// format stays backward-compatible with pre-D3 exits that
    /// never emit it (the admin `/metrics` view then folds in zeros
    /// for that exit until it upgrades).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<ExitPortForwardMetrics>,
}

/// Response body of `POST /v1/exits/port-forward/sync`. Carries the
/// list of ports the admin requested to revoke since the previous
/// push so the exit can call `Allocator::take_active_for_port` +
/// the cleanup worker for each entry. Empty vec is the steady state
/// (no admin action). A pre-revoke server (or one wired against an
/// older API) sends an empty list, which the new exit handles as a
/// no-op.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ExitPortForwardSyncResponse {
    /// External ports the exit must release on receipt. The
    /// allocator entry, the nftables map element, and the mirror
    /// row all get torn down. Idempotent: the API only enqueues a
    /// port once per admin request, and a duplicate take on the
    /// exit side returns `None`.
    #[serde(default)]
    pub pending_revoke_ports: Vec<u16>,
}

// ---------------------------------------------------------------------------
// Admin: pending vouchers.
// ---------------------------------------------------------------------------

/// Admin row of one in-flight pending voucher (metadata only - the
/// secret never leaves the server through this endpoint).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPendingVoucherRow {
    /// PSP-side opaque identifier.
    pub pending_id: String,
    /// Unix epoch of expiry.
    pub expires_at: u64,
}

/// Response for `GET /v1/admin/pending-vouchers`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPendingVouchersResponse {
    /// Every in-flight pending voucher.
    pub pending: Vec<AdminPendingVoucherRow>,
    /// Total count.
    pub total: u64,
}

// ---------------------------------------------------------------------------
// Admin: pricing.
// ---------------------------------------------------------------------------

/// Admin row of one pricing tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPricingTier {
    /// Persistent row id assigned by PostgreSQL.
    pub id: i64,
    /// Currency token (`"EUR"`, `"SAT"`, ...).
    pub currency: Currency,
    /// Lower bound (smallest unit of the currency).
    pub min_amount_units: u64,
    /// Subscription duration granted at this tier.
    pub duration_secs: u64,
    /// `false` once the admin soft-deleted the tier.
    pub enabled: bool,
}

/// Response for `GET /v1/admin/pricing`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPricingResponse {
    /// Every tier, enabled + soft-deleted, in (currency, min_amount_units) order.
    pub tiers: Vec<AdminPricingTier>,
    /// Total count, matches the other admin list envelopes.
    #[serde(default)]
    pub total: u64,
}

/// Request body for `POST /v1/admin/pricing/tiers` and
/// `PUT /v1/admin/pricing/tiers/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPricingTierBody {
    /// Currency token, case-insensitive on the server side.
    pub currency: String,
    /// Inclusive lower bound in the currency's smallest unit.
    pub min_amount_units: u64,
    /// Granted duration in seconds.
    pub duration_secs: u64,
}

/// Response body of `POST /v1/admin/pricing/tiers`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPricingTierCreatedResponse {
    /// Row id assigned by PostgreSQL on success.
    pub id: i64,
}

/// Request body for `PUT /v1/admin/pricing/ladder`: atomically replace
/// the whole tier ladder of one currency with a linear month ladder
/// (tier k grants k months for `k * price_per_month_units`). The
/// webhook only sees the paid amount, so one tier per purchasable
/// month count is required; this body is the 2-number form of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPricingLadderBody {
    /// Currency token, case-insensitive on the server side.
    pub currency: String,
    /// Price of one month, in the currency's smallest unit.
    pub price_per_month_units: u64,
    /// Ladder depth: tiers are generated for 1..=max_months.
    pub max_months: u32,
}

/// Response body of `PUT /v1/admin/pricing/ladder`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPricingLadderResponse {
    /// Number of enabled tiers after the replace (== max_months).
    pub tiers: u32,
}

// ---------------------------------------------------------------------------
// Admin: enrollment tokens.
// ---------------------------------------------------------------------------

/// `POST /v1/admin/enrollment-tokens` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCreateEnrollmentTokenBody {
    /// ISO 3166-1 alpha-2 country baked into the token.
    pub scope_country: CountryCode,
    /// City label baked into the token.
    pub scope_city: String,
    /// Selector weight baked into the token.
    pub scope_weight: u64,
    /// TTL in seconds. Clamped server-side to `[60, 7d]`.
    pub ttl_seconds: i64,
    /// Optional free-form note (audit). 256 chars max.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// `POST /v1/admin/enrollment-tokens` response body. The clear token
/// is returned **once** here and never again.
#[derive(Clone, Serialize, Deserialize)]
pub struct AdminCreateEnrollmentTokenResponse {
    /// Clear token string `wkey-exit-<id>-<secret>`. Display once.
    pub token: String,
    /// Public id of the token (12 hex chars). Safe to log.
    pub id: TokenId,
    /// Unix seconds at expiry.
    pub expires_at: i64,
    /// Scope echo (mirror of the request, for sanity check).
    pub scope_country: CountryCode,
    /// Scope echo.
    pub scope_city: String,
    /// Scope echo.
    pub scope_weight: u64,
}

impl fmt::Debug for AdminCreateEnrollmentTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminCreateEnrollmentTokenResponse")
            // Redacted: the show-once clear token must never appear in
            // logs; `id` is the log-safe reference.
            .field("token", &"<redacted>")
            .field("id", &self.id)
            .field("expires_at", &self.expires_at)
            .field("scope_country", &self.scope_country)
            .field("scope_city", &self.scope_city)
            .field("scope_weight", &self.scope_weight)
            .finish()
    }
}

/// One row of the admin enrollment-token listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminEnrollmentTokenRow {
    /// Public id of the token (12 hex chars).
    pub id: TokenId,
    /// Unix seconds at creation.
    pub created_at: i64,
    /// Unix seconds at expiry.
    pub expires_at: i64,
    /// `Some(t)` once consumed.
    pub redeemed_at: Option<i64>,
    /// SS58 address of the exit that consumed this token (its auth
    /// identity at enroll time).
    pub redeemed_by: Option<PubkeySs58>,
    /// `Some(t)` once admin-revoked.
    pub revoked_at: Option<i64>,
    /// Scope.
    pub scope_country: CountryCode,
    /// Scope.
    pub scope_city: String,
    /// Scope.
    pub scope_weight: u64,
    /// SS58 address of the admin who minted the token.
    pub created_by: PubkeySs58,
    /// Optional free-form note.
    pub note: Option<String>,
}

/// Envelope for the admin enrollment-token listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminEnrollmentTokensResponse {
    /// Every token row, freshest-first.
    pub tokens: Vec<AdminEnrollmentTokenRow>,
    /// Total count.
    pub total: u64,
}

// ---------------------------------------------------------------------------
// Referral system.
// ---------------------------------------------------------------------------

/// `GET /v1/referral` response. Returns the user's own referral code
/// and stats. The code is created lazily on first call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferralStatusResponse {
    /// The user's shareable referral code (`wref-<16hex>`).
    pub code: String,
    /// Number of referees who used this code.
    pub referral_count: u64,
    /// Total bonus seconds earned from referrals.
    pub earned_bonus_secs: u64,
}

/// Admin row of one referral code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminReferralRow {
    /// Referrer wallet SS58 address (`wb…`).
    pub owner_pubkey_ss58: PubkeySs58,
    /// Code string (`wref-<16hex>`).
    pub code: String,
    /// Unix seconds at creation.
    pub created_at: u64,
    /// Number of times consumed.
    pub times_used: u64,
    /// Total bonus seconds granted to this referrer.
    pub total_bonus_secs: u64,
}

/// Response for `GET /v1/admin/referrals`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminReferralsResponse {
    /// All referral codes.
    pub referrals: Vec<AdminReferralRow>,
    /// Total count.
    pub total: u64,
}

// ---------------------------------------------------------------------------
// Admin: payment ledger.
// ---------------------------------------------------------------------------

/// One row of the accounting ledger for `GET /v1/admin/ledger`.
///
/// By design there are NO identity fields here: no pubkey, no external
/// transaction id, no PSP customer reference. Day-truncation is applied
/// at write time (pattern R2/R6) so the timestamp cannot be used for
/// cross-table timing correlation. This matches the invariants of
/// `warren_api::payment_ledger::LedgerEntry` on the server side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminLedgerRow {
    /// Payment provider (e.g. `"stripe"`, `"btcpay"`, `"monero"`).
    pub provider: String,
    /// Amount in the smallest unit of `currency` (cents for EUR/USD,
    /// satoshi for SAT, ...).
    pub amount_minor: i64,
    /// Currency as an uppercase ISO 4217 token (`"EUR"`, `"SAT"`, ...).
    pub currency: String,
    /// Unix timestamp of the record, truncated to midnight UTC.
    pub created_at: u64,
}

/// Response for `GET /v1/admin/ledger`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminLedgerResponse {
    /// All ledger entries in insertion order.
    pub entries: Vec<AdminLedgerRow>,
    /// Total entry count.
    pub total: u64,
}

// ---------------------------------------------------------------------------
// Admin: Stripe card refund (POST /v1/admin/subscribers/{pubkey}/stripe-refund).
// ---------------------------------------------------------------------------

/// Response for `POST /v1/admin/subscribers/{pubkey_ss58}/stripe-refund`.
///
/// Returned on HTTP 200 when the Stripe refund API accepted the charge.
/// `refunded` is always `true` on a 200 response. `subscription_expired`
/// is `true` when the Warren subscription was also expired (it may be
/// `false` if the subscriber had no active subscription at the time of
/// the call, which is still a valid outcome since the card refund itself
/// succeeded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminStripeRefundResponse {
    /// The Stripe refund id (e.g. `re_3Ox...`).
    pub stripe_refund_id: String,
    /// Always `true` on a 200 response.
    pub refunded: bool,
    /// `true` when the Warren subscription was expired as part of this
    /// call; `false` when no subscription row was found (refund still
    /// succeeded on Stripe's side).
    pub subscription_expired: bool,
}

// ---------------------------------------------------------------------------
// Admin: Google Play refund (POST /v1/admin/subscribers/{pubkey}/google-refund).
// ---------------------------------------------------------------------------

/// Response for `POST /v1/admin/subscribers/{pubkey_ss58}/google-refund`.
///
/// Returned on HTTP 200 when the Google Play Developer API accepted the
/// `orders.refund` call (with `revoke=true`). `refunded` is always `true`
/// on a 200 response. `subscription_expired` is `true` when the Warren
/// subscription was also expired; it may be `false` if the subscriber had
/// no active subscription at the time of the call (the Google refund
/// itself still succeeded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminGoogleRefundResponse {
    /// Always `true` on a 200 response.
    pub refunded: bool,
    /// `true` when the Warren subscription was expired as part of this
    /// call; `false` when no subscription row was found.
    pub subscription_expired: bool,
}

// ---------------------------------------------------------------------------
// EU CRD art. 11a withdrawal queue (POST /v1/withdrawal + admin processing).
// ---------------------------------------------------------------------------

/// Request body for `POST /v1/withdrawal` (no-auth, website-facing).
///
/// The consumer exercises their 14-day right of withdrawal from the
/// website checkout. The only value carried is the Stripe payment
/// reference of their purchase (`pi_…` payment intent or `ch_…` charge):
/// no name, no email, no reason. Identity stays with Stripe; the operator
/// resolves the reference there to issue the refund.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalRequestBody {
    /// Stripe payment reference of the purchase to withdraw from.
    pub payment_ref: String,
}

/// 200 response for `POST /v1/withdrawal`.
///
/// `reference` is a random acknowledgement id the consumer keeps as proof
/// of their declaration (durable-medium acknowledgement, art. 11/13 CRD).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalAck {
    /// Random reference id for the recorded declaration.
    pub reference: String,
}

/// One row of the admin withdrawal queue.
///
/// Holds only the payment reference and processing fields: no identity.
/// The operator cross-references `payment_ref` in the Stripe dashboard to
/// see the customer and issue the refund.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminWithdrawalRow {
    /// Random reference id (also the Stripe refund idempotency key).
    pub id: String,
    /// Stripe payment reference the refund is issued against.
    pub payment_ref: String,
    /// Processing status: `"pending"`, `"refunded"`, or `"rejected"`.
    pub status: String,
    /// Unix timestamp the request was declared, midnight-truncated.
    pub created_at: u64,
    /// Unix timestamp the request was processed, midnight-truncated;
    /// `None` while pending.
    pub processed_at: Option<u64>,
}

/// Response for `GET /v1/admin/withdrawals`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminWithdrawalsResponse {
    /// All withdrawal requests in declaration order.
    pub requests: Vec<AdminWithdrawalRow>,
    /// Total request count.
    pub total: u64,
}

/// Optional request body for `POST /v1/admin/withdrawals/{id}/refund`.
///
/// An empty (or absent) body keeps the historical behavior: the server
/// enforces the 14-day withdrawal window (plus a 2-day grace for the
/// day-truncated declaration date) against the payment's Stripe creation
/// time and 422s with [`AdminWithdrawalOutOfWindow`] when exceeded.
/// `override:true` is the operator's explicit decision to refund anyway;
/// warren-admin records it under a distinct audit action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdminWithdrawalRefundBody {
    /// `true` to refund even when the request was filed outside the
    /// 14-day withdrawal window. Defaults to `false` (window enforced).
    #[serde(rename = "override", default)]
    pub override_window: bool,
}

/// 422 body for `POST /v1/admin/withdrawals/{id}/refund` when the request
/// was filed outside the 14-day withdrawal window (plus grace) and no
/// override was supplied. Machine-read by warren-admin to offer the
/// clearly-labeled "Refund anyway" secondary action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminWithdrawalOutOfWindow {
    /// Always `"out_of_window"`. Discriminates this 422 from a Stripe
    /// refund rejection (which carries a different `error` string).
    pub error: String,
    /// Days elapsed between the payment's Stripe creation time and the
    /// withdrawal declaration (rounded up).
    pub payment_age_days: u64,
}

/// Response for the admin process endpoints
/// (`POST /v1/admin/withdrawals/{id}/refund` and `.../reject`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminWithdrawalProcessResponse {
    /// The request reference id that was processed.
    pub id: String,
    /// New status after processing (`"refunded"` or `"rejected"`).
    pub status: String,
    /// The Stripe refund id when a refund was issued; `None` for a reject.
    pub stripe_refund_id: Option<String>,
    /// `true` when the refund also terminated the linked Warren access
    /// (unredeemed voucher cancelled, or the redeeming subscriber's
    /// subscription expired). `false` when the payment reference could not
    /// be resolved to a voucher (past retention or unknown): the money
    /// movement still succeeded, only the best-effort access termination
    /// did not apply. Defaults to `false` for responses from older servers.
    #[serde(default)]
    pub access_revoked: bool,
    /// `true` when the refund proceeded without the payment-age check
    /// because the Stripe age lookup failed (fail-open: the legal duty is
    /// refunding in time). The operator should verify the window manually
    /// in the Stripe dashboard. Defaults to `false` for older servers.
    #[serde(default)]
    pub age_unverified: bool,
}

// ---------------------------------------------------------------------------
// Multi-exit failover incidents (POST /v1/incidents/exit-down +
// GET /v1/admin/exits/health).
// ---------------------------------------------------------------------------

/// Allowed `reason_code` values on the failover-incident wire. Kept
/// as a discriminated enum (vs a free-form string) so an attacker
/// cannot smuggle arbitrary telemetry strings through the public
/// endpoint. The server discards the value once the request is
/// validated; only the count survives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncidentReason {
    /// QUIC handshake never completed (DNS / TCP / TLS error pre-auth).
    Timeout,
    /// QUIC connection established but the post-handshake exchange
    /// (HPKE setup or Warren `Setup` frame) failed.
    HandshakeFail,
    /// Server rejected the client identity. Typically a stale
    /// enrollment token or a revoked client cert.
    AuthFail,
}

/// `POST /v1/incidents/exit-down` body. Wire DTO shared by
/// `warren-api` (server-side handler), `warren-api-client` (daemon
/// caller), and any future telemetry consumer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentExitDownRequest {
    /// Hex-encoded Ed25519 public key of the exit that the client
    /// could not reach. Typed as
    /// `PubkeyHex` so the 64-hex-chars constraint is enforced at
    /// `serde_json::from_str` time and a malformed report cannot
    /// reach the incident store.
    pub exit_pubkey_hex: PubkeyHex,
    /// Why the report fired. Validated on the wire via
    /// [`IncidentReason`]; unknown variants cause a 422 server-side.
    pub reason_code: IncidentReason,
    /// Client-supplied Unix seconds at which the failed handshake
    /// happened. The server replaces it with its own clock when
    /// recording so the 24 h aging window is not steerable by a
    /// malicious client. Accepted on the wire for forward
    /// compatibility with future telemetry consumers.
    pub ts_unix: u64,
}

/// `POST /v1/incidents/pubkey-mismatch` body. Pin-mismatch
/// telemetry: a client whose `WarrenPinnedExitPubkeys` table flagged
/// a pubkey rotation under a known `exit_id` reports the divergence
/// so the operator can correlate substitution attempts through the
/// access log. Privacy: the endpoint stores nothing in a DB and the
/// signer identity is intentionally NOT recorded (no-log doctrine).
/// Operators reading the log only get the operator-side metadata
/// (`exit_id_hex`, the two pubkey hexes, location forensics) - all of
/// which is already public via the signed relay list.
///
/// Fields are deliberately plain `String`s (not the validating
/// newtypes): this is fire-and-forget forensic telemetry, and a report
/// whose observed value is malformed (e.g. garbage served by a MITM)
/// is exactly the report worth receiving. The server must sanitize
/// before logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentPubkeyMismatchRequest {
    /// 32-char hex stable exit identifier whose pin entry was flagged.
    pub exit_id_hex: String,
    /// Pubkey hex the client had pinned for this `exit_id` (= the
    /// previously trusted value the operator rotated away from, or
    /// an attacker substituted from).
    pub old_pubkey_hex: String,
    /// Pubkey hex the client observed on the failed connect (= what
    /// the relay list now serves under the same `exit_id`).
    pub new_pubkey_hex: String,
    /// Forensic snapshot at pin time (ISO 3166 alpha-2, lowercase).
    /// Optional via empty string so a client without location info can
    /// still report.
    #[serde(default)]
    pub country_code: String,
    /// Forensic snapshot at pin time (free-form city label). Optional.
    #[serde(default)]
    pub city: String,
    /// Client-supplied unix seconds at which the mismatch was observed.
    /// The server replaces it with its own clock when logging.
    pub ts_unix: u64,
}

/// Aggregate row returned by `GET /v1/admin/exits/health`. The wire
/// schema is intentionally narrow: it carries only the three fields
/// listed below, no signer identity, no IP, no session id (no-log
/// doctrine).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitHealthRow {
    /// Exit pubkey reported by clients.
    pub exit_pubkey_hex: PubkeyHex,
    /// Number of incidents in the past 24 h.
    pub count_24h: u32,
    /// Unix seconds of the most recent report.
    pub last_seen_unix: u64,
}

/// Severity level for a [`Notice`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoticeLevel {
    /// Informational (e.g. "new region available").
    Info,
    /// Warning (e.g. "subscription expires in 3 days").
    Warning,
    /// Error-level (e.g. "your app version is unsupported").
    Error,
}

/// A broadcast notice pushed to clients via `GET /v1/notices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    /// Unique notice identifier (hex, server-assigned).
    pub id: String,
    /// Human-readable message.
    pub message: String,
    /// Severity level.
    pub level: NoticeLevel,
    /// Minimum client version this notice applies to (semver, inclusive).
    /// `None` = all versions.
    pub min_client_version: Option<String>,
    /// Maximum client version this notice applies to (semver, inclusive).
    /// `None` = all versions.
    pub max_client_version: Option<String>,
    /// Unix timestamp after which the notice is no longer shown.
    /// `None` = permanent until admin deletes.
    pub expires_at: Option<u64>,
}

/// Response for `GET /v1/notices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoticesResponse {
    /// Active notices (not expired).
    pub notices: Vec<Notice>,
}

/// Admin request body for `POST /v1/admin/notices`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminCreateNoticeRequest {
    /// Human-readable message.
    pub message: String,
    /// Severity level.
    pub level: NoticeLevel,
    /// Optional semver range filters.
    pub min_client_version: Option<String>,
    /// Optional semver range filters.
    pub max_client_version: Option<String>,
    /// Optional expiry unix timestamp.
    pub expires_at: Option<u64>,
}

// ---------------------------------------------------------------------------
// Global device-session cap (v2). The EXIT (authenticated to warren-api
// with its OWN identity) calls these endpoints on behalf of a connecting
// client. The capped account is the CLIENT wallet pubkey carried in the
// body, NOT the exit's auth identity.
// ---------------------------------------------------------------------------

/// Expected length of a `device_id_hex` field: 16 bytes encoded as 32
/// lowercase hex chars.
const DEVICE_ID_HEX_LEN: usize = 32;

/// `true` if `s` is exactly 32 lowercase hex chars (= a 16-byte device
/// id). Shared by the handler boundary check so both sides agree on the
/// shape. Kept as a free function (rather than a newtype) because the
/// field stays a plain `String` on the wire and is validated at the
/// handler boundary with a 400 on failure.
#[must_use]
pub fn is_valid_device_id_hex(s: &str) -> bool {
    is_lower_hex(s, DEVICE_ID_HEX_LEN)
}

/// Expected length of a `serial_hex` field: a 32-byte token serial
/// (SHA-256 of the token input, doc 64) as 64 lowercase hex chars.
const TOKEN_SERIAL_HEX_LEN: usize = 64;

/// `true` if `s` is exactly 64 lowercase hex chars (= a 32-byte token
/// serial). Shared by the handler boundary check, same posture as
/// [`is_valid_device_id_hex`].
#[must_use]
pub fn is_valid_token_serial_hex(s: &str) -> bool {
    is_lower_hex(s, TOKEN_SERIAL_HEX_LEN)
}

/// `POST /v1/session/open` request body (sent by an exit on behalf of a
/// connecting client).
///
/// Two accepted shapes (doc 64 phase 1 dual-shape migration):
/// - **legacy (wallet)**: `pubkey_ss58` + `device_id_hex` present,
///   `token_b64` absent. The ledger caps distinct devices per account.
/// - **v2 (anonymous token)**: `token_b64` present, the wallet fields
///   absent. The API verifies the Privacy Pass token offline and leases
///   its serial; the exit never names the subscriber.
///
/// A body carrying both shapes (or neither) is refused with 400.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionOpenRequest {
    /// CLIENT wallet SS58 pubkey - the account whose device count is
    /// capped. NOT the exit's auth identity. Legacy shape only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey_ss58: Option<PubkeySs58>,
    /// Self-asserted device id: 16 bytes as 32 lowercase hex chars.
    /// Validated at the handler boundary (400 on malformed). Legacy
    /// shape only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id_hex: Option<String>,
    /// Exit currently serving this device (diagnostics; stored on the
    /// lease). An operator label like `exit-fr-1`, NOT the 16-byte
    /// [`ExitId`] used by [`RegisterExitRequest`].
    pub exit_id: String,
    /// Optional cap override the exit may pass from its CLI. When
    /// absent, the server uses `warren_config::MAX_DEVICES_PER_ACCOUNT`.
    /// Legacy shape only (the v2 cap is enforced at token issuance).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_devices: Option<u32>,
    /// Anonymous session token (full Privacy Pass token bytes, base64url
    /// no pad, doc 64). Presence selects the v2 shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_b64: Option<String>,
}

/// Why a `session/open` was refused (`admitted == false`). Extends the
/// legacy implicit "device limit reached" with the v2 token outcomes so
/// the exit can react (e.g. present the next epoch's token on
/// `WrongEpoch`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRejectReason {
    /// Legacy shape: the account already holds `max` live devices.
    DeviceLimitReached,
    /// v2: the token does not verify under the CURRENT epoch's issuer
    /// key (expired epoch token, or presented too early). Recovery: the
    /// exit presents the next epoch's token.
    WrongEpoch,
    /// v2: the token is malformed or its signature does not verify.
    InvalidToken,
    /// v2: another live lease already holds this token serial (a
    /// double-spend from a different exit).
    SerialInUse,
    /// Forward compatibility: a reason this build does not know.
    #[serde(other)]
    Unknown,
}

/// `POST /v1/session/open` response body. Always returned with HTTP 200;
/// the exit acts on `admitted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionOpenResponse {
    /// `true` if the device was admitted (fresh lease or renewal).
    pub admitted: bool,
    /// Cap in force (echoed for logging / client display). Always 1 for
    /// the v2 token shape (one live lease per serial).
    pub max: u32,
    /// Distinct live devices currently leased for this account. Equals
    /// `max` when `admitted` is `false`.
    pub current: u32,
    /// Why admission was refused; absent when `admitted` is `true` (and
    /// on responses from pre-v2 servers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<SessionRejectReason>,
}

/// `POST /v1/session/close` request body (graceful disconnect reported
/// by the exit). Dual-shape like [`SessionOpenRequest`]: legacy closes
/// by `(pubkey_ss58, device_id_hex)`, v2 closes by `(serial_hex,
/// exit_id)` (the lease slot the open was recorded under).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionCloseRequest {
    /// CLIENT wallet SS58 pubkey whose lease is released. Legacy shape
    /// only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey_ss58: Option<PubkeySs58>,
    /// Device id whose lease is released (16 bytes, 32 lowercase hex).
    /// Legacy shape only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id_hex: Option<String>,
    /// Token serial whose lease is released (32 bytes, 64 lowercase
    /// hex). v2 shape only. The exit computes it offline from the token
    /// it admitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_hex: Option<String>,
    /// The closing exit's operator label, matching the `exit_id` the
    /// lease was opened under. v2 shape only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_id: Option<String>,
}

// ---- Anonymous session credentials (Privacy Pass, ADR-0006 / doc 64) ----

/// `POST /v1/tokens/issue` request body (wallet-signed by the client).
///
/// One entry per epoch the client wants tokens for. Each entry MUST carry
/// exactly `warren_config::TOKEN_QUOTA_PER_EPOCH` blinded messages: a fixed
/// batch so the request pattern reveals no device-count signal. Blinded
/// messages and blind signatures are base64url (no padding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIssueRequest {
    /// Per-epoch blinded batches.
    pub epochs: Vec<TokenEpochRequest>,
}

/// One epoch's blinded batch in a [`TokenIssueRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEpochRequest {
    /// Epoch index (`unix_secs / TOKEN_EPOCH_SECS`) the tokens are for.
    pub epoch: u64,
    /// Base64url (no pad) blinded messages, one per requested token.
    pub blinded: Vec<String>,
}

/// `POST /v1/tokens/issue` response body (always HTTP 200; per-epoch outcome
/// in the body). An epoch the policy refused carries `issued=false` and a
/// `reject_reason`, so a partially-covered request still returns the epochs
/// that could be signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIssueResponse {
    /// Per-epoch results, aligned by `epoch` with the request.
    pub epochs: Vec<TokenEpochResponse>,
}

/// One epoch's issuance outcome in a [`TokenIssueResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEpochResponse {
    /// Epoch index this result is for.
    pub epoch: u64,
    /// `true` if the batch was signed.
    pub issued: bool,
    /// Base64url (no pad) blind signatures, aligned with the request's
    /// `blinded` order. Empty when `issued` is `false`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blind_signatures: Vec<String>,
    /// Hex `token_key_id` the batch was signed under, so the client knows
    /// which epoch key to finalize/verify against. `None` when not issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_key_id: Option<String>,
    /// Machine-readable refusal reason when `issued` is `false`
    /// (`out_of_window` | `not_subscribed` | `already_issued` | `bad_batch`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
}

/// `GET /v1/tokens/keys` response: the issuer public keys for the currently
/// spendable/verifiable window, so an exit or a client can fetch the key for
/// the epoch it needs without contacting the issuer per redemption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIssuerDirectory {
    /// The issuer name pinned into every `TokenChallenge`.
    pub issuer_name: String,
    /// Privacy Pass token type (always `2`).
    pub token_type: u16,
    /// Epoch length in seconds, so a verifier can compute the current epoch.
    pub epoch_secs: u64,
    /// Domain-separator label hashed (with the epoch index) into every
    /// token's `redemption_context`. Published here so clients rebuild the
    /// challenge from the directory alone, with no hardcoded copy to drift.
    pub context_label: String,
    /// Exact number of blinded messages an issue request must carry per
    /// epoch (the fixed batch size; also the device cap).
    pub quota_per_epoch: u32,
    /// How many epochs ahead of the current one the issuer signs.
    pub prefetch_epochs: u64,
    /// One key per epoch in the published window.
    pub keys: Vec<TokenIssuerKey>,
}

/// One epoch's public key in a [`TokenIssuerDirectory`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenIssuerKey {
    /// Epoch this key signs/verifies.
    pub epoch: u64,
    /// Hex `token_key_id` (`SHA-256` of the RSASSA-PSS SPKI).
    pub token_key_id: String,
    /// Base64url (no pad) RSASSA-PSS `SubjectPublicKeyInfo` DER.
    pub spki_b64: String,
    /// First unix second the key is valid (epoch start).
    pub not_before: u64,
    /// Exclusive last unix second the key is valid (epoch end).
    pub not_after: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_pubkey_hex_error_redacts_the_value() {
        let bad = format!("{}Z", "a".repeat(63));
        let msg = PubkeyHex::try_from(bad.as_str())
            .expect_err("non-hex suffix must be rejected")
            .to_string();
        assert!(!msg.contains(&bad), "full value must not leak: {msg}");
        assert!(msg.contains("aaaaaaaa…"), "short prefix kept: {msg}");
    }

    #[test]
    fn invalid_pubkey_ss58_error_redacts_the_value() {
        let bad = "wbNotARealAddressNotARealAddressNotARealAddress";
        let msg = PubkeySs58::try_from(bad)
            .expect_err("bogus SS58 must be rejected")
            .to_string();
        assert!(!msg.contains(bad), "full value must not leak: {msg}");
        assert!(msg.contains("wbNotARe…"), "short prefix kept: {msg}");
    }

    #[test]
    fn invalid_token_id_error_redacts_the_value() {
        let bad = "AAAABBBBCCCC";
        let msg = TokenId::try_from(bad)
            .expect_err("uppercase token id must be rejected")
            .to_string();
        assert!(!msg.contains(bad), "full value must not leak: {msg}");
        assert!(msg.contains("AAAABBBB…"), "short prefix kept: {msg}");
    }

    #[test]
    fn invalid_country_code_error_redacts_the_value() {
        let bad = "NotACountryCode";
        let msg = CountryCode::try_from(bad)
            .expect_err("long string must be rejected")
            .to_string();
        assert!(!msg.contains(bad), "full value must not leak: {msg}");
        assert!(msg.contains("NotACoun…"), "short prefix kept: {msg}");
    }

    #[test]
    fn pricing_ladder_body_pins_its_wire_field_names() {
        let body: AdminPricingLadderBody = serde_json::from_str(
            r#"{"currency":"EUR","price_per_month_units":700,"max_months":36}"#,
        )
        .expect("wire form must deserialize");
        assert_eq!(body.currency, "EUR");
        assert_eq!(body.price_per_month_units, 700);
        assert_eq!(body.max_months, 36);
        let json = serde_json::to_string(&AdminPricingLadderResponse { tiers: 36 })
            .expect("serialize response");
        assert_eq!(json, r#"{"tiers":36}"#, "response wire shape is pinned");
    }

    #[test]
    fn payment_method_serializes_to_lowercase_wire_form() {
        for (variant, expected) in [
            (PaymentMethod::Lightning, "\"lightning\""),
            (PaymentMethod::Monero, "\"monero\""),
            (PaymentMethod::Card, "\"card\""),
            (PaymentMethod::Cash, "\"cash\""),
            (PaymentMethod::Bitcoin, "\"bitcoin\""),
            (PaymentMethod::Manual, "\"manual\""),
            (PaymentMethod::AppStore, "\"appstore\""),
            (PaymentMethod::GooglePlay, "\"googleplay\""),
            (PaymentMethod::Paypal, "\"paypal\""),
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            assert_eq!(
                json, expected,
                "variant {variant:?} must serialize to {expected}"
            );
        }
    }

    #[test]
    fn payment_method_deserializes_from_lowercase_wire_form() {
        for (wire, expected) in [
            ("\"lightning\"", PaymentMethod::Lightning),
            ("\"monero\"", PaymentMethod::Monero),
            ("\"card\"", PaymentMethod::Card),
            ("\"cash\"", PaymentMethod::Cash),
            ("\"bitcoin\"", PaymentMethod::Bitcoin),
            ("\"manual\"", PaymentMethod::Manual),
            ("\"appstore\"", PaymentMethod::AppStore),
            ("\"googleplay\"", PaymentMethod::GooglePlay),
            ("\"paypal\"", PaymentMethod::Paypal),
        ] {
            let pm: PaymentMethod = serde_json::from_str(wire).expect("deserialize");
            assert_eq!(pm, expected, "wire {wire:?} must parse to {expected:?}");
        }
    }

    #[test]
    fn payment_method_rejects_capitalized_or_unknown_inputs() {
        assert!(
            serde_json::from_str::<PaymentMethod>("\"Manual\"").is_err(),
            "capitalization must be rejected (rename_all = lowercase contract)",
        );
        assert!(
            serde_json::from_str::<PaymentMethod>("\"swift\"").is_err(),
            "unknown variant must be rejected",
        );
    }

    #[test]
    fn payment_method_from_wire_round_trips_with_as_wire() {
        for v in [
            PaymentMethod::Lightning,
            PaymentMethod::Monero,
            PaymentMethod::Card,
            PaymentMethod::Cash,
            PaymentMethod::Bitcoin,
            PaymentMethod::Manual,
            PaymentMethod::AppStore,
            PaymentMethod::GooglePlay,
            PaymentMethod::Paypal,
        ] {
            let parsed = PaymentMethod::from_wire(v.as_wire()).expect("round-trip");
            assert_eq!(parsed, v);
        }
        assert!(PaymentMethod::from_wire("Manual").is_err());
        assert!(PaymentMethod::from_wire("").is_err());
    }

    #[test]
    fn mobile_payment_wire_types_round_trip() {
        let apple_init = InitApplePaymentResponse {
            app_account_token: "550e8400-e29b-41d4-a716-446655440000".to_owned(),
        };
        let json = serde_json::to_string(&apple_init).unwrap();
        let parsed: InitApplePaymentResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, apple_init);

        let apple_check = CheckApplePaymentRequest {
            jws_transaction: "eyJhbGciOiJFUzI1NiJ9.test.sig".to_owned(),
        };
        let json = serde_json::to_string(&apple_check).unwrap();
        let parsed: CheckApplePaymentRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.jws_transaction, apple_check.jws_transaction);

        let google_init = InitGooglePaymentResponse {
            obfuscated_account_id: "obf_abc123".to_owned(),
        };
        let json = serde_json::to_string(&google_init).unwrap();
        let parsed: InitGooglePaymentResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, google_init);

        let google_ack = AcknowledgeGooglePaymentRequest {
            purchase_token: "token_xyz".to_owned(),
        };
        let json = serde_json::to_string(&google_ack).unwrap();
        let parsed: AcknowledgeGooglePaymentRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.purchase_token, google_ack.purchase_token);

        let response = MobilePaymentResponse {
            expires_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, r#"{"expires_at":1700000000}"#);
        let parsed: MobilePaymentResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, response);
    }

    #[test]
    fn withdrawal_refund_body_override_defaults_false_and_uses_wire_name() {
        // The admin refund POST historically has an empty body: `{}` (and an
        // absent field) must keep override off so old callers never bypass
        // the 14-day window check.
        let empty: AdminWithdrawalRefundBody =
            serde_json::from_str("{}").expect("empty object must parse");
        assert!(
            !empty.override_window,
            "absent override must default to false"
        );

        let on: AdminWithdrawalRefundBody = serde_json::from_str(r#"{"override":true}"#)
            .expect("override body must parse under the wire name");
        assert!(on.override_window, "explicit override:true must round-trip");

        let json = serde_json::to_string(&on).expect("serialize");
        assert_eq!(
            json, r#"{"override":true}"#,
            "the wire field must be named `override`"
        );
    }

    #[test]
    fn withdrawal_out_of_window_error_pins_wire_shape() {
        let err = AdminWithdrawalOutOfWindow {
            error: "out_of_window".to_owned(),
            payment_age_days: 17,
        };
        let json = serde_json::to_string(&err).expect("serialize");
        assert_eq!(
            json, r#"{"error":"out_of_window","payment_age_days":17}"#,
            "the 422 body is machine-read by warren-admin; its shape is frozen"
        );
        let parsed: AdminWithdrawalOutOfWindow = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed.payment_age_days, 17);
        assert_eq!(parsed.error, "out_of_window");
    }

    #[test]
    fn withdrawal_process_response_age_unverified_defaults_false_on_legacy_json() {
        // Additive-field compat: a response from an older warren-api without
        // `age_unverified` must still parse, with the flag off.
        let legacy = r#"{"id":"ref1","status":"refunded","stripe_refund_id":"re_1"}"#;
        let parsed: AdminWithdrawalProcessResponse =
            serde_json::from_str(legacy).expect("legacy JSON without age_unverified must parse");
        assert!(
            !parsed.age_unverified,
            "absent age_unverified must default to false"
        );

        let with_field =
            r#"{"id":"ref1","status":"refunded","stripe_refund_id":"re_1","age_unverified":true}"#;
        let parsed: AdminWithdrawalProcessResponse =
            serde_json::from_str(with_field).expect("new JSON must parse");
        assert!(parsed.age_unverified, "explicit true must round-trip");
    }

    #[test]
    fn withdrawal_process_response_access_revoked_defaults_false_on_legacy_json() {
        // Additive-field compat: a warren-admin built against this crate must
        // still parse a response from an older warren-api that does not emit
        // `access_revoked` yet.
        let legacy = r#"{"id":"ref1","status":"refunded","stripe_refund_id":"re_1"}"#;
        let parsed: AdminWithdrawalProcessResponse =
            serde_json::from_str(legacy).expect("legacy JSON without access_revoked must parse");
        assert!(
            !parsed.access_revoked,
            "absent access_revoked must default to false"
        );

        let with_field =
            r#"{"id":"ref1","status":"refunded","stripe_refund_id":"re_1","access_revoked":true}"#;
        let parsed: AdminWithdrawalProcessResponse =
            serde_json::from_str(with_field).expect("new JSON must parse");
        assert!(parsed.access_revoked, "explicit true must round-trip");
    }

    #[test]
    fn admin_google_refund_response_pins_wire_shape() {
        let resp = AdminGoogleRefundResponse {
            refunded: true,
            subscription_expired: false,
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert_eq!(
            json, r#"{"refunded":true,"subscription_expired":false}"#,
            "wire shape is pinned"
        );
        let parsed: AdminGoogleRefundResponse = serde_json::from_str(&json).expect("deserialize");
        assert!(parsed.refunded);
        assert!(!parsed.subscription_expired);
    }

    #[test]
    fn check_apple_payment_request_debug_redacts_jws() {
        let req = CheckApplePaymentRequest {
            jws_transaction: "secret-jws-data".to_owned(),
        };
        let debug = format!("{req:?}");
        assert!(
            !debug.contains("secret-jws-data"),
            "Debug must redact jws_transaction: {debug}"
        );
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn acknowledge_google_payment_request_debug_redacts_token() {
        let req = AcknowledgeGooglePaymentRequest {
            purchase_token: "secret-purchase-token".to_owned(),
        };
        let debug = format!("{req:?}");
        assert!(
            !debug.contains("secret-purchase-token"),
            "Debug must redact purchase_token: {debug}"
        );
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn subscription_response_round_trip() {
        let original = SubscriptionResponse {
            expires_at: 1_700_000_000,
        };
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, r#"{"expires_at":1700000000}"#);
        let parsed: SubscriptionResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.expires_at, original.expires_at);
    }

    #[test]
    fn register_account_response_round_trip_carries_added_secs() {
        let original = RegisterAccountResponse {
            expires_at: 1_700_000_000,
            added_secs: 2_592_000,
        };
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(
            json, r#"{"expires_at":1700000000,"added_secs":2592000}"#,
            "added_secs must be on the wire so the client shows the real granted duration"
        );
        let parsed: RegisterAccountResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn register_account_response_defaults_added_secs_for_older_servers() {
        // A server that pre-dates the field emits only `expires_at`; the
        // client must still deserialize (added_secs falls back to 0).
        let parsed: RegisterAccountResponse =
            serde_json::from_str(r#"{"expires_at":1700000000}"#).unwrap();
        assert_eq!(parsed.expires_at, 1_700_000_000);
        assert_eq!(parsed.added_secs, 0);
    }

    #[test]
    fn admin_pricing_response_total_defaults_to_zero() {
        let parsed: AdminPricingResponse = serde_json::from_str(r#"{"tiers":[]}"#).unwrap();
        assert_eq!(
            parsed.total, 0,
            "missing `total` must deserialize to 0 to keep wire-compat with older servers"
        );
    }

    #[test]
    fn admin_voucher_row_cancelled_at_defaults_to_none() {
        let raw = r#"{"secret_hash_hex":"deadbeef","duration_secs":3600,"payment_method":"manual","created_at":0,"redeemed_at":null,"is_redeemed":false,"redeemed_by_pubkey_ss58":null}"#;
        let parsed: AdminVoucherRow = serde_json::from_str(raw).unwrap();
        assert!(
            parsed.cancelled_at.is_none(),
            "missing `cancelled_at` must default to None for wire-compat with pre-cancel servers"
        );
    }

    #[test]
    fn admin_subscribers_page_response_round_trips_with_echoed_paging() {
        let page = AdminSubscribersPageResponse {
            subscribers: vec![AdminSubscriptionRow {
                pubkey_ss58: PubkeySs58::try_from(crate::ss58::encode(&[0x11; 32]))
                    .expect("valid SS58"),
                expires_at: 1_800_000_000,
                is_active: true,
            }],
            total: 42,
            offset: 50,
            limit: 25,
        };
        let json = serde_json::to_string(&page).expect("serialize");
        let parsed: AdminSubscribersPageResponse =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.subscribers.len(), 1, "page rows survive round-trip");
        assert_eq!(
            parsed.subscribers[0].pubkey_ss58, page.subscribers[0].pubkey_ss58,
            "subscriber pubkey round-trips"
        );
        assert_eq!(parsed.total, 42, "total is the full filtered count");
        assert_eq!(
            (parsed.offset, parsed.limit),
            (50, 25),
            "paging echoed back"
        );
    }

    #[test]
    fn admin_subscriber_detail_response_carries_join_panels() {
        let detail = AdminSubscriberDetailResponse {
            subscription: AdminSubscriptionRow {
                pubkey_ss58: PubkeySs58::try_from(crate::ss58::encode(&[0x22; 32]))
                    .expect("valid SS58"),
                expires_at: 1_800_000_000,
                is_active: true,
            },
            funding_vouchers: vec![AdminVoucherRow {
                secret_hash_hex: "deadbeef".to_owned(),
                duration_secs: 2_592_000,
                payment_method: PaymentMethod::Card,
                created_at: 1_700_000_000,
                redeemed_at: Some(1_700_000_500),
                is_redeemed: true,
                redeemed_by_pubkey_ss58: Some(
                    PubkeySs58::try_from(crate::ss58::encode(&[0x22; 32])).expect("valid SS58"),
                ),
                cancelled_at: None,
                max_redemptions: Some(1),
                valid_until: None,
                redemptions_count: 0,
            }],
            port_forwards: vec![AdminPortForwardRow {
                client_pubkey_ss58: Some(
                    PubkeySs58::try_from(crate::ss58::encode(&[0x22; 32])).expect("valid SS58"),
                ),
                exit_pubkey_ss58: PubkeySs58::try_from(crate::ss58::encode(&[0xee; 32]))
                    .expect("valid SS58"),
                port: 49200,
                expires_at: 1_700_003_600,
                exit_last_sync_unix_secs: Some(1_700_000_000),
            }],
        };
        let json = serde_json::to_string(&detail).expect("serialize");
        let parsed: AdminSubscriberDetailResponse =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            parsed.funding_vouchers.len(),
            1,
            "the funding-vouchers join panel must survive the round-trip"
        );
        assert_eq!(parsed.port_forwards.len(), 1, "port-forward join panel too");
        assert_eq!(parsed.subscription.expires_at, 1_800_000_000);
    }

    #[test]
    fn exit_port_forward_sync_request_round_trips() {
        let pubkey =
            PubkeySs58::try_from(crate::ss58::encode(&[0xaa; 32])).expect("valid SS58 address");
        let req = ExitPortForwardSyncRequest {
            instance_id: 0xDEAD_BEEF_CAFE_F00D,
            generation: 7,
            captured_at_unix_secs: 1_700_000_000,
            allocations: vec![ExitPortForwardAllocation {
                internal_ip: std::net::Ipv4Addr::new(10, 66, 0, 42),
                external_port: 49200,
                internal_port: 49200,
                proto: PortForwardProto::Tcp,
                expires_at_unix_secs: 1_700_003_600,
                client_pubkey_ss58: Some(pubkey),
            }],
            metrics: None,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let parsed: ExitPortForwardSyncRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.instance_id, req.instance_id);
        assert_eq!(parsed.generation, req.generation);
        assert_eq!(parsed.captured_at_unix_secs, req.captured_at_unix_secs);
        assert_eq!(parsed.allocations.len(), 1);
        let alloc = &parsed.allocations[0];
        assert_eq!(alloc.external_port, 49200);
        assert_eq!(alloc.proto, PortForwardProto::Tcp);
        assert_eq!(
            alloc.internal_ip,
            std::net::Ipv4Addr::new(10, 66, 0, 42),
            "Ipv4Addr round-trips via its dotted-decimal Display form"
        );
    }

    #[test]
    fn admin_port_forward_metrics_response_round_trips() {
        let exit =
            PubkeySs58::try_from(crate::ss58::encode(&[0xbb; 32])).expect("valid SS58 address");
        let resp = AdminPortForwardMetricsResponse {
            metrics: vec![AdminPortForwardMetricsRow {
                exit_pubkey_ss58: exit.clone(),
                metrics: ExitPortForwardMetrics {
                    allocations_total: 12,
                    releases_total: 4,
                    evictions_total: 1,
                    quota_exceeded_total: 7,
                    rate_limited_total: 2,
                    exhausted_total: 5,
                },
            }],
            total: 1,
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let parsed: AdminPortForwardMetricsResponse =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.total, 1);
        assert_eq!(parsed.metrics.len(), 1);
        assert_eq!(parsed.metrics[0].exit_pubkey_ss58, exit);
        assert_eq!(
            parsed.metrics[0].metrics.exhausted_total, 5,
            "the pool-exhaustion (port-conflict) counter must survive the round-trip"
        );
        assert_eq!(parsed.metrics[0].metrics.quota_exceeded_total, 7);
        assert_eq!(parsed.metrics[0].metrics.rate_limited_total, 2);
    }

    #[test]
    fn exit_port_forward_sync_request_instance_id_defaults_to_zero() {
        // Wire-compat: a pre-instance-id exit omits the field. It must
        // deserialize to 0 rather than fail, so the API falls back to
        // the legacy generation-only behaviour for that exit.
        let raw = r#"{"generation":42,"captured_at_unix_secs":1700000000,"allocations":[]}"#;
        let parsed: ExitPortForwardSyncRequest =
            serde_json::from_str(raw).expect("deserialize without instance_id");
        assert_eq!(parsed.instance_id, 0);
        assert_eq!(parsed.generation, 42);
    }

    #[test]
    fn exit_port_forward_allocation_tolerates_missing_client_pubkey() {
        // The exit resolves the client pubkey via its tunnel session
        // map, which can briefly lag a fresh allocation. The wire
        // format MUST tolerate a missing field so the push is not
        // dropped during that lag.
        let raw = r#"{"internal_ip":"10.66.0.42","external_port":49200,"internal_port":49200,"proto":"tcp","expires_at_unix_secs":1700003600}"#;
        let parsed: ExitPortForwardAllocation =
            serde_json::from_str(raw).expect("deserialize without client_pubkey_ss58");
        assert!(
            parsed.client_pubkey_ss58.is_none(),
            "absent client_pubkey_ss58 must default to None"
        );
    }

    #[test]
    fn port_forward_proto_serializes_to_lowercase_wire_form() {
        for (variant, expected) in [
            (PortForwardProto::Tcp, "\"tcp\""),
            (PortForwardProto::Udp, "\"udp\""),
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            assert_eq!(json, expected, "variant {variant:?} wire form");
        }
    }

    #[test]
    fn port_forward_proto_rejects_unknown_input() {
        assert!(
            serde_json::from_str::<PortForwardProto>("\"sctp\"").is_err(),
            "unknown protocol must be rejected by deserialization"
        );
    }

    #[test]
    fn incident_reason_round_trips_via_screaming_snake_case() {
        for (variant, expected) in [
            (IncidentReason::Timeout, "\"TIMEOUT\""),
            (IncidentReason::HandshakeFail, "\"HANDSHAKE_FAIL\""),
            (IncidentReason::AuthFail, "\"AUTH_FAIL\""),
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            assert_eq!(json, expected, "variant {variant:?} wire form");
            let parsed: IncidentReason = serde_json::from_str(expected).expect("deserialize");
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn incident_reason_rejects_unknown_variant() {
        assert!(
            serde_json::from_str::<IncidentReason>("\"NOPE\"").is_err(),
            "unknown variant must be rejected by deserialization (so the server returns 422)"
        );
    }

    /// One v4 ingress+egress endpoint on quic/h3:51820.
    fn sample_endpoints() -> Vec<RegisterEndpoint> {
        vec![RegisterEndpoint {
            addr: "198.51.100.1".to_owned(),
            family: "ipv4".to_owned(),
            ingress: true,
            egress: true,
            listeners: vec![RegisterListener {
                port: 51820,
                transport: "quic".to_owned(),
                alpn: "h3".to_owned(),
            }],
        }]
    }

    #[test]
    fn register_exit_request_endpoints_round_trip() {
        // The v6 register declares per-endpoint flags. A v4 egress
        // endpoint and a v6 non-egress endpoint (the FDC DAD-fail shape)
        // must both survive the wire round-trip with their flags intact.
        let mut endpoints = sample_endpoints();
        endpoints.push(RegisterEndpoint {
            addr: "2001:db8::2".to_owned(),
            family: "ipv6".to_owned(),
            ingress: true,
            egress: false,
            listeners: vec![RegisterListener {
                port: 51820,
                transport: "quic".to_owned(),
                alpn: "h3".to_owned(),
            }],
        });
        let req = RegisterExitRequest {
            telemetry: None,
            endpoints,
            country: CountryCode::try_from("FR").unwrap(),
            city: "Paris".to_owned(),
            weight: 100,
            active: true,
            exit_id: None,
            exit_x25519_multihop_pubkey_hex: None,
            version: None,
            active_sessions: None,
            cover_domain: None,
            update_status: None,
            hwqual: None,
            port_forward: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: RegisterExitRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.endpoints.len(), 2);
        assert!(parsed.endpoints[0].egress, "v4 endpoint egress survives");
        assert_eq!(parsed.endpoints[1].family, "ipv6");
        assert!(
            !parsed.endpoints[1].egress,
            "v6 non-egress flag must survive the round-trip"
        );
    }

    #[test]
    fn register_endpoint_flags_default_true_when_absent() {
        // ingress/egress default to true (the common single-IP node);
        // listeners default to empty. A minimal endpoint must decode.
        let raw = r#"{"addr":"198.51.100.1","family":"ipv4"}"#;
        let ep: RegisterEndpoint = serde_json::from_str(raw).unwrap();
        assert!(ep.ingress, "ingress defaults to true");
        assert!(ep.egress, "egress defaults to true");
        assert!(ep.listeners.is_empty(), "listeners default to empty");
    }

    #[test]
    fn register_exit_request_carries_optional_exit_id() {
        // Exit binaries that mint an exit_id locally must be able to
        // send it on every heartbeat so the API persists the value.
        let req = RegisterExitRequest {
            telemetry: None,
            endpoints: sample_endpoints(),
            country: CountryCode::try_from("FR").unwrap(),
            city: "Paris".to_owned(),
            weight: 100,
            active: true,
            exit_id: Some(ExitId::from_bytes([0xa1; 16])),
            exit_x25519_multihop_pubkey_hex: None,
            version: None,
            active_sessions: None,
            cover_domain: None,
            update_status: None,
            hwqual: None,
            port_forward: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains("\"exit_id\":"),
            "wire form must include exit_id when Some: {json}"
        );
        let parsed: RegisterExitRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.exit_id, Some(ExitId::from_bytes([0xa1; 16])));
    }

    #[test]
    fn register_exit_request_tolerates_absent_exit_id() {
        // Backward-compat: an exit that does not mint an exit_id omits
        // the field. The server falls back to enrollment-time storage or
        // a freshly generated value on its side.
        let raw = r#"{"endpoints":[{"addr":"198.51.100.1","family":"ipv4","ingress":true,"egress":true,"listeners":[{"port":51820,"transport":"quic","alpn":"h3"}]}],"country":"FR","city":"Paris","weight":100,"active":true}"#;
        let parsed: RegisterExitRequest = serde_json::from_str(raw).unwrap();
        assert!(
            parsed.exit_id.is_none(),
            "absent exit_id must deserialize to None"
        );
    }

    #[test]
    fn register_exit_request_omits_none_optional_fields_on_wire() {
        // `skip_serializing_if = Option::is_none` keeps the on-wire shape
        // narrow when the optional fields are absent.
        let req = RegisterExitRequest {
            telemetry: None,
            endpoints: sample_endpoints(),
            country: CountryCode::try_from("FR").unwrap(),
            city: "Paris".to_owned(),
            weight: 100,
            active: true,
            exit_id: None,
            exit_x25519_multihop_pubkey_hex: None,
            version: None,
            active_sessions: None,
            cover_domain: None,
            update_status: None,
            hwqual: None,
            port_forward: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            !json.contains("exit_id"),
            "None exit_id must NOT appear on the wire (skip_serializing_if): {json}"
        );
        assert!(
            !json.contains("version"),
            "None version must NOT appear on the wire (skip_serializing_if): {json}"
        );
        assert!(
            !json.contains("port_forward"),
            "None port_forward must NOT appear on the wire (skip_serializing_if): {json}"
        );
    }

    #[test]
    fn register_exit_request_version_round_trips() {
        // The exit binary advertises its build identifier on every
        // heartbeat so the admin panel can display fleet deployment
        // state. Absent field (legacy binary) must decode to None.
        let req = RegisterExitRequest {
            telemetry: None,
            endpoints: sample_endpoints(),
            country: CountryCode::try_from("FR").unwrap(),
            city: "Paris".to_owned(),
            weight: 100,
            active: true,
            exit_id: None,
            exit_x25519_multihop_pubkey_hex: None,
            version: Some("v0.3.7-2-gabc1234".to_owned()),
            active_sessions: None,
            cover_domain: None,
            update_status: None,
            hwqual: None,
            port_forward: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: RegisterExitRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.version.as_deref(),
            Some("v0.3.7-2-gabc1234"),
            "version must survive the wire round-trip"
        );

        let legacy = r#"{"endpoints":[{"addr":"198.51.100.1","family":"ipv4","ingress":true,"egress":true,"listeners":[{"port":51820,"transport":"quic","alpn":"h3"}]}],"country":"FR","city":"Paris","weight":100,"active":true}"#;
        let parsed: RegisterExitRequest = serde_json::from_str(legacy).unwrap();
        assert!(
            parsed.version.is_none(),
            "legacy heartbeat without version must decode to None"
        );
    }

    #[test]
    fn register_exit_request_port_forward_round_trips_and_defaults_none() {
        // doc 79: the exit reports whether its NAT-PMP port-forwarding gateway
        // is enabled. `Some(true)` and `Some(false)` must both survive the wire
        // round-trip (the client gates the feature on this), and a legacy
        // heartbeat that omits the field must decode to `None` (unknown), never
        // a misleading `false`.
        let req = RegisterExitRequest {
            telemetry: None,
            endpoints: sample_endpoints(),
            country: CountryCode::try_from("FR").unwrap(),
            city: "Paris".to_owned(),
            weight: 100,
            active: true,
            exit_id: None,
            exit_x25519_multihop_pubkey_hex: None,
            version: None,
            active_sessions: None,
            cover_domain: None,
            update_status: None,
            hwqual: None,
            port_forward: Some(true),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains("\"port_forward\":true"),
            "enabled NAT-PMP must appear on the wire: {json}"
        );
        let parsed: RegisterExitRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.port_forward, Some(true));

        let off = RegisterExitRequest {
            port_forward: Some(false),
            ..req
        };
        let json = serde_json::to_string(&off).unwrap();
        let parsed: RegisterExitRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.port_forward,
            Some(false),
            "an exit with NAT-PMP explicitly disabled must round-trip as Some(false)"
        );

        let legacy = r#"{"endpoints":[{"addr":"198.51.100.1","family":"ipv4","ingress":true,"egress":true,"listeners":[{"port":51820,"transport":"quic","alpn":"h3"}]}],"country":"FR","city":"Paris","weight":100,"active":true}"#;
        let parsed: RegisterExitRequest = serde_json::from_str(legacy).unwrap();
        assert!(
            parsed.port_forward.is_none(),
            "legacy heartbeat without port_forward must decode to None (unknown)"
        );
    }

    fn sample_hwqual() -> ExitHwQual {
        ExitHwQual {
            verdict: ExitHwQualVerdict::Go,
            capacity_class: String::new(),
            est_clean_tunnel_gbps: 0.0,
            reasons: String::new(),
            cpu_model: "AMD EPYC 4484PX 12-Core Processor".to_owned(),
            cpu_cores: 24,
            aes_ni: true,
            aes256gcm_gbps_per_core: 45.2,
            nic_iface: "eno1".to_owned(),
            nic_speed_mbps: 10_000,
            udp_loopback_pps: 328_000,
            udp_loopback_gbps: 3.68,
            measured_at: 1_700_000_000,
        }
    }

    #[test]
    fn hwqual_evaluate_marks_a_capable_box_go_high_class() {
        let q = sample_hwqual().evaluate();
        assert_eq!(q.verdict, ExitHwQualVerdict::Go);
        assert_eq!(
            q.capacity_class, "high",
            "10G NIC + >=250k pps is high class"
        );
        assert!(q.reasons.is_empty());
        assert!(
            q.est_clean_tunnel_gbps > 7.0 && q.est_clean_tunnel_gbps <= 10.0,
            "estimate tracks 2x single-core capped at NIC, got {}",
            q.est_clean_tunnel_gbps
        );
    }

    #[test]
    fn hwqual_evaluate_fails_a_box_without_aes_ni() {
        let mut q = sample_hwqual();
        q.aes_ni = false;
        let q = q.evaluate();
        assert_eq!(q.verdict, ExitHwQualVerdict::NoGo);
        assert_eq!(q.capacity_class, "unfit");
        assert!(
            q.reasons.contains("AES-NI"),
            "reason names the missing AES-NI"
        );
        assert_eq!(q.est_clean_tunnel_gbps, 0.0, "NO_GO reports zero capacity");
    }

    #[test]
    fn hwqual_evaluate_fails_a_slow_datapath() {
        let mut q = sample_hwqual();
        q.udp_loopback_pps = 90_000; // below the 120k floor
        let q = q.evaluate();
        assert_eq!(q.verdict, ExitHwQualVerdict::NoGo);
        assert!(q.reasons.contains("120k"), "reason names the pps floor");
    }

    #[test]
    fn hwqual_round_trips_and_omits_none_on_register() {
        let q = sample_hwqual().evaluate();
        let json = serde_json::to_string(&q).unwrap();
        let parsed: ExitHwQual = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, q, "ExitHwQual survives the wire round-trip");
        // Absent on a legacy heartbeat -> None (no field required on the wire).
        let legacy = r#"{"endpoints":[{"addr":"198.51.100.1","family":"ipv4","ingress":true,"egress":true,"listeners":[]}],"country":"FR","city":"Paris","weight":100,"active":true}"#;
        let req: RegisterExitRequest = serde_json::from_str(legacy).unwrap();
        assert!(req.hwqual.is_none(), "legacy heartbeat has no hwqual");
    }

    #[test]
    fn admin_exit_row_round_trips_with_exit_id() {
        let pubkey_ss58 = crate::ss58::encode(&[0xaa; 32]);
        let raw = format!(
            r#"{{"pubkey_ss58":"{pubkey_ss58}","exit_id":"123456789abcdef01122334455667788","ip_addrs":["198.51.100.1:51820"],"country":"FR","city":"Paris","weight":100,"active":true,"last_seen":1700000000,"seconds_since_last_seen":42}}"#
        );
        let parsed: AdminExitRow = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.pubkey_ss58.as_str(), pubkey_ss58);
        assert_eq!(parsed.exit_id.to_hex(), "123456789abcdef01122334455667788");
        assert_eq!(parsed.country.as_str(), "FR");
        assert!(
            parsed.version.is_none(),
            "row emitted by a pre-version server must decode with version=None"
        );
    }

    #[test]
    fn currency_round_trips_all_uppercase_tokens() {
        for (variant, expected) in [
            (Currency::EUR, "\"EUR\""),
            (Currency::USD, "\"USD\""),
            (Currency::BTC, "\"BTC\""),
            (Currency::XMR, "\"XMR\""),
            (Currency::SAT, "\"SAT\""),
            (Currency::RON, "\"RON\""),
            (Currency::CAD, "\"CAD\""),
            (Currency::GBP, "\"GBP\""),
            (Currency::CHF, "\"CHF\""),
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            assert_eq!(json, expected, "variant {variant:?} wire form");
            let parsed: Currency = serde_json::from_str(expected).expect("deserialize");
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn currency_rejects_lowercase_token() {
        assert!(
            serde_json::from_str::<Currency>("\"eur\"").is_err(),
            "lowercase must be rejected (rename_all = UPPERCASE contract)"
        );
    }

    #[test]
    fn notice_level_round_trips_lowercase_tokens() {
        for (variant, expected) in [
            (NoticeLevel::Info, "\"info\""),
            (NoticeLevel::Warning, "\"warning\""),
            (NoticeLevel::Error, "\"error\""),
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            assert_eq!(json, expected, "variant {variant:?} wire form");
            let parsed: NoticeLevel = serde_json::from_str(expected).expect("deserialize");
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn notice_level_rejects_uppercase_token() {
        assert!(
            serde_json::from_str::<NoticeLevel>("\"INFO\"").is_err(),
            "uppercase must be rejected (rename_all = lowercase contract)"
        );
    }

    #[test]
    fn exit_update_state_round_trips_all_known_tokens() {
        for (variant, expected) in [
            (ExitUpdateState::Idle, "\"idle\""),
            (ExitUpdateState::Staging, "\"staging\""),
            (ExitUpdateState::Staged, "\"staged\""),
            (ExitUpdateState::Swapping, "\"swapping\""),
            (ExitUpdateState::Applied, "\"applied\""),
            (ExitUpdateState::Failed, "\"failed\""),
            (ExitUpdateState::PersistPending, "\"persist_pending\""),
        ] {
            let json = serde_json::to_string(&variant).expect("serialize");
            assert_eq!(json, expected, "variant {variant:?} wire form");
            let parsed: ExitUpdateState = serde_json::from_str(expected).expect("deserialize");
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn exit_update_state_unrecognized_token_deserializes_to_unknown() {
        let parsed: ExitUpdateState = serde_json::from_str("\"resharding\"").expect(
            "an unrecognized token must fall back to Unknown, never fail the whole heartbeat",
        );
        assert_eq!(parsed, ExitUpdateState::Unknown);
    }

    #[test]
    fn exit_update_state_unknown_serializes_as_unknown_token() {
        let json = serde_json::to_string(&ExitUpdateState::Unknown).expect("serialize");
        assert_eq!(json, "\"unknown\"");
    }

    #[test]
    fn crl_entry_rejects_reason_with_line_break() {
        let pubkey = crate::ss58::encode(&[0x11; 32]);
        let raw = format!(
            r#"{{"pubkey_ss58":"{pubkey}","revoked_at_unix_secs":1700000000,"reason":"line one\nline two"}}"#
        );
        assert!(
            serde_json::from_str::<CrlEntry>(&raw).is_err(),
            "a reason containing a line break must be rejected at deserialization"
        );
    }

    #[test]
    fn crl_entry_accepts_reason_with_colon() {
        let pubkey = crate::ss58::encode(&[0x11; 32]);
        let raw = format!(
            r#"{{"pubkey_ss58":"{pubkey}","revoked_at_unix_secs":1700000000,"reason":"chargeback: disputed"}}"#
        );
        let parsed: CrlEntry =
            serde_json::from_str(&raw).expect("colon in reason must be accepted");
        assert_eq!(parsed.reason, "chargeback: disputed");
    }

    #[test]
    fn admin_crl_revoke_request_rejects_reason_with_line_break() {
        let pubkey = crate::ss58::encode(&[0x22; 32]);
        let raw = format!(r#"{{"pubkey_ss58":"{pubkey}","reason":"abuse\nmore"}}"#);
        assert!(
            serde_json::from_str::<AdminCrlRevokeRequest>(&raw).is_err(),
            "a reason containing a line break must be rejected at deserialization"
        );
    }

    #[test]
    fn admin_crl_revoke_request_accepts_reason_with_colon() {
        let pubkey = crate::ss58::encode(&[0x22; 32]);
        let raw = format!(r#"{{"pubkey_ss58":"{pubkey}","reason":"abuse: repeated"}}"#);
        let parsed: AdminCrlRevokeRequest =
            serde_json::from_str(&raw).expect("colon in reason must be accepted");
        assert_eq!(parsed.reason, "abuse: repeated");
    }

    #[test]
    fn crl_canonical_message_is_sorted_by_pubkey_and_pinned() {
        let addr_a = crate::ss58::encode(&[0x00; 32]);
        let addr_b = crate::ss58::encode(&[0x07; 32]);
        assert_eq!(addr_a, "wb7kgy8FF4rx4tamkksPfoymeeeZVXLrnSjbBxCun3XhP9DnB");
        assert_eq!(addr_b, "wb7uuPeV524ZMHaQnrrsgXkRNirw6ntzcMaQ1vgcNsMEMRCDm");

        // Entries handed in reverse-sorted order to prove the function
        // sorts them by pubkey before building the preimage.
        let entries = vec![
            CrlEntry {
                pubkey_ss58: PubkeySs58::try_from(addr_b.clone()).unwrap(),
                revoked_at_unix_secs: 1_700_000_100,
                reason: "abuse".to_owned(),
            },
            CrlEntry {
                pubkey_ss58: PubkeySs58::try_from(addr_a.clone()).unwrap(),
                revoked_at_unix_secs: 1_700_000_000,
                reason: "chargeback".to_owned(),
            },
        ];
        let message = crl_canonical_message(3, 1_700_000_200, &entries);
        let expected = format!(
            "v1\n3\n1700000200\n{addr_a}:1700000000:chargeback\n{addr_b}:1700000100:abuse\n"
        );
        assert_eq!(String::from_utf8(message).unwrap(), expected);
    }

    #[test]
    fn enroll_exit_request_debug_redacts_token() {
        let req = EnrollExitRequest {
            token: "wkey-exit-abc123-supersecret".to_owned(),
        };
        let debug = format!("{req:?}");
        assert!(
            !debug.contains("supersecret"),
            "Debug must redact the enrollment token: {debug}"
        );
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn admin_create_voucher_response_debug_redacts_secret() {
        let resp = AdminCreateVoucherResponse {
            voucher_secret: "ABCD-EFGH-JKMN-PQRS".to_owned(),
            secret_hash_hex: "deadbeef".to_owned(),
            duration_secs: 3600,
            max_redemptions: Some(1),
            valid_until_unix_secs: None,
        };
        let debug = format!("{resp:?}");
        assert!(
            !debug.contains("ABCD-EFGH-JKMN-PQRS"),
            "Debug must redact the show-once voucher secret: {debug}"
        );
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn admin_create_enrollment_token_response_debug_redacts_token() {
        let resp = AdminCreateEnrollmentTokenResponse {
            token: "wkey-exit-abc123-supersecret".to_owned(),
            id: TokenId::from_hex_validated("abc123abc123".to_owned()),
            expires_at: 1_700_086_400,
            scope_country: CountryCode::try_from("FR").unwrap(),
            scope_city: "Paris".to_owned(),
            scope_weight: 100,
        };
        let debug = format!("{resp:?}");
        assert!(
            !debug.contains("supersecret"),
            "Debug must redact the show-once clear token: {debug}"
        );
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn hwqual_evaluate_marks_standard_class_for_mid_tier_nic() {
        let mut q = sample_hwqual();
        q.nic_speed_mbps = 2500;
        let q = q.evaluate();
        assert_eq!(q.verdict, ExitHwQualVerdict::Go);
        assert_eq!(
            q.capacity_class, "standard",
            "2.5G NIC is below the high-class 10G floor"
        );
    }

    #[test]
    fn hwqual_evaluate_marks_entry_class_for_1g_nic() {
        let mut q = sample_hwqual();
        q.nic_speed_mbps = 1_000;
        let q = q.evaluate();
        assert_eq!(q.verdict, ExitHwQualVerdict::Go);
        assert_eq!(
            q.capacity_class, "entry",
            "1G NIC clears the floor but is below the standard tier"
        );
    }

    #[test]
    fn hwqual_evaluate_fails_a_nic_below_the_floor() {
        let mut q = sample_hwqual();
        q.nic_speed_mbps = 999;
        let q = q.evaluate();
        assert_eq!(q.verdict, ExitHwQualVerdict::NoGo);
        assert!(
            q.reasons.contains("NIC below 1 Gbit/s"),
            "reason names the NIC floor: {}",
            q.reasons
        );
    }

    #[test]
    fn hwqual_evaluate_fails_a_box_with_too_few_cores() {
        let mut q = sample_hwqual();
        q.cpu_cores = 1;
        let q = q.evaluate();
        assert_eq!(q.verdict, ExitHwQualVerdict::NoGo);
        assert!(
            q.reasons.contains("fewer than 2 cores"),
            "reason names the core floor: {}",
            q.reasons
        );
    }

    #[test]
    fn hwqual_summary_go_one_liner_contains_class_and_go() {
        let q = sample_hwqual().evaluate();
        let summary = q.summary();
        assert!(summary.starts_with("GO:"), "summary: {summary}");
        assert!(summary.contains("high-class"), "summary: {summary}");
    }

    #[test]
    fn hwqual_summary_no_go_one_liner_contains_no_go_and_bracketed_reasons() {
        let mut q = sample_hwqual();
        q.aes_ni = false;
        let q = q.evaluate();
        let summary = q.summary();
        assert!(summary.starts_with("NO_GO:"), "summary: {summary}");
        assert!(
            summary.contains("[no AES-NI"),
            "summary must bracket the reasons: {summary}"
        );
    }

    #[test]
    fn incident_exit_down_request_round_trips() {
        let req = IncidentExitDownRequest {
            exit_pubkey_hex: PubkeyHex::try_from(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .expect("test fixture: 64-hex"),
            reason_code: IncidentReason::HandshakeFail,
            ts_unix: 1_700_000_000,
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let parsed: IncidentExitDownRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.exit_pubkey_hex, req.exit_pubkey_hex);
        assert_eq!(parsed.reason_code, req.reason_code);
        assert_eq!(parsed.ts_unix, req.ts_unix);
    }
}
