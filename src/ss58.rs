//! SS58 codec for the Warren wallet identity public key.
//!
//! The Warren user identity is a 32-byte Ed25519 public key derived
//! from the user's BIP39 mnemonic (see `warren_identity::derive_node_key`).
//! Its **canonical string representation** - everywhere it is rendered as
//! text (the `X-Warren-PubKey` auth header, JSON request bodies, SQLite
//! columns, config files, structured logs, the desktop/mobile UI, the
//! FFI surface) - is an **SS58 address** with Warren's network prefix
//! [`WARREN_SS58_PREFIX`] (`13295`).
//!
//! SS58 is the Substrate/Polkadot address format. It is *only* an
//! encoding of the same 32 raw bytes plus a 2-byte network prefix and a
//! 2-byte Blake2b checksum - the cryptographic key, the Ed25519
//! signatures, and the TLS raw-public-key handshake are all unchanged.
//! Decode an address back to the 32 bytes at the crypto boundary, encode
//! the 32 bytes to an address at the string boundary.
//!
//! # Why prefix 13295
//!
//! Prefix `13295` lands every Warren address in a fixed visual bucket:
//! the base58 output always starts with **`wb`** (Warren Browse) and is
//! 47-49 characters long. This is a deliberate branding choice and a
//! cheap human sanity check ("does it start with `wb`?").
//!
//! # Wire compatibility
//!
//! This codec is byte-for-byte identical to
//! [`@polkadot/util-crypto`](https://github.com/polkadot-js/common)
//! `encodeAddress(pubkey, 13295)` / `decodeAddress`. The
//! `polkadot_reference_vectors` test pins the exact strings
//! produced by `@polkadot/util-crypto` v14, so any divergence (here or
//! in the JS layer) fails CI. The desktop renderer uses the JS library
//! directly; this Rust codec serves the daemon, the backend
//! (`warren-api`), and the mobile FFI/JNI.
//!
//! # Algorithm (SS58, [Substrate spec])
//!
//! ```text
//! prefix_bytes = ss58_prefix_encoding(13295)            // 2 bytes here
//! checksum     = blake2b_512("SS58PRE" || prefix_bytes || pubkey)[..2]
//! address      = base58( prefix_bytes || pubkey || checksum )
//! ```
//!
//! [Substrate spec]: https://docs.substrate.io/reference/address-formats/

use blake2::{Blake2b512, Digest};

/// Warren's SS58 network prefix. Chosen so that every encoded address
/// starts with the `wb` (Warren Browse) base58 prefix.
///
/// Valid SS58 prefixes are 14-bit (`0..=16383`); `13295` sits in the
/// two-byte-encoded range (`64..=16383`).
pub const WARREN_SS58_PREFIX: u16 = 13295;

/// SS58 checksum domain-separation tag, mandated by the spec.
const SS58_CHECKSUM_PREFIX: &[u8] = b"SS58PRE";

/// Raw Ed25519 public-key length (the SS58 payload for an AccountId32).
const PUBKEY_LEN: usize = 32;

/// Checksum length appended after the payload. SS58 uses 2 bytes for a
/// 32-byte account id.
const CHECKSUM_LEN: usize = 2;

/// Length of the two-byte prefix encoding used for `13295`.
const PREFIX_LEN: usize = 2;

/// Total decoded length of a Warren address: `prefix(2) + pubkey(32) +
/// checksum(2)`.
const DECODED_LEN: usize = PREFIX_LEN + PUBKEY_LEN + CHECKSUM_LEN;

/// Hard cap on the textual address length accepted by [`decode`]. A
/// 36-byte payload encodes to 47-49 base58 chars; 64 leaves slack
/// while keeping the O(n^2) base58 decoder away from unauthenticated
/// megabyte inputs (this codec parses the `X-Warren-PubKey` header
/// before any signature check).
const MAX_ADDRESS_LEN: usize = 64;

/// Errors returned when decoding an SS58 string into a Warren pubkey.
///
/// Deliberately exhaustive: the SS58 format has exactly these four
/// failure modes, so downstream crates (e.g. `mullvad-types`) can match
/// them all without a catch-all arm.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Ss58Error {
    /// The string is not valid base58.
    #[error("not valid base58")]
    BadBase58,
    /// The decoded byte length is not `prefix(2) + pubkey(32) +
    /// checksum(2)` = 36 bytes (e.g. an address for a different SS58
    /// account type, or a truncated string).
    #[error("unexpected decoded length (not a 32-byte SS58 account address)")]
    BadLength,
    /// The address encodes a different SS58 network prefix than
    /// [`WARREN_SS58_PREFIX`]. We reject foreign-network addresses
    /// rather than silently accept them.
    #[error("wrong SS58 network prefix (not a Warren `wb…` address)")]
    WrongNetwork,
    /// The Blake2b checksum does not match - the address is corrupt or
    /// mistyped.
    #[error("SS58 checksum mismatch (corrupt or mistyped address)")]
    BadChecksum,
}

/// Encodes the two-byte SS58 prefix for a 14-bit network ident in the
/// `64..=16383` range, per the Substrate spec.
fn encode_prefix(prefix: u16) -> [u8; PREFIX_LEN] {
    // 14-bit ident. `13295` already fits; the mask documents the field.
    let ident = prefix & 0b0011_1111_1111_1111;
    let first = ((ident & 0b0000_0000_1111_1100) >> 2) as u8 | 0b0100_0000;
    let second = ((ident >> 8) as u8) | (((ident & 0b0000_0000_0000_0011) << 6) as u8);
    [first, second]
}

/// Computes the 2-byte SS58 checksum over `prefix_bytes || pubkey`.
fn checksum(prefix_bytes: &[u8], pubkey: &[u8; PUBKEY_LEN]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Blake2b512::new();
    hasher.update(SS58_CHECKSUM_PREFIX);
    hasher.update(prefix_bytes);
    hasher.update(pubkey);
    let digest = hasher.finalize();
    [digest[0], digest[1]]
}

/// Encodes a raw 32-byte Ed25519 public key as a Warren SS58 address
/// (`wb…`).
///
/// Infallible: every 32-byte input maps to a valid address.
#[must_use]
pub fn encode(pubkey: &[u8; PUBKEY_LEN]) -> String {
    let prefix_bytes = encode_prefix(WARREN_SS58_PREFIX);
    let cs = checksum(&prefix_bytes, pubkey);

    let mut buf = [0u8; DECODED_LEN];
    buf[..PREFIX_LEN].copy_from_slice(&prefix_bytes);
    buf[PREFIX_LEN..PREFIX_LEN + PUBKEY_LEN].copy_from_slice(pubkey);
    buf[PREFIX_LEN + PUBKEY_LEN..].copy_from_slice(&cs);

    bs58::encode(buf).into_string()
}

/// Decodes a Warren SS58 address back into the raw 32-byte Ed25519
/// public key.
///
/// Strictly validates the network prefix ([`WARREN_SS58_PREFIX`]) and
/// the Blake2b checksum, so a corrupt, mistyped, or foreign-network
/// address is rejected rather than silently coerced.
///
/// # Errors
///
/// See [`Ss58Error`].
pub fn decode(address: &str) -> Result<[u8; PUBKEY_LEN], Ss58Error> {
    // Cheap length gate BEFORE the O(n^2) base58 decode: this runs on
    // unauthenticated input (auth header), so an oversized string must
    // never reach the quadratic path.
    if address.len() > MAX_ADDRESS_LEN {
        return Err(Ss58Error::BadLength);
    }

    let data = bs58::decode(address)
        .into_vec()
        .map_err(|_| Ss58Error::BadBase58)?;

    if data.len() != DECODED_LEN {
        return Err(Ss58Error::BadLength);
    }

    let expected_prefix = encode_prefix(WARREN_SS58_PREFIX);
    if data[..PREFIX_LEN] != expected_prefix {
        return Err(Ss58Error::WrongNetwork);
    }

    let pubkey: [u8; PUBKEY_LEN] = data[PREFIX_LEN..PREFIX_LEN + PUBKEY_LEN]
        .try_into()
        .expect("slice length checked above");

    let expected_cs = checksum(&expected_prefix, &pubkey);
    if data[PREFIX_LEN + PUBKEY_LEN..] != expected_cs {
        return Err(Ss58Error::BadChecksum);
    }

    Ok(pubkey)
}

/// Returns `true` if `address` is a well-formed Warren SS58 address
/// (correct prefix + checksum).
#[must_use]
pub fn is_valid(address: &str) -> bool {
    decode(address).is_ok()
}

/// Number of leading characters kept by [`shorten`].
pub const SHORT_HEAD: usize = 6;
/// Number of trailing characters kept by [`shorten`].
pub const SHORT_TAIL: usize = 6;

/// Shortens an address for compact display, Polkadot-style:
/// `wb7kgy…P9DnB` (first [`SHORT_HEAD`] + `…` + last [`SHORT_TAIL`]).
///
/// Strings too short to shorten (≤ head+tail+1 ellipsis) are returned
/// unchanged. This is a pure presentation helper - the full address is
/// what gets copied to the clipboard and sent on the wire.
#[must_use]
pub fn shorten(address: &str) -> String {
    let len = address.chars().count();
    if len <= SHORT_HEAD + SHORT_TAIL + 1 {
        return address.to_owned();
    }
    let head: String = address.chars().take(SHORT_HEAD).collect();
    let tail: String = address.chars().skip(len - SHORT_TAIL).collect::<String>();
    format!("{head}…{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ground-truth vectors captured from `@polkadot/util-crypto` v14
    /// (`encodeAddress(hexToU8a(pubkey), 13295)`). These freeze the wire
    /// format: any drift in this Rust codec OR in the desktop JS layer
    /// fails against the same constants.
    ///
    /// `(pubkey_hex, expected_ss58)`.
    const POLKADOT_VECTORS: &[(&str, &str)] = &[
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "wb7kgy8FF4rx4tamkksPfoymeeeZVXLrnSjbBxCun3XhP9DnB",
        ),
        (
            "0707070707070707070707070707070707070707070707070707070707070707",
            "wb7uuPeV524ZMHaQnrrsgXkRNirw6ntzcMaQ1vgcNsMEMRCDm",
        ),
        (
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "wbBdxLCYEJVa8tMAFTJVYn5tvHX8SUf8SZmSQRqs9ro3EXEkh",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "wb7khGVR6Ymj2RtPCAgzamtdT5DT6xhM84hfhYkBf3b8ouCzT",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "wbDYME7neT9po3eBDfQGhBt35J8hnaXVJdg9KZtZ5WPHsRRhP",
        ),
    ];

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s)
            .expect("test hex")
            .try_into()
            .expect("32 bytes")
    }

    #[test]
    fn polkadot_reference_vectors() {
        // Encode must reproduce @polkadot/util-crypto byte-for-byte.
        for (pubkey_hex, expected) in POLKADOT_VECTORS {
            let pubkey = hex32(pubkey_hex);
            let addr = encode(&pubkey);
            assert_eq!(
                &addr, expected,
                "SS58 encode diverged from @polkadot for pubkey {pubkey_hex}"
            );
            // And decode must invert it back to the exact bytes.
            assert_eq!(
                decode(expected).expect("reference address must decode"),
                pubkey,
                "SS58 decode diverged for {expected}"
            );
        }
    }

    #[test]
    fn full_chain_derivation_anchors() {
        // Anchors tying the warren-identity derivation vectors (frozen
        // in `lib.rs` / `wallet`) to their SS58 form. Computed via
        // @polkadot/util-crypto v14 against the known derived pubkeys.
        let anchors = [
            (
                "21e9276da8395d56af5c83c00ffb4afba7ebd337189aeea9136bfc9d3fd44f6b",
                "wb8X9ovjY66mreUk8qVtmRX5DGP4mkTqoYkUFjU6gbtjp1mUr",
            ),
            (
                "d9d24d24f77550ec46914c30d83dc973063c759967d03af4efe508fb34ed5308",
                "wbCgHqDAE3CKBuAeSDCC4r9TZtjXveuXNd934zzm7ncceJa6q",
            ),
            (
                "fba874de8721df35921c9999a036c03bb098df35fc21fcbeac98af880ababdb9",
                "wbDSf2fncAfyDQkNbkyqjuhi8kpg3z8kCHqL2TYDSM2F1nVED",
            ),
        ];
        for (pubkey_hex, expected) in anchors {
            assert_eq!(&encode(&hex32(pubkey_hex)), expected);
        }
    }

    #[test]
    fn every_warren_address_starts_with_wb() {
        // Branding + cheap sanity invariant: prefix 13295 always yields
        // a `wb…` base58 string.
        for (pubkey_hex, _) in POLKADOT_VECTORS {
            let addr = encode(&hex32(pubkey_hex));
            assert!(addr.starts_with("wb"), "address must start with wb: {addr}");
        }
    }

    #[test]
    fn roundtrip_is_stable_over_many_keys() {
        for i in 0u8..=255 {
            let pubkey = [i; 32];
            let addr = encode(&pubkey);
            assert_eq!(decode(&addr).expect("roundtrip"), pubkey);
        }
    }

    #[test]
    fn decode_rejects_non_base58() {
        // `0`, `O`, `I`, `l` are not in the base58 alphabet.
        assert_eq!(decode("0OIl not base58"), Err(Ss58Error::BadBase58));
    }

    #[test]
    fn decode_rejects_wrong_length() {
        // A valid base58 string that decodes to too few bytes.
        assert_eq!(decode("abc"), Err(Ss58Error::BadLength));
    }

    #[test]
    fn decode_rejects_oversized_input_before_base58() {
        // DoS guard: base58 decoding is O(n^2) and this codec sits on
        // unauthenticated inputs (the X-Warren-PubKey header). Any
        // string longer than MAX_ADDRESS_LEN must be rejected on the
        // cheap length check, never fed to bs58.
        let oversized = "1".repeat(10_000);
        assert_eq!(decode(&oversized), Err(Ss58Error::BadLength));
        // Boundary: exactly one char past the cap is rejected too.
        let just_over = "1".repeat(MAX_ADDRESS_LEN + 1);
        assert_eq!(decode(&just_over), Err(Ss58Error::BadLength));
        // Sanity: every legitimate Warren address fits under the cap
        // (47-49 chars), so the guard cannot reject a real address.
        for (_, addr) in POLKADOT_VECTORS {
            assert!(addr.len() <= MAX_ADDRESS_LEN);
            assert!(decode(addr).is_ok());
        }
    }

    #[test]
    fn decode_rejects_foreign_network_prefix() {
        // The same 32 bytes (`0x11…`) encoded for a *different* two-byte
        // SS58 network (prefix 1000, via @polkadot/util-crypto) decodes
        // to the same 36-byte length but a different prefix → rejected
        // as a foreign network (not BadLength).
        let foreign_addr = "vjdfteK8ZU3Lg6jotudWVQk1eGD7GEnb46Xv5JdmKpQD2WB1r";
        assert_eq!(decode(foreign_addr), Err(Ss58Error::WrongNetwork));
    }

    #[test]
    fn decode_rejects_corrupt_checksum() {
        // Flip one char in the middle of a valid address → checksum (or
        // payload) mismatch. We mutate a body char, not the `wb` head,
        // to keep the prefix intact and exercise the checksum path.
        let good = encode(&[0x11; 32]);
        let mut chars: Vec<char> = good.chars().collect();
        // Pick an index well inside the payload region.
        let idx = chars.len() / 2;
        chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
        let corrupt: String = chars.into_iter().collect();
        // Either checksum mismatch or, if the mutation lands on the
        // prefix bits after base58 carry, wrong network - both are
        // rejections, never an `Ok`.
        assert!(decode(&corrupt).is_err());
    }

    #[test]
    fn shorten_keeps_head_and_tail() {
        let addr = "wb7kgy8FF4rx4tamkksPfoymeeeZVXLrnSjbBxCun3XhP9DnB";
        assert_eq!(shorten(addr), "wb7kgy…hP9DnB");
    }

    #[test]
    fn shorten_leaves_short_strings_untouched() {
        assert_eq!(shorten("wb7kgy"), "wb7kgy");
        assert_eq!(shorten("short"), "short");
    }

    #[test]
    fn is_valid_matches_decode() {
        let addr = encode(&[0x42; 32]);
        assert!(is_valid(&addr));
        assert!(!is_valid("definitely not an address"));
    }
}
