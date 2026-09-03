//! The deterministic exit and entry picks every Warren client makes from a
//! verified directory, promoted from the production app daemon so the SDK
//! family cannot choose differently from the desktop app on the same
//! directory.
//!
//! Both picks are pure functions over pre-filtered candidates (country
//! hint, drain avoid-set and the [`super::multihop_directory::CircuitPolicy`]
//! diversity rule are the caller's job) and both are deterministic on
//! purpose: a per-call weighted RNG once made the daemon see a "different"
//! circuit on every directory poll and tear the tunnel down in an endless
//! reconnect loop. Do NOT reintroduce randomness here.
//!
//! - [`pick_exit`]: highest `weight`, ties broken by the smallest `exit_id`
//!   (the daemon's 1-hop rule).
//! - [`pick_entry`]: entries on the client's continent first when any
//!   exist, then highest `weight`, ties broken by the smallest node id (the
//!   daemon's 2-hop entry rule). The continent comes from purely local
//!   signals, so a location-blind client passes `None` and gets the pure
//!   weight order.
//!
//! The golden vector `tests/fixtures/exit_pick.json` pins both rules.

use std::cmp::Reverse;

use serde::{Deserialize, Serialize};

use super::multihop_directory::{NodeEntry, VerifiedEntry, VerifiedExit};

/// Coarse continent grouping for the latency-aware entry ranking.
/// Continent-level is deliberate: it is derivable from purely local
/// signals (no probe, no geolocation call, nothing observable on the
/// wire) and it already separates the pathological picks (an
/// intercontinental entry hop taxes every serialized connect round trip
/// and every steady-state packet with ~10x the RTT).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Continent {
    /// Europe, Turkey included (see [`continent_of_country`]).
    Europe,
    /// North and South America.
    Americas,
    /// Asia and the Middle East.
    Asia,
    /// Africa.
    Africa,
    /// Australia and the Pacific.
    Oceania,
}

/// Continent of an ISO 3166-1 alpha-2 country code, covering plausible
/// fleet countries. `None` (unknown code) disables the proximity
/// preference for that node rather than guessing.
#[must_use]
pub fn continent_of_country(cc: &str) -> Option<Continent> {
    let bytes = cc.as_bytes();
    if bytes.len() != 2 {
        return None;
    }
    let buf = [bytes[0].to_ascii_lowercase(), bytes[1].to_ascii_lowercase()];
    match &buf {
        b"at" | b"be" | b"bg" | b"ch" | b"cz" | b"de" | b"dk" | b"ee" | b"es" | b"fi" | b"fr"
        | b"gb" | b"gr" | b"hr" | b"hu" | b"ie" | b"is" | b"it" | b"lt" | b"lu" | b"lv" | b"md"
        | b"mt" | b"nl" | b"no" | b"pl" | b"pt" | b"ro" | b"rs" | b"se" | b"si" | b"sk" | b"ua" => {
            Some(Continent::Europe)
        }
        b"ar" | b"br" | b"ca" | b"cl" | b"co" | b"mx" | b"pe" | b"us" => Some(Continent::Americas),
        // `tr` sits with Europe to stay consistent with the IANA area of its
        // timezone (`Europe/Istanbul`): a client deriving its continent from
        // the timezone must agree with the country side, or Turkish clients
        // would never see a TR entry as local.
        b"tr" => Some(Continent::Europe),
        b"ae" | b"hk" | b"id" | b"il" | b"in" | b"jp" | b"kr" | b"my" | b"ph" | b"sg" | b"th"
        | b"tw" | b"vn" => Some(Continent::Asia),
        b"eg" | b"ke" | b"ma" | b"ng" | b"za" => Some(Continent::Africa),
        b"au" | b"nz" => Some(Continent::Oceania),
        _ => None,
    }
}

/// What [`pick_exit`] ranks on: the server-envelope selection weight and
/// the exit's 16-byte routing tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitCandidate {
    /// Selection weight (unattested server-envelope tier).
    pub weight: u64,
    /// The exit's routing tag, the deterministic tie-break key.
    pub exit_id: [u8; 16],
}

impl From<&NodeEntry> for ExitCandidate {
    fn from(n: &NodeEntry) -> Self {
        Self {
            weight: n.weight,
            exit_id: *n.exit.exit_id.as_bytes(),
        }
    }
}

impl From<&VerifiedExit> for ExitCandidate {
    fn from(x: &VerifiedExit) -> Self {
        Self {
            weight: x.weight,
            exit_id: x.exit_id,
        }
    }
}

/// What [`pick_entry`] ranks on: the entry's selection weight, its node
/// routing tag and its attested country.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryCandidate<'a> {
    /// Selection weight (unattested server-envelope tier).
    pub weight: u64,
    /// The entry node's 16-byte routing tag: `relay.relay_id` in the
    /// directory view, `exit_id` in the flat entry view (the dual-role fleet
    /// gives one node the same bytes for both).
    pub node_id: [u8; 16],
    /// ISO 3166-1 alpha-2 country, any case (attested).
    pub country: &'a str,
}

impl<'a> From<&'a NodeEntry> for EntryCandidate<'a> {
    fn from(n: &'a NodeEntry) -> Self {
        Self {
            weight: n.weight,
            node_id: n.relay.relay_id,
            country: &n.country,
        }
    }
}

impl<'a> From<&'a VerifiedEntry> for EntryCandidate<'a> {
    fn from(e: &'a VerifiedEntry) -> Self {
        Self {
            weight: e.weight,
            node_id: e.exit_id,
            country: &e.country,
        }
    }
}

/// Index of the exit to dial among `candidates`: highest weight, ties
/// broken by the smallest `exit_id` (byte-lexicographic), a full tie by the
/// first index. `None` on an empty slice.
///
/// Weights are compared, never summed, so an untrusted `u64::MAX` weight
/// cannot overflow anything.
#[must_use]
pub fn pick_exit(candidates: &[ExitCandidate]) -> Option<usize> {
    // `min_by_key` returns the FIRST minimum, which is what makes a full tie
    // deterministic on the index.
    (0..candidates.len()).min_by_key(|&i| (Reverse(candidates[i].weight), candidates[i].exit_id))
}

/// Indices of the `items` on the client's continent when at least one is,
/// otherwise every index: the continent preference narrows, it never
/// empties. `country_of` yields the item's ISO 3166-1 alpha-2 country.
/// `None` for `client_continent` (location-blind client, unknown timezone)
/// keeps every index.
///
/// This is the partition [`pick_entry`] applies; it is exposed so a caller
/// ranking `(entry, exit)` pairs by the shared path-aware score can apply
/// the same preference to its pairs through the entry's country.
#[must_use]
pub fn prefer_client_continent<T, F>(
    items: &[T],
    client_continent: Option<Continent>,
    country_of: F,
) -> Vec<usize>
where
    F: Fn(&T) -> &str,
{
    let local: Vec<usize> = client_continent
        .map(|client| {
            items
                .iter()
                .enumerate()
                .filter(|(_, item)| continent_of_country(country_of(item)) == Some(client))
                .map(|(i, _)| i)
                .collect()
        })
        .unwrap_or_default();
    if local.is_empty() {
        (0..items.len()).collect()
    } else {
        local
    }
}

/// Index of the entry to dial among `candidates` for an already-chosen
/// exit: entries on the client's continent first when any exist (see
/// [`prefer_client_continent`]), then highest weight, ties broken by the
/// smallest `node_id`, a full tie by the first index. `None` on an empty
/// slice.
///
/// For a fixed exit this is exactly the no-signal order of
/// [`super::path_aware::select_entry_path_aware`] restricted to the
/// continent partition, which is how the app daemon has ranked entries
/// since the proximity rule shipped.
#[must_use]
pub fn pick_entry(
    candidates: &[EntryCandidate<'_>],
    client_continent: Option<Continent>,
) -> Option<usize> {
    prefer_client_continent(candidates, client_continent, |c| c.country)
        .into_iter()
        .min_by_key(|&i| (Reverse(candidates[i].weight), candidates[i].node_id))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use warrenguard_multihop::{ExitDescriptorSigned, ExitId, RelayDescriptorSigned};

    use super::super::multihop_directory::{CircuitPolicy, VerifiedMultiHopDirectory};
    use super::super::path_aware::{PathAwareParams, select_entry_path_aware};
    use super::*;

    fn node(tag: u8, country: &str, weight: u64) -> NodeEntry {
        let endpoint: std::net::SocketAddr = format!("198.51.100.{tag}:443").parse().unwrap();
        NodeEntry {
            relay: RelayDescriptorSigned {
                relay_id: [tag; 16],
                relay_ed25519_pubkey: [tag; 32],
                endpoint,
                cover_domain: None,
                tcp_fallback: false,
                signature: [0; 64],
            },
            exit: ExitDescriptorSigned {
                exit_id: ExitId::from_bytes([tag; 16]),
                exit_ed25519_pubkey: [tag; 32],
                exit_x25519_multihop_pubkey: [tag; 32],
                endpoint: Some(endpoint),
                cover_domain: None,
                signature: [0; 64],
                dns_disabled: false,
                exit_mlkem768_pubkey: None,
            },
            country: country.to_owned(),
            city: "City".to_owned(),
            asn: 0,
            weight,
            attestation_hex: String::new(),
            edge_cert_sha256: None,
        }
    }

    fn dir(nodes: Vec<NodeEntry>) -> VerifiedMultiHopDirectory {
        VerifiedMultiHopDirectory {
            operational_pubkey: SigningKey::from_bytes(&[7; 32]).verifying_key(),
            nodes,
            generation: 1,
            signed_at: 0,
            expires_at: u64::MAX,
            dropped: 0,
        }
    }

    #[test]
    fn continent_mappings_cover_the_fleet_and_stay_conservative() {
        assert_eq!(continent_of_country("de"), Some(Continent::Europe));
        assert_eq!(continent_of_country("NL"), Some(Continent::Europe));
        assert_eq!(continent_of_country("tr"), Some(Continent::Europe));
        assert_eq!(continent_of_country("sg"), Some(Continent::Asia));
        assert_eq!(continent_of_country("us"), Some(Continent::Americas));
        assert_eq!(continent_of_country("za"), Some(Continent::Africa));
        assert_eq!(continent_of_country("nz"), Some(Continent::Oceania));
        assert_eq!(
            continent_of_country("zz"),
            None,
            "an unknown country must disable the preference, not guess"
        );
        assert_eq!(continent_of_country("deu"), None, "alpha-3 is not modeled");
        assert_eq!(continent_of_country(""), None);
    }

    #[test]
    fn exit_candidates_project_identically_from_both_directory_views() {
        let d = dir(vec![node(3, "nl", 42)]);
        let from_node = ExitCandidate::from(&d.nodes[0]);
        let from_flat = ExitCandidate::from(&d.exits()[0]);
        assert_eq!(from_node, from_flat);
        assert_eq!(
            from_node,
            ExitCandidate {
                weight: 42,
                exit_id: [3; 16]
            }
        );
    }

    #[test]
    fn entry_candidates_project_identically_from_both_directory_views() {
        let d = dir(vec![node(5, "DE", 9)]);
        let entries = d.entries();
        let from_node = EntryCandidate::from(&d.nodes[0]);
        let from_flat = EntryCandidate::from(&entries[0]);
        assert_eq!(from_node, from_flat);
        assert_eq!(
            from_node,
            EntryCandidate {
                weight: 9,
                node_id: [5; 16],
                country: "DE"
            }
        );
    }

    #[test]
    fn exit_pick_over_directory_nodes_is_highest_weight_then_smallest_id() {
        let d = dir(vec![
            node(9, "nl", 100),
            node(2, "de", 300),
            node(1, "de", 300),
        ]);
        let candidates: Vec<ExitCandidate> = d.nodes.iter().map(ExitCandidate::from).collect();
        assert_eq!(
            pick_exit(&candidates),
            Some(2),
            "300 ties, id [1;16] < [2;16]"
        );
    }

    #[test]
    fn entry_pick_without_a_continent_agrees_with_the_path_aware_entry_ranking() {
        // The two homes of "which entry fronts this exit" must agree when no
        // path signal exists, or the SDK and the daemon diverge on the same
        // directory.
        let d = dir(vec![
            node(4, "fi", 100),
            node(2, "de", 500),
            node(1, "se", 500),
            node(3, "nl", 100),
        ]);
        let entries = d.entries();
        let exits = d.exits();
        let policy = CircuitPolicy::for_directory(&d);
        let exit = &exits[3];
        let permitted: Vec<&VerifiedEntry> =
            entries.iter().filter(|e| policy.permits(e, exit)).collect();
        let candidates: Vec<EntryCandidate<'_>> =
            permitted.iter().map(|e| EntryCandidate::from(*e)).collect();

        let picked = pick_entry(&candidates, None).map(|i| permitted[i].exit_id);
        let path_aware = select_entry_path_aware(
            &entries,
            exit,
            &policy,
            None,
            |_| None,
            0,
            None,
            &PathAwareParams::default(),
        )
        .map(|e| e.exit_id);
        assert_eq!(picked, path_aware);
        assert_eq!(picked, Some([1; 16]), "500 ties, id [1;16] < [2;16]");
    }

    #[test]
    fn entry_pick_prefers_the_client_continent_over_server_weight() {
        let d = dir(vec![node(1, "sg", 100), node(2, "de", 1)]);
        let candidates: Vec<EntryCandidate<'_>> =
            d.nodes.iter().map(EntryCandidate::from).collect();
        assert_eq!(pick_entry(&candidates, Some(Continent::Europe)), Some(1));
        assert_eq!(pick_entry(&candidates, Some(Continent::Asia)), Some(0));
        assert_eq!(
            pick_entry(&candidates, None),
            Some(0),
            "location-blind keeps the pure weight order"
        );
    }

    #[test]
    fn continent_preference_narrows_but_never_empties() {
        fn country(n: &NodeEntry) -> &str {
            &n.country
        }
        let d = dir(vec![node(1, "sg", 1), node(2, "us", 2), node(3, "de", 3)]);
        assert_eq!(
            prefer_client_continent(&d.nodes, Some(Continent::Europe), country),
            vec![2]
        );
        assert_eq!(
            prefer_client_continent(&d.nodes, Some(Continent::Africa), country),
            vec![0, 1, 2],
            "no local entry: every index stays eligible"
        );
        assert_eq!(
            prefer_client_continent(&d.nodes, None, country),
            vec![0, 1, 2]
        );
        let empty: [NodeEntry; 0] = [];
        assert!(prefer_client_continent(&empty, Some(Continent::Europe), country).is_empty());
    }
}
