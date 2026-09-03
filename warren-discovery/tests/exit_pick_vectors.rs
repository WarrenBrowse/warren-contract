//! Golden vectors for the deterministic exit and entry picks
//! ([`pick_exit`] / [`pick_entry`]). Every Warren client family has to make
//! the same choice from the same directory, or a refreshed directory reads
//! as a "different" circuit on one client and tears its tunnel down while
//! another keeps it. The fixture is the byte-level contract for that
//! choice; the sibling-language SDKs replay the same file. Ids are
//! synthetic on purpose.

use warren_discovery_core::{Continent, EntryCandidate, ExitCandidate, pick_entry, pick_exit};

#[derive(serde::Deserialize)]
struct Fixture {
    version: u32,
    exit: Vec<ExitCase>,
    entry: Vec<EntryCase>,
}

#[derive(serde::Deserialize)]
struct ExitCase {
    name: String,
    candidates: Vec<ExitRow>,
    expected: Option<usize>,
}

#[derive(serde::Deserialize)]
struct ExitRow {
    weight: u64,
    exit_id: String,
}

#[derive(serde::Deserialize)]
struct EntryCase {
    name: String,
    client_continent: Option<Continent>,
    candidates: Vec<EntryRow>,
    expected: Option<usize>,
}

#[derive(serde::Deserialize)]
struct EntryRow {
    weight: u64,
    node_id: String,
    country: String,
}

fn id16(hex_id: &str) -> [u8; 16] {
    hex::decode(hex_id)
        .expect("fixture ids are hex")
        .try_into()
        .expect("fixture ids are 16 bytes")
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/exit_pick.json"))
        .expect("exit_pick.json must parse")
}

#[test]
fn exit_vectors_replay_against_pick_exit() {
    for case in &fixture().exit {
        let candidates: Vec<ExitCandidate> = case
            .candidates
            .iter()
            .map(|c| ExitCandidate {
                weight: c.weight,
                exit_id: id16(&c.exit_id),
            })
            .collect();
        assert_eq!(
            pick_exit(&candidates),
            case.expected,
            "exit vector `{}` diverged",
            case.name
        );
    }
}

#[test]
fn entry_vectors_replay_against_pick_entry() {
    for case in &fixture().entry {
        let candidates: Vec<EntryCandidate<'_>> = case
            .candidates
            .iter()
            .map(|c| EntryCandidate {
                weight: c.weight,
                node_id: id16(&c.node_id),
                country: c.country.as_str(),
            })
            .collect();
        assert_eq!(
            pick_entry(&candidates, case.client_continent),
            case.expected,
            "entry vector `{}` diverged",
            case.name
        );
    }
}

#[test]
fn fixture_is_versioned_populated_and_free_of_duplicate_names() {
    // A pruned or half-emptied fixture would let a sibling-language replay
    // pass on a subset of the rule, so the shape itself is pinned.
    let f = fixture();
    assert_eq!(f.version, 1, "vector schema version");
    assert!(f.exit.len() >= 8, "exit section must keep its cases");
    assert!(f.entry.len() >= 14, "entry section must keep its cases");
    for (section, names) in [
        (
            "exit",
            f.exit.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        ),
        (
            "entry",
            f.entry.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
        ),
    ] {
        let mut seen = std::collections::HashSet::new();
        for name in names {
            assert!(
                seen.insert(name),
                "duplicate {section} vector name `{name}`"
            );
        }
    }
}

#[test]
fn continent_serializes_to_the_cross_language_spelling() {
    // Pins the lowercase spelling the fixture and the TypeScript/Dart
    // replays use: a rename here breaks the shared fixture on purpose.
    for (continent, spelled) in [
        (Continent::Europe, "europe"),
        (Continent::Americas, "americas"),
        (Continent::Asia, "asia"),
        (Continent::Africa, "africa"),
        (Continent::Oceania, "oceania"),
    ] {
        assert_eq!(
            serde_json::to_value(continent).unwrap(),
            serde_json::json!(spelled)
        );
        let back: Continent = serde_json::from_value(serde_json::json!(spelled)).unwrap();
        assert_eq!(back, continent);
    }
}
