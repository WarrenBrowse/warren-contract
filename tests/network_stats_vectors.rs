//! Golden wire vector for the public `GET /v1/network/stats` transparency
//! snapshot. The app (daemon, JNI), the website and the TypeScript SDK all
//! parse this JSON, so a field rename or retype here breaks four readers at
//! once: the fixture pins the exact shape.

use warren_contract::dto::{
    ExitHistoryPoint, ExitId, ExitLiveStats, FleetHistoryPoint, FleetLiveStats, LoadDriver,
    LoadLevel, NetworkStatsResponse, NetworkUserStats,
};

const FIXTURE: &str = include_str!("fixtures/network-stats-v1.json");

fn sample() -> NetworkStatsResponse {
    NetworkStatsResponse {
        version: 1,
        environment: "beta".to_owned(),
        generated_at: 1_790_000_000,
        window_secs: 60,
        exit_users_rounding: 5,
        exit_live_threshold: 20,
        users: NetworkUserStats {
            accounts_total: 1_234,
            subscribers_active: 987,
            connected: 57,
        },
        fleet: FleetLiveStats {
            exits_online: 2,
            exits_total: 3,
            download_bps: 400_000_000,
            upload_bps: 50_000_000,
            capacity_bps: 2_000_000_000,
            load_percent: 23,
            transferred_24h_bytes: 9_000_000_000_000,
            peak_connected_24h: 80,
            peak_throughput_24h_bps: 900_000_000,
        },
        exits: vec![
            ExitLiveStats {
                exit_id: ExitId::from_bytes([0xab; 16]),
                name: Some("fr-par-h1b".to_owned()),
                country: "FR".to_owned(),
                city: "Paris".to_owned(),
                online: true,
                live: true,
                connected: 40,
                download_bps: 300_000_000,
                upload_bps: 30_000_000,
                capacity_bps: Some(1_000_000_000),
                load_percent: Some(37),
                load_level: Some(LoadLevel::Low),
                load_driver: Some(LoadDriver::Bandwidth),
                cpu_percent: Some(21),
                uptime_secs: Some(172_800),
                history: vec![ExitHistoryPoint {
                    t: 1_789_999_940,
                    connected: 40,
                    throughput_bps: 310_000_000,
                    load_percent: Some(35),
                }],
            },
            ExitLiveStats {
                exit_id: ExitId::from_bytes([0xcd; 16]),
                name: None,
                country: "RO".to_owned(),
                city: "Bucharest".to_owned(),
                online: true,
                live: false,
                connected: 0,
                download_bps: 0,
                upload_bps: 0,
                capacity_bps: None,
                load_percent: None,
                load_level: Some(LoadLevel::Moderate),
                load_driver: None,
                cpu_percent: None,
                uptime_secs: None,
                history: vec![],
            },
        ],
        history: vec![FleetHistoryPoint {
            t: 1_789_999_100,
            connected: 55,
            throughput_bps: 420_000_000,
        }],
    }
}

#[test]
fn network_stats_matches_the_frozen_fixture() {
    let expected: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture is JSON");
    assert_eq!(
        serde_json::to_value(sample()).expect("serialize"),
        expected,
        "the stats snapshot is parsed by the daemon, the JNI, the website and the TS SDK: its JSON shape is frozen"
    );
}

#[test]
fn network_stats_parses_the_frozen_fixture() {
    let parsed: NetworkStatsResponse = serde_json::from_str(FIXTURE).expect("fixture parses");
    assert_eq!(parsed, sample());
}

#[test]
fn an_unknown_load_level_or_driver_parses_as_unknown() {
    let level: LoadLevel = serde_json::from_str("\"overheated\"").expect("tolerant");
    let driver: LoadDriver = serde_json::from_str("\"memory\"").expect("tolerant");
    assert_eq!(
        (level, driver),
        (LoadLevel::Unknown, LoadDriver::Unknown),
        "a server adding a level or a driver must not break a deployed client"
    );
}

#[test]
fn a_snapshot_with_unknown_fields_still_parses() {
    let mut value: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture is JSON");
    value["fleet"]["added_later"] = serde_json::json!(1);
    value["exits"][0]["added_later"] = serde_json::json!("x");
    let parsed: NetworkStatsResponse =
        serde_json::from_value(value).expect("new fields are additive");
    assert_eq!(parsed, sample());
}
