//! Golden HTTP `/v1` wire vectors. The DTOs are defined once here and consumed
//! by both the client SDK and the backend, so these freeze the JSON shape: any
//! accidental field rename/retype (which would break the deployed server or the
//! sibling-language SDKs) turns a green build red.

use warren_contract::dto::*;
use warren_contract::ss58;

fn json(v: &impl serde::Serialize) -> serde_json::Value {
    serde_json::to_value(v).unwrap()
}

fn roundtrips<T: serde::Serialize + serde::de::DeserializeOwned>(v: &T) {
    let s = serde_json::to_string(v).unwrap();
    let back: T = serde_json::from_str(&s).unwrap();
    assert_eq!(
        s,
        serde_json::to_string(&back).unwrap(),
        "round-trip changed the JSON"
    );
}

#[test]
fn register_account_request_shape() {
    let addr = ss58::encode(&[0x11; 32]);
    let req = RegisterAccountRequest {
        pubkey_ss58: PubkeySs58::try_from(addr.clone()).unwrap(),
        voucher_secret: "ABCD-EFGH-JKMN-PQRS".to_owned(),
        referral_code: None,
    };
    assert_eq!(
        json(&req),
        serde_json::json!({ "pubkey_ss58": addr, "voucher_secret": "ABCD-EFGH-JKMN-PQRS" }),
        "referral_code must be omitted when None"
    );
    roundtrips(&req);
}

#[test]
fn subscription_response_shape() {
    let resp = SubscriptionResponse {
        expires_at: 1_700_000_000,
    };
    assert_eq!(
        json(&resp),
        serde_json::json!({ "expires_at": 1_700_000_000u64 })
    );
    roundtrips(&resp);
}

#[test]
fn check_response_shape() {
    let resp = CheckResponse {
        ip: "1.2.3.4".to_owned(),
        is_exit: false,
        exit_country: None,
        exit_city: None,
    };
    assert_eq!(
        json(&resp),
        serde_json::json!({ "ip": "1.2.3.4", "is_exit": false }),
        "optional exit_country/exit_city omitted when None"
    );
    roundtrips(&resp);
}

#[test]
fn session_open_response_shape() {
    let resp = SessionOpenResponse {
        admitted: true,
        max: 5,
        current: 1,
    };
    assert_eq!(
        json(&resp),
        serde_json::json!({ "admitted": true, "max": 5, "current": 1 })
    );
    roundtrips(&resp);
}

#[test]
fn incident_reason_screaming_snake_case() {
    assert_eq!(json(&IncidentReason::Timeout), serde_json::json!("TIMEOUT"));
    assert_eq!(
        json(&IncidentReason::HandshakeFail),
        serde_json::json!("HANDSHAKE_FAIL")
    );
    assert_eq!(
        json(&IncidentReason::AuthFail),
        serde_json::json!("AUTH_FAIL")
    );
}

#[test]
fn register_exit_response_update_directive_shape() {
    // Doc 52: the heartbeat response optionally piggybacks the signed
    // release manifest, embedded verbatim (the node re-verifies it; the
    // transport adds no authority). Absent on a normal heartbeat, and a
    // default response stays the empty object older exits expect.
    let resp = RegisterExitResponse::default();
    assert_eq!(json(&resp), serde_json::json!({}));

    let manifest = warren_contract::release::sign_release_manifest(
        "v0.7.0-3-gabc1234",
        "canary",
        &"9f".repeat(32),
        42_000_000,
        7,
        1_700_000_000,
        1_700_086_400,
        &ed25519_dalek::SigningKey::from_bytes(&[0xab; 32]),
    );
    let resp = RegisterExitResponse {
        drain: None,
        update: Some(manifest),
    };
    let v = json(&resp);
    assert_eq!(v["update"]["release_version"], "v0.7.0-3-gabc1234");
    assert_eq!(v["update"]["generation"], 7);
    assert!(
        v.get("drain").is_none(),
        "absent drain must stay omitted next to a present update"
    );
    roundtrips(&resp);
}

#[test]
fn exit_update_status_shape() {
    let st = ExitUpdateStatus {
        state: ExitUpdateState::Staged,
        target_version: Some("v0.7.0-3-gabc1234".to_owned()),
        error: None,
    };
    assert_eq!(
        json(&st),
        serde_json::json!({
            "state": "staged",
            "target_version": "v0.7.0-3-gabc1234",
        }),
        "state is lowercase snake_case; absent error is omitted"
    );
    roundtrips(&st);

    let failed = ExitUpdateStatus {
        state: ExitUpdateState::PersistPending,
        target_version: None,
        error: Some("slot bake unsupported (grub)".to_owned()),
    };
    assert_eq!(json(&failed)["state"], "persist_pending");
    roundtrips(&failed);
}

#[test]
fn legacy_register_exit_request_without_update_status_still_parses() {
    // Wire-compat: exits that pre-date the update agent omit the field.
    let legacy = serde_json::json!({
        "endpoints": [],
        "country": "SG",
        "city": "Singapore",
        "weight": 100,
    });
    let req: RegisterExitRequest = serde_json::from_value(legacy).unwrap();
    assert!(
        req.update_status.is_none(),
        "absent update_status must parse as None"
    );
}

#[test]
fn legacy_register_exit_request_without_telemetry_still_parses() {
    // Wire-compat: exits that pre-date the telemetry block omit the field.
    let legacy = serde_json::json!({
        "endpoints": [],
        "country": "SG",
        "city": "Singapore",
        "weight": 100,
    });
    let req: RegisterExitRequest = serde_json::from_value(legacy).unwrap();
    assert!(
        req.telemetry.is_none(),
        "absent telemetry must parse as None"
    );
}

#[test]
fn exit_telemetry_shape() {
    // Counters are cumulative since process start; the server derives rates
    // by delta and treats a decreasing counter as a process restart.
    let full = ExitTelemetry {
        bytes_tx_total: 10,
        bytes_rx_total: 20,
        datagrams_tx_total: 3,
        datagrams_rx_total: 4,
        clients_connected: 2,
        handshakes_total: 7,
        handshake_failures_total: 1,
        rtt_p50_ms: Some(12),
        rtt_p95_ms: Some(80),
        quic_lost_packets_total: 5,
        quic_congestion_events_total: 6,
        cpu_percent: Some(37.5),
        mem_rss_bytes: Some(52_428_800),
        load1_milli: Some(410),
        nic_tx_bytes_total: Some(1_000),
        nic_rx_bytes_total: Some(2_000),
        nic_speed_mbps: Some(1_000),
        uptime_secs: 3_600,
        drain_clients_remaining: None,
    };
    let v = json(&full);
    assert_eq!(
        v["bytes_tx_total"], 10,
        "cumulative counters are plain u64 fields"
    );
    assert_eq!(v["rtt_p50_ms"], 12);
    assert_eq!(
        v.get("drain_clients_remaining"),
        None,
        "absent optional telemetry fields are omitted from the wire"
    );
    roundtrips(&full);

    // A minimal block from a box where /proc sampling is unavailable.
    let sparse = ExitTelemetry::default();
    let v = json(&sparse);
    assert_eq!(v["bytes_tx_total"], 0);
    assert_eq!(v.get("cpu_percent"), None, "None system gauges are omitted");
    roundtrips(&sparse);
}

#[test]
fn register_exit_request_telemetry_roundtrips() {
    let req = serde_json::json!({
        "endpoints": [],
        "country": "SG",
        "city": "Singapore",
        "weight": 100,
        "telemetry": { "bytes_tx_total": 1, "bytes_rx_total": 2,
            "datagrams_tx_total": 0, "datagrams_rx_total": 0,
            "clients_connected": 1, "handshakes_total": 0,
            "handshake_failures_total": 0, "quic_lost_packets_total": 0,
            "quic_congestion_events_total": 0, "uptime_secs": 60 }
    });
    let parsed: RegisterExitRequest = serde_json::from_value(req).unwrap();
    let telemetry = parsed.telemetry.expect("telemetry block must parse");
    assert_eq!(telemetry.bytes_tx_total, 1);
    assert_eq!(telemetry.clients_connected, 1);
    assert!(telemetry.rtt_p50_ms.is_none());
}
