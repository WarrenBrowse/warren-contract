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
        reason: None,
    };
    assert_eq!(
        json(&resp),
        serde_json::json!({ "admitted": true, "max": 5, "current": 1 }),
        "reason must be omitted when None (pre-v2 exits pin this shape)"
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
fn legacy_register_exit_request_without_update_status_or_telemetry_still_parses() {
    // Wire-compat: exits that pre-date the update agent and the telemetry
    // block omit both fields.
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
        relay_legs: None,
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

// ---------------------------------------------------------------------------
// Doc-54 fleet-rollout admin DTOs.
// ---------------------------------------------------------------------------

#[test]
fn admin_release_row_and_response_shape() {
    let hash = "9f".repeat(32);
    let row = AdminReleaseRow {
        version: "v0.7.0-3-gabc1234".to_owned(),
        channel: "stable".to_owned(),
        binary_sha256_hex: hash.clone(),
        binary_size: 42_000_000,
        generation: 7,
        expires_at: 1_700_086_400,
        created_at: 1_700_000_000,
        binary_uploaded: true,
    };
    assert_eq!(
        json(&row),
        serde_json::json!({
            "version": "v0.7.0-3-gabc1234",
            "channel": "stable",
            "binary_sha256_hex": hash,
            "binary_size": 42_000_000u64,
            "generation": 7u64,
            "expires_at": 1_700_086_400u64,
            "created_at": 1_700_000_000u64,
            "binary_uploaded": true,
        })
    );
    roundtrips(&row);

    let resp = AdminReleasesResponse {
        releases: vec![row],
    };
    assert_eq!(json(&resp)["releases"].as_array().unwrap().len(), 1);
    roundtrips(&resp);
}

#[test]
fn admin_create_release_request_embeds_the_signed_manifest() {
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
    let req = AdminCreateReleaseRequest {
        manifest: manifest.clone(),
    };
    let v = json(&req);
    assert_eq!(v["manifest"]["release_version"], "v0.7.0-3-gabc1234");
    assert_eq!(v["manifest"]["generation"], 7);
    assert_eq!(
        v.as_object().unwrap().len(),
        1,
        "manifest is the sole top-level field: {v}"
    );
    roundtrips(&req);
}

#[test]
fn admin_create_rollout_request_omits_absent_canary() {
    let req = AdminCreateRolloutRequest {
        version: "v0.7.0-3-gabc1234".to_owned(),
        canary_pubkey_ss58: None,
    };
    assert_eq!(
        json(&req),
        serde_json::json!({ "version": "v0.7.0-3-gabc1234" }),
        "canary_pubkey_ss58 must be omitted when None"
    );
    roundtrips(&req);
}

#[test]
fn admin_create_rollout_request_carries_canary_when_present() {
    let addr = ss58::encode(&[0x33; 32]);
    let req = AdminCreateRolloutRequest {
        version: "v0.7.0-3-gabc1234".to_owned(),
        canary_pubkey_ss58: Some(PubkeySs58::try_from(addr.clone()).unwrap()),
    };
    assert_eq!(
        json(&req),
        serde_json::json!({ "version": "v0.7.0-3-gabc1234", "canary_pubkey_ss58": addr })
    );
    roundtrips(&req);
}

#[test]
fn admin_rollout_response_shape() {
    let addr = ss58::encode(&[0x44; 32]);
    let node = AdminRolloutNodeRow {
        pubkey_ss58: PubkeySs58::try_from(addr.clone()).unwrap(),
        is_canary: true,
        state: "verifying".to_owned(),
        previous_version: Some("v0.6.9".to_owned()),
        error: None,
        updated_at: 1_700_000_100,
    };
    assert_eq!(
        json(&node),
        serde_json::json!({
            "pubkey_ss58": addr,
            "is_canary": true,
            "state": "verifying",
            "previous_version": "v0.6.9",
            "updated_at": 1_700_000_100u64,
        }),
        "error must be omitted when None"
    );
    roundtrips(&node);

    let resp = AdminRolloutResponse {
        id: 12,
        version: "v0.7.0-3-gabc1234".to_owned(),
        status: "active".to_owned(),
        created_at: 1_700_000_000,
        nodes: vec![node],
    };
    let v = json(&resp);
    assert_eq!(v["id"], 12);
    assert_eq!(v["status"], "active");
    assert_eq!(v["nodes"].as_array().unwrap().len(), 1);
    roundtrips(&resp);
}

#[test]
fn admin_rollout_audit_response_shape() {
    let row = AdminRolloutAuditRow {
        at: 1_700_000_000,
        actor: "controller".to_owned(),
        action: "swap_applied".to_owned(),
        detail_json: r#"{"node":"wbAAA"}"#.to_owned(),
    };
    assert_eq!(
        json(&row),
        serde_json::json!({
            "at": 1_700_000_000u64,
            "actor": "controller",
            "action": "swap_applied",
            "detail_json": r#"{"node":"wbAAA"}"#,
        })
    );
    roundtrips(&row);

    let resp = AdminRolloutAuditResponse { rows: vec![row] };
    assert_eq!(json(&resp)["rows"].as_array().unwrap().len(), 1);
    roundtrips(&resp);
}

// ---------------------------------------------------------------------------
// Campaign voucher DTOs.
// ---------------------------------------------------------------------------

#[test]
fn admin_create_voucher_request_omits_false_unlimited_and_absent_optionals() {
    let req = AdminCreateVoucherRequest {
        duration_secs: 2_592_000,
        payment_method: PaymentMethod::Manual,
        max_redemptions: None,
        unlimited_redemptions: false,
        valid_until_unix_secs: None,
    };
    assert_eq!(
        json(&req),
        serde_json::json!({ "duration_secs": 2_592_000u64, "payment_method": "manual" }),
        "false unlimited_redemptions and absent max_redemptions/valid_until must be omitted"
    );
    roundtrips(&req);
}

#[test]
fn admin_create_voucher_request_carries_true_unlimited_and_deadline() {
    let req = AdminCreateVoucherRequest {
        duration_secs: 2_592_000,
        payment_method: PaymentMethod::Manual,
        max_redemptions: None,
        unlimited_redemptions: true,
        valid_until_unix_secs: Some(1_700_086_400),
    };
    assert_eq!(
        json(&req),
        serde_json::json!({
            "duration_secs": 2_592_000u64,
            "payment_method": "manual",
            "unlimited_redemptions": true,
            "valid_until_unix_secs": 1_700_086_400u64,
        }),
        "true unlimited_redemptions must be present on the wire"
    );
    roundtrips(&req);
}

#[test]
fn admin_create_voucher_response_defaults_max_redemptions_to_single_use() {
    // A server response that pre-dates campaign vouchers omits the field.
    let raw = r#"{"voucher_secret":"ABCD-EFGH-JKMN-PQRS","secret_hash_hex":"deadbeef","duration_secs":3600}"#;
    let parsed: AdminCreateVoucherResponse = serde_json::from_str(raw).unwrap();
    assert_eq!(
        parsed.max_redemptions,
        Some(1),
        "absent max_redemptions must default to single-use"
    );
    assert!(parsed.valid_until_unix_secs.is_none());
}

#[test]
fn admin_create_voucher_response_full_shape() {
    let resp = AdminCreateVoucherResponse {
        voucher_secret: "ABCD-EFGH-JKMN-PQRS".to_owned(),
        secret_hash_hex: "deadbeef".to_owned(),
        duration_secs: 3600,
        max_redemptions: None,
        valid_until_unix_secs: Some(1_700_086_400),
    };
    assert_eq!(
        json(&resp),
        serde_json::json!({
            "voucher_secret": "ABCD-EFGH-JKMN-PQRS",
            "secret_hash_hex": "deadbeef",
            "duration_secs": 3600u64,
            "max_redemptions": null,
            "valid_until_unix_secs": 1_700_086_400u64,
        })
    );
    roundtrips(&resp);
}

// ---------------------------------------------------------------------------
// Unknown-field tolerance: the tolerant-reader posture is part of the wire
// contract. If someone adds `deny_unknown_fields` to one of these DTOs,
// these tests must break.
// ---------------------------------------------------------------------------

#[test]
fn register_account_request_tolerates_unknown_field() {
    let addr = ss58::encode(&[0x55; 32]);
    let raw = serde_json::json!({
        "pubkey_ss58": addr,
        "voucher_secret": "ABCD-EFGH-JKMN-PQRS",
        "unexpected_future_field": "surprise",
    });
    let parsed: RegisterAccountRequest = serde_json::from_value(raw)
        .expect("an unknown field must not break deserialization (tolerant reader)");
    assert_eq!(parsed.voucher_secret, "ABCD-EFGH-JKMN-PQRS");
}

#[test]
fn subscription_response_tolerates_unknown_field() {
    let raw = serde_json::json!({
        "expires_at": 1_700_000_000u64,
        "unexpected_future_field": "surprise",
    });
    let parsed: SubscriptionResponse = serde_json::from_value(raw)
        .expect("an unknown field must not break deserialization (tolerant reader)");
    assert_eq!(parsed.expires_at, 1_700_000_000);
}

// ---------------------------------------------------------------------------
// Session-cap open/close.
// ---------------------------------------------------------------------------

#[test]
fn session_open_request_omits_absent_max_devices() {
    let addr = ss58::encode(&[0x66; 32]);
    let device_id_hex = "a".repeat(32);
    let req = SessionOpenRequest {
        pubkey_ss58: Some(PubkeySs58::try_from(addr.clone()).unwrap()),
        device_id_hex: Some(device_id_hex.clone()),
        exit_id: "exit-fr-1".to_owned(),
        max_devices: None,
        token_b64: None,
    };
    assert_eq!(
        json(&req),
        serde_json::json!({
            "pubkey_ss58": addr,
            "device_id_hex": device_id_hex,
            "exit_id": "exit-fr-1",
        }),
        "max_devices and the v2 token field must be omitted when None"
    );
    roundtrips(&req);
}

#[test]
fn session_open_request_carries_max_devices_when_present() {
    let addr = ss58::encode(&[0x77; 32]);
    let device_id_hex = "b".repeat(32);
    let req = SessionOpenRequest {
        pubkey_ss58: Some(PubkeySs58::try_from(addr.clone()).unwrap()),
        device_id_hex: Some(device_id_hex.clone()),
        exit_id: "exit-fr-1".to_owned(),
        max_devices: Some(3),
        token_b64: None,
    };
    assert_eq!(
        json(&req),
        serde_json::json!({
            "pubkey_ss58": addr,
            "device_id_hex": device_id_hex,
            "exit_id": "exit-fr-1",
            "max_devices": 3u32,
        })
    );
    roundtrips(&req);
}
