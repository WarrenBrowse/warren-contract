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
        voucher_secret: Some("ABCD-EFGH-JKMN-PQRS".to_owned()),
        referral_code: None,
    };
    assert_eq!(
        json(&req),
        serde_json::json!({ "pubkey_ss58": addr, "voucher_secret": "ABCD-EFGH-JKMN-PQRS" }),
        "the with-voucher wire form must stay byte-identical to the pre-optional one"
    );
    roundtrips(&req);
}

#[test]
fn register_account_request_omits_absent_voucher_secret() {
    // Auto-voucher onboarding: the beta app registers with no code and
    // the server redeems its configured campaign voucher.
    let addr = ss58::encode(&[0x11; 32]);
    let req = RegisterAccountRequest {
        pubkey_ss58: PubkeySs58::try_from(addr.clone()).unwrap(),
        voucher_secret: None,
        referral_code: None,
    };
    assert_eq!(
        json(&req),
        serde_json::json!({ "pubkey_ss58": addr }),
        "an absent voucher_secret must be omitted from the wire, not null"
    );
    roundtrips(&req);

    let parsed: RegisterAccountRequest =
        serde_json::from_value(serde_json::json!({ "pubkey_ss58": addr }))
            .expect("a body without voucher_secret must deserialize");
    assert_eq!(parsed.voucher_secret, None);
}

#[test]
fn network_info_response_shape() {
    let resp = NetworkInfoResponse {
        environment: "beta".to_owned(),
        degraded: true,
        default_rate_bps: Some(20_000_000),
        payments_enabled: false,
    };
    assert_eq!(
        json(&resp),
        serde_json::json!({
            "environment": "beta",
            "degraded": true,
            "default_rate_bps": 20_000_000u64,
            "payments_enabled": false,
        })
    );
    roundtrips(&resp);
}

#[test]
fn network_info_response_omits_absent_default_rate() {
    let resp = NetworkInfoResponse {
        environment: "production".to_owned(),
        degraded: false,
        default_rate_bps: None,
        payments_enabled: true,
    };
    assert_eq!(
        json(&resp),
        serde_json::json!({
            "environment": "production",
            "degraded": false,
            "payments_enabled": true,
        }),
        "an uncapped environment must omit default_rate_bps"
    );
    roundtrips(&resp);
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
fn register_exit_fleet_identity_components_are_optional_and_roundtrip() {
    // A heartbeat from a binary that predates the fleet-identity work must
    // decode to None on every component, so the server's sticky COALESCE
    // preserves whatever it already stored instead of blanking it.
    let legacy = serde_json::json!({
        "endpoints": [],
        "country": "DE",
        "city": "Falkenstein",
        "weight": 100,
    });
    let parsed: RegisterExitRequest = serde_json::from_value(legacy).unwrap();
    for (name, present) in [
        ("provider_code", parsed.provider_code.is_some()),
        ("provider", parsed.provider.is_some()),
        ("virt_code", parsed.virt_code.is_some()),
        ("virt", parsed.virt.is_some()),
        ("city_code", parsed.city_code.is_some()),
        ("node_index", parsed.node_index.is_some()),
    ] {
        assert!(!present, "absent {name} must parse as None");
    }

    // A reporting node carries the letters AND the plaintext: neither is
    // derivable from the other (FDCservers is `d` because `f` is FlokiNet,
    // and `fsn` is a datacenter code, not a truncation of "Falkenstein").
    let full = serde_json::json!({
        "endpoints": [],
        "country": "DE",
        "city": "Falkenstein",
        "weight": 100,
        "provider_code": "h",
        "provider": "Hetzner",
        "virt_code": "v",
        "virt": "KVM",
        "city_code": "fsn",
        "node_index": 1,
    });
    let parsed: RegisterExitRequest = serde_json::from_value(full).unwrap();
    assert_eq!(parsed.provider_code.as_deref(), Some("h"));
    assert_eq!(parsed.provider.as_deref(), Some("Hetzner"));
    assert_eq!(parsed.virt_code.as_deref(), Some("v"));
    assert_eq!(parsed.virt.as_deref(), Some("KVM"));
    assert_eq!(parsed.city_code.as_deref(), Some("fsn"));
    assert_eq!(parsed.node_index, Some(1));
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
        steal_percent: Some(0.5),
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
    // Steal is carried beside cpu_percent, never folded into it: cpu_percent
    // is derived from idle, so a node starved by its hypervisor reads as busy
    // there and only this field can tell the two apart.
    assert_eq!(v["steal_percent"], 0.5);
    assert_eq!(v["cpu_percent"], 37.5, "the two are independent gauges");
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
    assert_eq!(
        v.get("steal_percent"),
        None,
        "an exit binary predating steal_percent omits it, so the wire is unchanged for old nodes"
    );
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
    assert_eq!(
        parsed.voucher_secret.as_deref(),
        Some("ABCD-EFGH-JKMN-PQRS")
    );
}

// ---------------------------------------------------------------------------
// Subscribers feed: bandwidth-rate extensions. Old exits must keep parsing
// (they ignore the new fields); new servers must stay byte-identical to the
// legacy payload when the rate feature is unused.
// ---------------------------------------------------------------------------

#[test]
fn active_subscribers_response_legacy_payload_still_parses() {
    let addr = ss58::encode(&[0x66; 32]);
    let raw = serde_json::json!({
        "generation": 7u64,
        "now_unix_secs": 1_700_000_000u64,
        "active_pubkeys": [addr],
    });
    let parsed: ActiveSubscribersResponse =
        serde_json::from_value(raw).expect("a pre-rate payload must deserialize");
    assert_eq!(parsed.default_rate_bps, None);
    assert_eq!(parsed.rate_overrides, None);
}

#[test]
fn active_subscribers_response_without_rates_matches_legacy_bytes() {
    let addr = ss58::encode(&[0x66; 32]);
    let resp = ActiveSubscribersResponse {
        generation: 7,
        now_unix_secs: 1_700_000_000,
        active_pubkeys: vec![PubkeySs58::try_from(addr.clone()).unwrap()],
        default_rate_bps: None,
        rate_overrides: None,
    };
    assert_eq!(
        json(&resp),
        serde_json::json!({
            "generation": 7u64,
            "now_unix_secs": 1_700_000_000u64,
            "active_pubkeys": [addr],
        }),
        "unused rate fields must be absent, keeping the payload legacy-identical"
    );
    roundtrips(&resp);
}

#[test]
fn active_subscribers_response_carries_default_rate_and_overrides() {
    let addr = ss58::encode(&[0x66; 32]);
    let resp = ActiveSubscribersResponse {
        generation: 8,
        now_unix_secs: 1_700_000_000,
        active_pubkeys: vec![PubkeySs58::try_from(addr.clone()).unwrap()],
        default_rate_bps: Some(20_000_000),
        rate_overrides: Some(vec![SubscriberRateOverride {
            pubkey_ss58: PubkeySs58::try_from(addr.clone()).unwrap(),
            rate_bps: 0,
        }]),
    };
    assert_eq!(
        json(&resp),
        serde_json::json!({
            "generation": 8u64,
            "now_unix_secs": 1_700_000_000u64,
            "active_pubkeys": [addr],
            "default_rate_bps": 20_000_000u64,
            "rate_overrides": [ { "pubkey_ss58": addr, "rate_bps": 0u64 } ],
        }),
        "rate_bps 0 is the on-wire unlimited (exempt) marker"
    );
    roundtrips(&resp);
}

#[test]
fn subscribers_delta_add_without_rate_matches_legacy_bytes() {
    let addr = ss58::encode(&[0x77; 32]);
    let add = SubscriberDeltaAdd {
        pubkey_ss58: PubkeySs58::try_from(addr.clone()).unwrap(),
        expires_at: 1_700_086_400,
        rate_bps: None,
    };
    assert_eq!(
        json(&add),
        serde_json::json!({ "pubkey_ss58": addr, "expires_at": 1_700_086_400u64 }),
        "an entry on the default rate must serialize exactly as before"
    );
    roundtrips(&add);
}

#[test]
fn subscribers_delta_response_carries_default_rate_and_per_entry_override() {
    let addr = ss58::encode(&[0x77; 32]);
    let resp = SubscribersDeltaResponse {
        from_generation: 3,
        to_generation: 5,
        now_unix_secs: 1_700_000_000,
        added: vec![SubscriberDeltaAdd {
            pubkey_ss58: PubkeySs58::try_from(addr.clone()).unwrap(),
            expires_at: 1_700_086_400,
            rate_bps: Some(0),
        }],
        removed: vec![],
        default_rate_bps: Some(20_000_000),
    };
    assert_eq!(
        json(&resp),
        serde_json::json!({
            "from_generation": 3u64,
            "to_generation": 5u64,
            "now_unix_secs": 1_700_000_000u64,
            "added": [ { "pubkey_ss58": addr, "expires_at": 1_700_086_400u64, "rate_bps": 0u64 } ],
            "removed": [],
            "default_rate_bps": 20_000_000u64,
        })
    );
    roundtrips(&resp);

    // A pre-rate delta payload must keep parsing.
    let legacy = serde_json::json!({
        "from_generation": 3u64,
        "to_generation": 5u64,
        "now_unix_secs": 1_700_000_000u64,
        "added": [ { "pubkey_ss58": addr, "expires_at": 1_700_086_400u64 } ],
        "removed": [],
    });
    let parsed: SubscribersDeltaResponse =
        serde_json::from_value(legacy).expect("a pre-rate delta must deserialize");
    assert_eq!(parsed.default_rate_bps, None);
    assert_eq!(parsed.added[0].rate_bps, None);
}

// ---------------------------------------------------------------------------
// Admin: network settings.
// ---------------------------------------------------------------------------

#[test]
fn admin_network_response_shape() {
    let addr = ss58::encode(&[0x88; 32]);
    let resp = AdminNetworkResponse {
        environment: "beta".to_owned(),
        degraded: true,
        payments_enabled: false,
        default_rate_bps: Some(20_000_000),
        auto_voucher_fingerprint: Some("sha256:1a2b3c4d".to_owned()),
        rate_overrides: vec![AdminRateOverrideRow {
            pubkey_ss58: PubkeySs58::try_from(addr.clone()).unwrap(),
            rate_bps: 0,
        }],
    };
    assert_eq!(
        json(&resp),
        serde_json::json!({
            "environment": "beta",
            "degraded": true,
            "payments_enabled": false,
            "default_rate_bps": 20_000_000u64,
            "auto_voucher_fingerprint": "sha256:1a2b3c4d",
            "rate_overrides": [ { "pubkey_ss58": addr, "rate_bps": 0u64 } ],
        })
    );
    roundtrips(&resp);
}

#[test]
fn admin_network_update_request_null_clears_the_cap() {
    let parsed: AdminNetworkUpdateRequest = serde_json::from_str(r#"{}"#).unwrap();
    assert_eq!(
        parsed.default_rate_bps, None,
        "an absent default_rate_bps must parse as clear-the-cap"
    );
    let req = AdminNetworkUpdateRequest {
        default_rate_bps: Some(20_000_000),
    };
    assert_eq!(
        json(&req),
        serde_json::json!({ "default_rate_bps": 20_000_000u64 })
    );
    roundtrips(&req);
}

#[test]
fn admin_rate_limit_shape() {
    let set = AdminRateLimit {
        rate_bps: Some(5_000_000),
    };
    assert_eq!(json(&set), serde_json::json!({ "rate_bps": 5_000_000u64 }));
    roundtrips(&set);

    let cleared: AdminRateLimit = serde_json::from_str(r#"{}"#).unwrap();
    assert_eq!(
        cleared.rate_bps, None,
        "an absent rate_bps must parse as use-the-default-policy"
    );
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

// ---------------------------------------------------------------------------
// Session label hardening (warren-core doc 107 section 8.6).
// ---------------------------------------------------------------------------

#[test]
fn session_open_request_still_parses_without_the_ignored_exit_id() {
    // The server derives the lease slot from the caller's authenticated key,
    // so an exit may one day stop sending the label; the body must stay valid.
    let token_b64 = "dG9rZW4".to_owned();
    let req: SessionOpenRequest =
        serde_json::from_value(serde_json::json!({ "token_b64": token_b64 }))
            .expect("a v2 body without exit_id must deserialize");
    assert_eq!(req.exit_id, "", "an absent exit_id reads as empty");
    assert_eq!(req.token_b64.as_deref(), Some("dG9rZW4"));
}

#[test]
fn session_open_request_keeps_sending_exit_id_for_older_servers() {
    // A server that predates the hardening requires the field: the
    // serialized body must keep it even though a current server ignores it.
    let req = SessionOpenRequest {
        pubkey_ss58: None,
        device_id_hex: None,
        exit_id: "ab".repeat(32),
        max_devices: None,
        token_b64: Some("dG9rZW4".to_owned()),
    };
    assert_eq!(
        json(&req),
        serde_json::json!({ "exit_id": "ab".repeat(32), "token_b64": "dG9rZW4" }),
    );
}

// ---------------------------------------------------------------------------
// Route admission by anchor (warren-core doc 107): token directory block,
// exit heartbeat flag, and the four exit-signed session/route-* endpoints.
// ---------------------------------------------------------------------------

fn issuer_directory(route_admission: Option<RouteAdmissionInfo>) -> TokenIssuerDirectory {
    TokenIssuerDirectory {
        issuer_name: "warren".to_owned(),
        token_type: 2,
        epoch_secs: 3600,
        context_label: "warren/session-token/v1".to_owned(),
        quota_per_epoch: 3,
        prefetch_epochs: 1,
        keys: vec![TokenIssuerKey {
            epoch: 7,
            token_key_id: "11".repeat(32),
            spki_b64: "c3BraQ".to_owned(),
            not_before: 25_200,
            not_after: 28_800,
        }],
        route_admission,
    }
}

fn route_admission_info() -> RouteAdmissionInfo {
    RouteAdmissionInfo {
        version: ROUTE_ADMISSION_VERSION,
        kem_key_id: 1,
        kem_pubkey_hex: PubkeyHex::try_from("5a".repeat(32).as_str()).unwrap(),
        max_routes_per_anchor: 32,
        exit_ids_hex: vec![
            ExitId::from_bytes([0x01; 16]),
            ExitId::from_bytes([0xfe; 16]),
        ],
    }
}

fn today_directory_json() -> serde_json::Value {
    serde_json::json!({
        "issuer_name": "warren",
        "token_type": 2,
        "epoch_secs": 3600,
        "context_label": "warren/session-token/v1",
        "quota_per_epoch": 3,
        "prefetch_epochs": 1,
        "keys": [{
            "epoch": 7,
            "token_key_id": "11".repeat(32),
            "spki_b64": "c3BraQ",
            "not_before": 25_200,
            "not_after": 28_800,
        }],
    })
}

#[test]
fn token_directory_without_route_admission_is_byte_identical_to_today() {
    let dir = issuer_directory(None);
    assert_eq!(
        json(&dir),
        today_directory_json(),
        "a server with route admission off must serve exactly today's document"
    );
    let parsed: TokenIssuerDirectory = serde_json::from_value(today_directory_json()).unwrap();
    assert!(parsed.route_admission.is_none());
    roundtrips(&dir);
}

#[test]
fn token_directory_route_admission_shape() {
    let dir = issuer_directory(Some(route_admission_info()));
    let mut expected = today_directory_json();
    expected["route_admission"] = serde_json::json!({
        "version": 1,
        "kem_key_id": 1,
        "kem_pubkey_hex": "5a".repeat(32),
        "max_routes_per_anchor": 32,
        "exit_ids_hex": ["01".repeat(16), "fe".repeat(16)],
    });
    assert_eq!(json(&dir), expected);
    let back: TokenIssuerDirectory = serde_json::from_value(expected).unwrap();
    assert_eq!(back.route_admission, Some(route_admission_info()));
    roundtrips(&dir);
}

#[test]
fn route_admission_version_is_one() {
    assert_eq!(
        ROUTE_ADMISSION_VERSION, 1,
        "doc 107 freezes the first route admission block as version 1"
    );
}

#[test]
fn a_malformed_route_admission_block_withdraws_the_feature_without_failing_the_directory() {
    // The token directory is on the critical path of every main session: a
    // route admission block this build cannot read must cost the client route
    // admission (token routes take over), never its tokens.
    let malformed = [
        serde_json::json!({ "version": 1 }),
        serde_json::json!("not an object"),
        serde_json::json!({
            "version": 1, "kem_key_id": 1, "kem_pubkey_hex": "zz",
            "max_routes_per_anchor": 32, "exit_ids_hex": [],
        }),
        serde_json::json!({
            "version": 1, "kem_key_id": 1, "kem_pubkey_hex": "5a".repeat(32),
            "max_routes_per_anchor": 32, "exit_ids_hex": ["short"],
        }),
        serde_json::json!({
            "version": 2, "kem_key_id": 300, "kem_pubkey_hex": "5a".repeat(32),
            "max_routes_per_anchor": 32, "exit_ids_hex": [],
        }),
        serde_json::Value::Null,
    ];
    for block in malformed {
        let mut doc = today_directory_json();
        doc["route_admission"] = block.clone();
        let parsed: TokenIssuerDirectory = serde_json::from_value(doc)
            .unwrap_or_else(|e| panic!("directory must survive route_admission {block}: {e}"));
        assert!(
            parsed.route_admission.is_none(),
            "an unreadable block reads as absent: {block}"
        );
        assert_eq!(parsed.keys.len(), 1, "the issuer keys are intact");
    }
}

#[test]
fn route_admission_block_tolerates_a_future_field() {
    let mut doc = today_directory_json();
    doc["route_admission"] = serde_json::json!({
        "version": 1,
        "kem_key_id": 1,
        "kem_pubkey_hex": "5a".repeat(32),
        "max_routes_per_anchor": 32,
        "exit_ids_hex": ["01".repeat(16), "fe".repeat(16)],
        "a_field_from_a_later_server": true,
    });
    let parsed: TokenIssuerDirectory = serde_json::from_value(doc).unwrap();
    assert_eq!(parsed.route_admission, Some(route_admission_info()));
}

#[test]
fn register_exit_request_route_admission_flag_is_optional() {
    let legacy = serde_json::json!({
        "endpoints": [],
        "country": "FI",
        "city": "Helsinki",
        "weight": 100,
    });
    let mut req: RegisterExitRequest = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(req.route_admission, None, "an older exit omits the flag");
    let value = json(&req);
    assert!(
        value.get("route_admission").is_none(),
        "an absent flag stays off the wire: {value}"
    );

    req.route_admission = Some(true);
    let value = json(&req);
    assert_eq!(value["route_admission"], serde_json::json!(true));
    let back: RegisterExitRequest = serde_json::from_value(value).unwrap();
    assert_eq!(back.route_admission, Some(true));
    roundtrips(&back);
}

#[test]
fn sealed_to_api_blob_is_81_bytes_base64url_without_padding() {
    let mut bytes = [0u8; SEALED_TO_API_LEN];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap().wrapping_mul(37);
    }
    let blob = SealedToApiBlob::from_bytes(bytes);
    let value = json(&blob);
    let s = value.as_str().expect("a JSON string");
    assert_eq!(s.len(), 108, "81 bytes are 108 base64 chars, no padding");
    assert!(
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "url-safe alphabet: {s}"
    );
    let back: SealedToApiBlob = serde_json::from_value(value).unwrap();
    assert_eq!(back.as_bytes(), &bytes);
    assert_eq!(SEALED_TO_API_LEN, 81, "doc 107 section 6.3");
}

#[test]
fn sealed_to_api_blob_rejects_every_other_shape() {
    // 0xfb bytes encode to both url-safe characters, so the standard
    // alphabet rewrite below really differs from the accepted form.
    let good = SealedToApiBlob::from_bytes([0xfb; SEALED_TO_API_LEN]);
    let good_str = json(&good).as_str().unwrap().to_owned();
    assert!(
        good_str.contains('-') && good_str.contains('_'),
        "{good_str}"
    );
    let bad = [
        String::new(),
        good_str[..104].to_owned(),                   // 78 bytes
        format!("{good_str}AAAA"),                    // 84 bytes
        format!("{}=", &good_str[..107]),             // padding
        good_str.replace('-', "+").replace('_', "/"), // standard alphabet
        "!".repeat(108),
    ];
    for s in bad {
        let err = serde_json::from_value::<SealedToApiBlob>(serde_json::json!(s)).unwrap_err();
        assert!(
            !err.to_string().contains(&good_str[..16]),
            "the error must not echo the blob: {err}"
        );
    }
}

#[test]
fn session_route_anchor_request_shape() {
    let req = SessionRouteAnchorRequest {
        serial_hex: "0a".repeat(32),
        sealed_anchor_b64: SealedToApiBlob::from_bytes([0x33; SEALED_TO_API_LEN]),
    };
    let value = json(&req);
    assert_eq!(
        value,
        serde_json::json!({
            "serial_hex": "0a".repeat(32),
            "sealed_anchor_b64": json(&SealedToApiBlob::from_bytes([0x33; SEALED_TO_API_LEN])),
        })
    );
    roundtrips(&req);
}

#[test]
fn session_route_anchor_response_shapes() {
    let bound = SessionRouteAnchorResponse {
        status: RouteAnchorStatus::Bound,
        reason: None,
        max_routes: 32,
    };
    assert_eq!(
        json(&bound),
        serde_json::json!({ "status": "bound", "max_routes": 32 })
    );
    roundtrips(&bound);

    let refused = SessionRouteAnchorResponse {
        status: RouteAnchorStatus::Refused,
        reason: Some(RouteAnchorRefusal::NoLease),
        max_routes: 32,
    };
    assert_eq!(
        json(&refused),
        serde_json::json!({ "status": "refused", "reason": "no_lease", "max_routes": 32 })
    );
    roundtrips(&refused);
}

#[test]
fn route_anchor_refusal_wire_names_are_frozen() {
    for (reason, wire) in [
        (RouteAnchorRefusal::NoLease, "no_lease"),
        (RouteAnchorRefusal::InvalidSeal, "invalid_seal"),
        (RouteAnchorRefusal::StoreFull, "store_full"),
    ] {
        assert_eq!(json(&reason), serde_json::json!(wire));
    }
    assert_eq!(json(&RouteAnchorStatus::Bound), serde_json::json!("bound"));
    assert_eq!(
        json(&RouteAnchorStatus::Refused),
        serde_json::json!("refused")
    );
}

#[test]
fn unknown_route_anchor_status_and_reason_decode_as_unknown() {
    let resp: SessionRouteAnchorResponse = serde_json::from_value(serde_json::json!({
        "status": "a_later_status",
        "reason": "a_later_reason",
        "max_routes": 32,
    }))
    .expect("a later server's verdict must not fail the exit's decode");
    assert_eq!(resp.status, RouteAnchorStatus::Unknown);
    assert_eq!(resp.reason, Some(RouteAnchorRefusal::Unknown));
}

#[test]
fn session_route_open_request_shape() {
    let blob = SealedToApiBlob::from_bytes([0x44; SEALED_TO_API_LEN]);
    let req = SessionRouteOpenRequest {
        locator_b64: blob.clone(),
    };
    assert_eq!(
        json(&req),
        serde_json::json!({ "locator_b64": json(&blob) }),
        "the route exit names no exit: the API takes it from the caller's key"
    );
    roundtrips(&req);
}

#[test]
fn session_route_open_response_shapes() {
    let admitted = SessionRouteOpenResponse {
        admitted: true,
        route_serial_hex: Some("7e".repeat(32)),
        reason: None,
    };
    assert_eq!(
        json(&admitted),
        serde_json::json!({ "admitted": true, "route_serial_hex": "7e".repeat(32) })
    );
    roundtrips(&admitted);

    let refused = SessionRouteOpenResponse {
        admitted: false,
        route_serial_hex: None,
        reason: Some(RouteOpenRefusal::RouteLimit),
    };
    assert_eq!(
        json(&refused),
        serde_json::json!({ "admitted": false, "reason": "route_limit" })
    );
    roundtrips(&refused);
}

#[test]
fn route_open_refusal_wire_names_are_frozen() {
    for (reason, wire) in [
        (RouteOpenRefusal::Restoring, "restoring"),
        (RouteOpenRefusal::AnchorUnknown, "anchor_unknown"),
        (RouteOpenRefusal::RouteLimit, "route_limit"),
        (RouteOpenRefusal::InvalidLocator, "invalid_locator"),
    ] {
        assert_eq!(json(&reason), serde_json::json!(wire));
    }
    let later: RouteOpenRefusal = serde_json::from_value(serde_json::json!("a_later_reason"))
        .expect("an unknown reason must decode");
    assert_eq!(later, RouteOpenRefusal::Unknown);
}

#[test]
fn session_route_renew_shapes() {
    let req = SessionRouteRenewRequest {
        anchor_serials_hex: vec!["01".repeat(32)],
        route_serials_hex: vec!["02".repeat(32), "03".repeat(32)],
    };
    assert_eq!(
        json(&req),
        serde_json::json!({
            "anchor_serials_hex": ["01".repeat(32)],
            "route_serials_hex": ["02".repeat(32), "03".repeat(32)],
        })
    );
    roundtrips(&req);

    let resp = SessionRouteRenewResponse {
        unknown_anchor_serials_hex: Vec::new(),
        unknown_route_serials_hex: vec!["03".repeat(32)],
    };
    assert_eq!(
        json(&resp),
        serde_json::json!({
            "unknown_anchor_serials_hex": [],
            "unknown_route_serials_hex": ["03".repeat(32)],
        }),
        "both lists are always written, empty included"
    );
    roundtrips(&resp);
}

#[test]
fn session_route_renew_lists_default_to_empty_when_absent() {
    let req: SessionRouteRenewRequest =
        serde_json::from_value(serde_json::json!({ "route_serials_hex": ["02".repeat(32)] }))
            .unwrap();
    assert!(req.anchor_serials_hex.is_empty());
    assert_eq!(req.route_serials_hex.len(), 1);
    let resp: SessionRouteRenewResponse = serde_json::from_value(serde_json::json!({})).unwrap();
    assert!(resp.unknown_anchor_serials_hex.is_empty());
    assert!(resp.unknown_route_serials_hex.is_empty());
}

#[test]
fn session_route_close_request_shape() {
    let req = SessionRouteCloseRequest {
        route_serials_hex: vec!["04".repeat(32)],
    };
    assert_eq!(
        json(&req),
        serde_json::json!({ "route_serials_hex": ["04".repeat(32)] })
    );
    roundtrips(&req);
}

#[test]
fn route_dtos_never_print_a_serial_or_a_blob() {
    let serial = "9d".repeat(32);
    let blob = SealedToApiBlob::from_bytes([0x5c; SEALED_TO_API_LEN]);
    let blob_str = json(&blob).as_str().unwrap().to_owned();
    let rendered = [
        format!("{blob:?}"),
        format!(
            "{:?}",
            SessionRouteAnchorRequest {
                serial_hex: serial.clone(),
                sealed_anchor_b64: blob.clone(),
            }
        ),
        format!(
            "{:?}",
            SessionRouteOpenRequest {
                locator_b64: blob.clone(),
            }
        ),
        format!(
            "{:?}",
            SessionRouteOpenResponse {
                admitted: true,
                route_serial_hex: Some(serial.clone()),
                reason: None,
            }
        ),
        format!(
            "{:?}",
            SessionRouteRenewRequest {
                anchor_serials_hex: vec![serial.clone()],
                route_serials_hex: vec![serial.clone()],
            }
        ),
        format!(
            "{:?}",
            SessionRouteRenewResponse {
                unknown_anchor_serials_hex: vec![serial.clone()],
                unknown_route_serials_hex: vec![serial.clone()],
            }
        ),
        format!(
            "{:?}",
            SessionRouteCloseRequest {
                route_serials_hex: vec![serial.clone()],
            }
        ),
    ];
    for line in rendered {
        assert!(
            !line.contains(&serial[..8]) && !line.contains(&blob_str[..8]),
            "doc 107 section 8.7: no serial, prefix of a serial or blob in any log: {line}"
        );
    }
}

#[test]
fn route_serial_hex_validator_accepts_exactly_64_lowercase_hex() {
    assert!(is_valid_route_serial_hex(&"ab".repeat(32)));
    assert!(!is_valid_route_serial_hex(&"AB".repeat(32)));
    assert!(!is_valid_route_serial_hex(&"ab".repeat(31)));
    assert!(!is_valid_route_serial_hex(&"ab".repeat(33)));
    assert!(!is_valid_route_serial_hex(&"zz".repeat(32)));
}
