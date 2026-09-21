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
// Crypto payment rails (doc 91). Settlement lives in warren-core (BTCPay
// webhook, monerod/wallet-rpc and the polkadot/solana RPC watchers); what
// this crate owns is the wire surface every rail shares: the payment-method
// tokens, the pending-voucher metadata, the wpid support lookup, the
// node-health probe and the crypto refund row. A drift in any of these
// breaks the backend and the admin/SDK consumers at once.
// ---------------------------------------------------------------------------

#[test]
fn payment_method_wire_tokens_cover_every_rail() {
    // The lowercase token IS the wire format: a rename or a case change
    // is a breaking compat regression on both sides.
    let all = [
        (PaymentMethod::Lightning, "lightning"),
        (PaymentMethod::Monero, "monero"),
        (PaymentMethod::Card, "card"),
        (PaymentMethod::Cash, "cash"),
        (PaymentMethod::Bitcoin, "bitcoin"),
        (PaymentMethod::Manual, "manual"),
        (PaymentMethod::AppStore, "appstore"),
        (PaymentMethod::GooglePlay, "googleplay"),
        (PaymentMethod::Paypal, "paypal"),
        (PaymentMethod::Polkadot, "polkadot"),
        (PaymentMethod::Solana, "solana"),
    ];
    for (method, wire) in all {
        assert_eq!(json(&method), serde_json::json!(wire));
        assert_eq!(method.as_wire(), wire);
        assert_eq!(PaymentMethod::from_wire(wire).unwrap(), method);
        assert_eq!(method.to_string(), wire);
        roundtrips(&method);
    }
}

#[test]
fn payment_method_rejects_an_unknown_token_redacted() {
    // The rejected value is untrusted (could be a mispasted secret), so
    // the error carries only the 8-char redacted prefix.
    let err = PaymentMethod::from_wire("a-very-long-mispasted-secret-value").unwrap_err();
    assert_eq!(err.to_string(), "unknown payment method: a-very-l…");
}

#[test]
fn currency_wire_tokens_are_uppercase() {
    // UPPERCASE is part of the wire contract; pricing maps the token to
    // its smallest unit (cent, satoshi, piconero, planck, lamport).
    let all = [
        (Currency::EUR, "EUR"),
        (Currency::USD, "USD"),
        (Currency::BTC, "BTC"),
        (Currency::XMR, "XMR"),
        (Currency::SAT, "SAT"),
        (Currency::RON, "RON"),
        (Currency::CAD, "CAD"),
        (Currency::GBP, "GBP"),
        (Currency::CHF, "CHF"),
        (Currency::DOT, "DOT"),
        (Currency::SOL, "SOL"),
    ];
    for (currency, wire) in all {
        assert_eq!(json(&currency), serde_json::json!(wire));
        assert_eq!(currency.as_wire(), wire);
        roundtrips(&currency);
    }
}

#[test]
fn admin_pending_voucher_row_carries_the_crypto_rail_metadata() {
    // One row per rail the store records: the PSP-minted (btcpay) rows
    // settle in SAT, the self-hosted watchers in their native unit.
    let row = AdminPendingVoucherRow {
        pending_id: "pv_lightning_01".to_owned(),
        expires_at: 1_700_086_400,
        provider: Some("btcpay".to_owned()),
        currency: Some("SAT".to_owned()),
        amount_units: Some(150_000),
    };
    assert_eq!(
        json(&row),
        serde_json::json!({
            "pending_id": "pv_lightning_01",
            "expires_at": 1_700_086_400u64,
            "provider": "btcpay",
            "currency": "SAT",
            "amount_units": 150_000u64,
        })
    );
    roundtrips(&row);

    for (provider, currency, units) in [
        ("monero", "XMR", 423_000_000_000u64),
        ("solana", "SOL", 5_000_000_000u64),
        ("polkadot", "DOT", 750_000_000_000u64),
    ] {
        let row = AdminPendingVoucherRow {
            pending_id: format!("pv_{provider}_01"),
            expires_at: 1_700_086_400,
            provider: Some(provider.to_owned()),
            currency: Some(currency.to_owned()),
            amount_units: Some(units),
        };
        let v = json(&row);
        assert_eq!(v["provider"], provider);
        assert_eq!(v["currency"], currency);
        assert_eq!(v["amount_units"], units);
        roundtrips(&row);
    }
}

#[test]
fn admin_pending_voucher_row_pre_metadata_fields_parse_and_serialize_as_null() {
    // Rows recorded before the provider/currency metadata existed omit
    // the fields; `serde(default)` keeps them parseable as None. But the
    // attrs are parse-side only: this server still writes explicit nulls,
    // so consumers may rely on the keys being present.
    let legacy = serde_json::json!({
        "pending_id": "pv_legacy_01",
        "expires_at": 1_700_086_400u64,
    });
    let parsed: AdminPendingVoucherRow =
        serde_json::from_value(legacy).expect("a pre-metadata row must deserialize");
    assert_eq!(parsed.provider, None);
    assert_eq!(parsed.currency, None);
    assert_eq!(parsed.amount_units, None);
    assert_eq!(
        json(&parsed),
        serde_json::json!({
            "pending_id": "pv_legacy_01",
            "expires_at": 1_700_086_400u64,
            "provider": null,
            "currency": null,
            "amount_units": null,
        }),
        "None rail metadata serializes as explicit nulls, not omitted keys"
    );
}

#[test]
fn admin_pending_vouchers_response_shape() {
    let resp = AdminPendingVouchersResponse {
        pending: vec![AdminPendingVoucherRow {
            pending_id: "pv_monero_01".to_owned(),
            expires_at: 1_700_086_400,
            provider: Some("monero".to_owned()),
            currency: Some("XMR".to_owned()),
            amount_units: Some(423_000_000_000),
        }],
        total: 1,
    };
    let v = json(&resp);
    assert_eq!(v["total"], 1);
    assert_eq!(v["pending"].as_array().unwrap().len(), 1);
    roundtrips(&resp);
}

#[test]
fn admin_wpid_lookup_body_and_binding_row_shape() {
    // POST body (not a query param) so the pull credential never lands
    // in proxy access logs.
    let body = AdminWpidLookupBody {
        wpid: "wp_7f3a9c21".to_owned(),
    };
    assert_eq!(json(&body), serde_json::json!({ "wpid": "wp_7f3a9c21" }));
    roundtrips(&body);

    // A self-hosted rail binds the exact native amount quoted at invoice
    // creation (piconero, lamport, planck); btcpay leaves it null because
    // it is priced at settlement.
    let monero_binding = AdminWpidInvoiceBindingRow {
        rail: "monero".to_owned(),
        expires_at_unix: Some(1_700_086_400),
        locked_amount_native: Some(423_000_000_000),
        granted_duration_secs: Some(2_592_000),
    };
    assert_eq!(
        json(&monero_binding),
        serde_json::json!({
            "rail": "monero",
            "expires_at_unix": 1_700_086_400u64,
            "locked_amount_native": 423_000_000_000u64,
            "granted_duration_secs": 2_592_000u64,
        })
    );
    roundtrips(&monero_binding);

    let btcpay_binding = AdminWpidInvoiceBindingRow {
        rail: "btcpay".to_owned(),
        expires_at_unix: None,
        locked_amount_native: None,
        granted_duration_secs: None,
    };
    assert_eq!(
        json(&btcpay_binding),
        serde_json::json!({
            "rail": "btcpay",
            "expires_at_unix": null,
            "locked_amount_native": null,
            "granted_duration_secs": null,
        }),
        "absent binding fields serialize as nulls, not omitted keys"
    );
    roundtrips(&btcpay_binding);
}

#[test]
fn admin_wpid_lookup_response_covers_the_whole_lifecycle() {
    // 1. Invoice open, nothing settled yet.
    let open = AdminWpidLookupResponse {
        bindings: vec![AdminWpidInvoiceBindingRow {
            rail: "solana".to_owned(),
            expires_at_unix: Some(1_700_086_400),
            locked_amount_native: Some(5_000_000_000),
            granted_duration_secs: Some(2_592_000),
        }],
        settled: false,
        voucher_pull_pending: false,
        voucher_redeemed: None,
    };
    let v = json(&open);
    assert_eq!(v["settled"], false);
    assert_eq!(v["voucher_pull_pending"], false);
    assert_eq!(v["voucher_redeemed"], serde_json::Value::Null);
    assert_eq!(v["bindings"].as_array().unwrap().len(), 1);
    roundtrips(&open);

    // 2. Paid, voucher minted and queued for pull (not yet retrieved).
    let settled = AdminWpidLookupResponse {
        bindings: vec![],
        settled: true,
        voucher_pull_pending: true,
        voucher_redeemed: Some(false),
    };
    assert_eq!(
        json(&settled),
        serde_json::json!({
            "bindings": [],
            "settled": true,
            "voucher_pull_pending": true,
            "voucher_redeemed": false,
        })
    );
    roundtrips(&settled);

    // 3. Pulled and redeemed: the lifecycle's terminal state.
    let redeemed = AdminWpidLookupResponse {
        bindings: vec![],
        settled: true,
        voucher_pull_pending: false,
        voucher_redeemed: Some(true),
    };
    assert_eq!(json(&redeemed)["voucher_redeemed"], true);
    roundtrips(&redeemed);
}

#[test]
fn admin_payment_nodes_health_covers_every_watched_rail() {
    // One row per payment dependency warren-api probes. `node`/`status`
    // are free-form tokens so a new rail needs no contract bump; these
    // pin the five the crypto stack watches today.
    let resp = AdminPaymentNodesHealthResponse {
        nodes: vec![
            AdminPaymentNodeHealthRow {
                node: "btcpay".to_owned(),
                status: "healthy".to_owned(),
                detail: "invoice webhook ok".to_owned(),
                checked_at_unix: Some(1_700_000_000),
            },
            AdminPaymentNodeHealthRow {
                node: "monerod".to_owned(),
                status: "healthy".to_owned(),
                detail: "synced".to_owned(),
                checked_at_unix: Some(1_700_000_000),
            },
            AdminPaymentNodeHealthRow {
                node: "monero_wallet_rpc".to_owned(),
                status: "degraded".to_owned(),
                detail: "refresh lagging".to_owned(),
                checked_at_unix: Some(1_700_000_000),
            },
            AdminPaymentNodeHealthRow {
                node: "polkadot_rpc".to_owned(),
                status: "down".to_owned(),
                detail: "unreachable".to_owned(),
                checked_at_unix: None,
            },
            AdminPaymentNodeHealthRow {
                node: "solana_rpc".to_owned(),
                status: "unknown".to_owned(),
                detail: "never probed".to_owned(),
                checked_at_unix: None,
            },
        ],
    };
    let v = json(&resp);
    let nodes = v["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 5);
    assert_eq!(nodes[3]["checked_at_unix"], serde_json::Value::Null);
    roundtrips(&resp);
}

#[test]
fn admin_voucher_row_records_the_rail_and_legacy_rows_parse() {
    // A voucher minted from a settled crypto payment records which rail
    // paid for it; the hash-only secret stays off the wire either way.
    let row = AdminVoucherRow {
        secret_hash_hex: "deadbeef".to_owned(),
        duration_secs: 2_592_000,
        payment_method: PaymentMethod::Monero,
        created_at: 1_700_000_000,
        redeemed_at: None,
        is_redeemed: false,
        redeemed_by_pubkey_ss58: None,
        cancelled_at: None,
        max_redemptions: Some(1),
        valid_until: None,
        redemptions_count: 0,
    };
    let v = json(&row);
    assert_eq!(v["payment_method"], "monero");
    assert_eq!(v["max_redemptions"], 1);
    roundtrips(&row);

    // A row from a server that pre-dates the cancel/campaign fields
    // still parses, with single-use as the assumed redemption cap.
    let legacy = serde_json::json!({
        "secret_hash_hex": "deadbeef",
        "duration_secs": 2_592_000u64,
        "payment_method": "lightning",
        "created_at": 1_700_000_000u64,
        "redeemed_at": null,
        "is_redeemed": false,
        "redeemed_by_pubkey_ss58": null,
    });
    let parsed: AdminVoucherRow =
        serde_json::from_value(legacy).expect("a pre-campaign row must deserialize");
    assert_eq!(parsed.payment_method, PaymentMethod::Lightning);
    assert_eq!(parsed.cancelled_at, None);
    assert_eq!(parsed.max_redemptions, Some(1));
    assert_eq!(parsed.redemptions_count, 0);
}

#[test]
fn admin_withdrawal_row_omits_crypto_fields_on_the_stripe_rail() {
    // Card rows keep the historical shape: every crypto-refund field is
    // skip_serializing_if None, so none of them appear.
    let stripe_row = AdminWithdrawalRow {
        id: "wd_01".to_owned(),
        payment_ref: "pi_3PqExample".to_owned(),
        status: "pending".to_owned(),
        created_at: 1_700_000_000,
        processed_at: None,
        ..Default::default()
    };
    let v = json(&stripe_row);
    for field in [
        "rail",
        "refund_address",
        "eur_amount_minor",
        "native_amount_display",
        "treasury_hint",
    ] {
        assert!(
            v.get(field).is_none(),
            "{field} must be omitted on a Stripe row"
        );
    }
    assert_eq!(v["processed_at"], serde_json::Value::Null);
    roundtrips(&stripe_row);
}

#[test]
fn admin_withdrawal_row_carries_the_crypto_refund_fields() {
    // A self-service crypto refund (doc 91 section 6.4): the rail, the
    // consumer-supplied payout address and the native amount display.
    // Monero's treasury lives in the external merchant wallet, so
    // treasury_hint stays omitted; Solana's resolves cheaply on-chain.
    let monero_row = AdminWithdrawalRow {
        id: "wd_02".to_owned(),
        payment_ref: "wp_7f3a9c21".to_owned(),
        status: "pending".to_owned(),
        created_at: 1_700_000_000,
        processed_at: None,
        rail: Some("monero".to_owned()),
        refund_address: Some("44syntheticmonerorefundaddress000000000000000".to_owned()),
        eur_amount_minor: Some(1500),
        native_amount_display: Some("0.423000000000 XMR".to_owned()),
        treasury_hint: None,
    };
    let v = json(&monero_row);
    assert_eq!(v["rail"], "monero");
    assert_eq!(
        v["refund_address"],
        "44syntheticmonerorefundaddress000000000000000"
    );
    assert_eq!(v["native_amount_display"], "0.423000000000 XMR");
    assert_eq!(v["eur_amount_minor"], 1500);
    assert!(
        v.get("treasury_hint").is_none(),
        "a rail with an external treasury omits the hint"
    );
    roundtrips(&monero_row);

    let solana_row = AdminWithdrawalRow {
        rail: Some("solana".to_owned()),
        treasury_hint: Some("So1anaTreasury111111111111111111111111111".to_owned()),
        ..monero_row
    };
    assert_eq!(
        json(&solana_row)["treasury_hint"],
        "So1anaTreasury111111111111111111111111111"
    );
}

#[test]
fn admin_withdrawal_refund_body_defaults_and_crypto_guard() {
    // Both flags default to false so a legacy/absent body can never
    // silently satisfy the crypto sent-confirmed guard.
    let parsed: AdminWithdrawalRefundBody = serde_json::from_str(r#"{}"#).unwrap();
    assert!(!parsed.override_window);
    assert!(!parsed.sent_confirmed);

    // `override` has no skip attr (always on the wire); `sent_confirmed`
    // is skipped while false.
    assert_eq!(
        json(&AdminWithdrawalRefundBody::default()),
        serde_json::json!({ "override": false })
    );
    let confirmed = AdminWithdrawalRefundBody {
        override_window: false,
        sent_confirmed: true,
    };
    assert_eq!(
        json(&confirmed),
        serde_json::json!({ "override": false, "sent_confirmed": true })
    );
    roundtrips(&confirmed);
}

#[test]
fn withdrawal_request_and_ack_shape() {
    // The no-auth website-facing body carries only the payment
    // reference; identity stays with the PSP.
    let req = WithdrawalRequestBody {
        payment_ref: "pi_3PqExample".to_owned(),
    };
    assert_eq!(
        json(&req),
        serde_json::json!({ "payment_ref": "pi_3PqExample" })
    );
    roundtrips(&req);

    let ack = WithdrawalAck {
        reference: "wda_01".to_owned(),
    };
    assert_eq!(json(&ack), serde_json::json!({ "reference": "wda_01" }));
    roundtrips(&ack);
}

#[test]
fn mobile_payment_dtos_shape_and_secret_redaction() {
    let init_apple = InitApplePaymentResponse {
        app_account_token: "3f5b2c1e-9a8d-4e7f-b1c2-3d4e5f6a7b8c".to_owned(),
    };
    assert_eq!(
        json(&init_apple),
        serde_json::json!({
            "app_account_token": "3f5b2c1e-9a8d-4e7f-b1c2-3d4e5f6a7b8c"
        })
    );
    roundtrips(&init_apple);

    // The JWS receipt and the Play purchase token are credential-grade:
    // their Debug impls must never print them.
    let check_apple = CheckApplePaymentRequest {
        jws_transaction: "eyJhbGciOiJFUzI1NiJ9.payload.signature".to_owned(),
    };
    assert_eq!(
        json(&check_apple),
        serde_json::json!({
            "jws_transaction": "eyJhbGciOiJFUzI1NiJ9.payload.signature"
        })
    );
    let dbg = format!("{check_apple:?}");
    assert!(
        !dbg.contains("eyJhbGci"),
        "Debug must redact the JWS: {dbg}"
    );
    assert!(dbg.contains("<redacted>"));

    let init_google = InitGooglePaymentResponse {
        obfuscated_account_id: "obf_9c8b7a".to_owned(),
    };
    assert_eq!(
        json(&init_google),
        serde_json::json!({ "obfuscated_account_id": "obf_9c8b7a" })
    );
    roundtrips(&init_google);

    let ack_google = AcknowledgeGooglePaymentRequest {
        purchase_token: "kgdpfjep.secret-token".to_owned(),
    };
    let dbg = format!("{ack_google:?}");
    assert!(
        !dbg.contains("kgdpfjep"),
        "Debug must redact the purchase token: {dbg}"
    );
    assert!(dbg.contains("<redacted>"));

    let resp = MobilePaymentResponse {
        expires_at: 1_702_678_400,
    };
    assert_eq!(
        json(&resp),
        serde_json::json!({ "expires_at": 1_702_678_400u64 })
    );
    roundtrips(&resp);
}
