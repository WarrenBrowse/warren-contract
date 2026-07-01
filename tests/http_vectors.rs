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
