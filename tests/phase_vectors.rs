//! Golden vectors for the shared connection-phase reduction. The fixture is
//! replayed verbatim by the sibling-language SDKs (the TypeScript reducer in
//! warren-sdk-ts replays the same file), so the reduction can never drift
//! between the Rust contract and a client surface without a test going red on
//! one side.

use warren_contract::phase::{ConnectionPhase, EgressEvidence, TunnelStatus, reduce_phase};

#[derive(serde::Deserialize)]
struct Vector {
    status: TunnelStatus,
    egress: EgressEvidence,
    phase: ConnectionPhase,
}

fn vectors() -> Vec<Vector> {
    let raw = include_str!("fixtures/phase-reduction.json");
    serde_json::from_str(raw).expect("phase-reduction.json must parse")
}

#[test]
fn fixture_replays_against_the_reduction() {
    for (i, v) in vectors().iter().enumerate() {
        assert_eq!(
            reduce_phase(v.status, v.egress),
            v.phase,
            "vector {i} diverged: {:?} + {:?}",
            v.status,
            v.egress
        );
    }
}

#[test]
fn fixture_is_the_exhaustive_input_domain() {
    // 9 status values (7 variants, the two boolean-carrying ones twice) times
    // the 4 egress-evidence combinations. A pruned fixture would let a
    // sibling-language replay silently skip part of the domain.
    let vectors = vectors();
    assert_eq!(vectors.len(), 36, "fixture must cover the whole domain");
    let mut seen = std::collections::HashSet::new();
    for v in &vectors {
        assert!(
            seen.insert((format!("{:?}", v.status), format!("{:?}", v.egress))),
            "duplicate vector for {:?} + {:?}",
            v.status,
            v.egress
        );
    }
}

#[test]
fn status_and_evidence_serialize_to_the_cross_language_shape() {
    // Pins the JSON spelling the TypeScript union uses ("state" tag, camelCase
    // fields): a rename here breaks the shared fixture on purpose.
    assert_eq!(
        serde_json::to_value(TunnelStatus::Disconnected { locked_down: true }).unwrap(),
        serde_json::json!({ "state": "disconnected", "lockedDown": true })
    );
    assert_eq!(
        serde_json::to_value(TunnelStatus::Error {
            blocking_error: false
        })
        .unwrap(),
        serde_json::json!({ "state": "error", "blockingError": false })
    );
    assert_eq!(
        serde_json::to_value(TunnelStatus::Connected).unwrap(),
        serde_json::json!({ "state": "connected" })
    );
    assert_eq!(
        serde_json::to_value(EgressEvidence {
            host_offline: true,
            exit_egress_dead: false,
        })
        .unwrap(),
        serde_json::json!({ "hostOffline": true, "exitEgressDead": false })
    );
}
