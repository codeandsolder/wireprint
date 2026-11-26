use wireprint::{Header, Observation, passive::classify_observation};

#[test]
fn passive_classification_reuses_real_evidence_without_new_requests() -> anyhow::Result<()> {
    let mut observation: Observation =
        serde_json::from_str(include_str!("fixtures/pinterest-snapshot-matched.json"))?;
    let dns_before = serde_json::to_value(&observation.dns)?;
    let peer_before = observation.remote.clone();
    observation.status = Some(403);
    observation.response_headers = vec![
        Header {
            name: "cf-mitigated".into(),
            value: "challenge".into(),
        },
        Header {
            name: "content-type".into(),
            value: "text/html".into(),
        },
    ];
    let body = b"<html>challenge</html>";
    classify_observation(&mut observation, Some(body));
    assert_eq!(
        observation.outcome.as_ref().map(|outcome| &outcome.kind),
        Some(&wireprint::OutcomeKind::Challenge)
    );
    assert_eq!(observation.body_captured_bytes, Some(body.len()));
    assert!(observation.body_prefix_sha256.is_some());
    assert!(observation.body_template_sha256.is_some());
    assert!(observation.body_prefix.is_none());
    assert!(observation.endpoint_assessment.is_some());
    assert_eq!(observation.remote, peer_before);
    assert_eq!(serde_json::to_value(&observation.dns)?, dns_before);
    let first = serde_json::to_value(&observation)?;
    classify_observation(&mut observation, Some(body));
    assert_eq!(serde_json::to_value(&observation)?, first);
    Ok(())
}
