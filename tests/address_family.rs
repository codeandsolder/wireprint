use wireprint::{AddressFamily, Observation};

#[test]
fn legacy_capture_defaults_to_auto_family_without_changing_endpoint_evidence() {
    let raw = include_str!("fixtures/pinterest-snapshot-divergent.json");
    let mut observation: Observation = serde_json::from_str(raw).expect("legacy observation");
    assert_eq!(observation.connection_address_family, AddressFamily::Auto);
    let before = observation
        .endpoint_assessment
        .as_ref()
        .map(|x| &x.candidates);
    assert!(
        before.is_none(),
        "compact fixture only retains source evidence"
    );

    observation.connection_address_family = AddressFamily::Ipv6;
    let json = serde_json::to_value(&observation).expect("serialize selected family");
    assert_eq!(json["connection_address_family"], "ipv6");
    let restored: Observation = serde_json::from_value(json).expect("round-trip new observation");
    assert_eq!(restored.connection_address_family, AddressFamily::Ipv6);
    assert_eq!(restored.selected_endpoint, observation.selected_endpoint);
}

#[test]
fn strict_family_has_no_cross_family_fallback() {
    let addresses = [
        "192.0.2.1:443".parse().expect("IPv4"),
        "[2001:db8::1]:443".parse().expect("IPv6"),
    ];
    assert_eq!(AddressFamily::Ipv4.filter(addresses), [addresses[0]]);
    assert_eq!(AddressFamily::Ipv6.filter(addresses), [addresses[1]]);
    assert_eq!(AddressFamily::Auto.filter(addresses), addresses);
    assert!(AddressFamily::Ipv4.filter([addresses[1]]).is_empty());
    assert!(AddressFamily::Ipv6.filter([addresses[0]]).is_empty());
}
