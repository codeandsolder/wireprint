use wireprint::h3::{
    H3FingerprintMatchKind, H3Setting, classify_h3_quic, is_h3_grease_setting,
    is_quic_transport_parameter_grease, parse_quic_transport_parameter_wire, provider_signals,
};

fn varint(value: u64) -> Vec<u8> {
    if value < (1 << 6) {
        vec![value as u8]
    } else if value < (1 << 14) {
        let raw = (value | (0b01 << 14)) as u16;
        raw.to_be_bytes().to_vec()
    } else if value < (1 << 30) {
        let raw = (value | (0b10 << 30)) as u32;
        raw.to_be_bytes().to_vec()
    } else {
        let raw = value | (0b11 << 62);
        raw.to_be_bytes().to_vec()
    }
}

fn tp(id: u64, raw: &[u8]) -> Vec<u8> {
    let mut out = varint(id);
    out.extend(varint(raw.len() as u64));
    out.extend(raw);
    out
}

fn tp_varint(id: u64, value: u64) -> Vec<u8> {
    tp(id, &varint(value))
}

#[test]
fn raw_transport_parser_preserves_order_and_exact_bytes() {
    let mut raw = tp_varint(3, 1472);
    raw.extend(tp(12, &[]));
    raw.extend(tp(15, &[1, 2, 3, 4, 5, 6, 7, 8]));
    let parsed = parse_quic_transport_parameter_wire(&raw).unwrap();
    assert_eq!(
        parsed.iter().map(|p| p.id).collect::<Vec<_>>(),
        vec![3, 12, 15]
    );
    assert_eq!(parsed[0].raw_hex, "45c0");
    assert_eq!(parsed[1].length, 0);
    assert_eq!(parsed[2].raw_hex, "0102030405060708");
}

#[test]
fn parser_accepts_all_quic_varint_widths() {
    let mut raw = Vec::new();
    for (id, value) in [
        (1, 63),
        (3, 64),
        (4, 16_383),
        (5, 16_384),
        (6, (1 << 30) + 5),
    ] {
        raw.extend(tp_varint(id, value));
    }
    let parsed = classify_h3_quic(1, "h3", vec![], &raw).unwrap();
    assert_eq!(parsed.transport_parameters.max_idle_timeout, Some(63));
    assert_eq!(parsed.transport_parameters.max_udp_payload_size, Some(64));
    assert_eq!(parsed.transport_parameters.initial_max_data, Some(16_383));
    assert_eq!(
        parsed
            .transport_parameters
            .initial_max_stream_data_bidi_local,
        Some(16_384)
    );
    assert_eq!(
        parsed
            .transport_parameters
            .initial_max_stream_data_bidi_remote,
        Some((1 << 30) + 5)
    );
}

#[test]
fn grease_rules_match_the_protocol_reservations() {
    assert!(is_h3_grease_setting(0x21));
    assert!(is_h3_grease_setting(0x40));
    assert!(!is_h3_grease_setting(0x22));
    assert!(is_quic_transport_parameter_grease(27));
    assert!(is_quic_transport_parameter_grease(58));
    assert!(!is_quic_transport_parameter_grease(28));
}

#[test]
fn raw_structure_keeps_cid_reset_version_and_min_ack_delay() {
    let mut raw = tp(15, &[0; 8]);
    raw.extend(tp(2, &[0; 16]));
    raw.extend(tp(
        17,
        &[
            0, 0, 0, 1, 0, 0, 0, 1, 0x0a, 0x1a, 0x2a, 0x3a, 0xff, 0x00, 0x00, 0x1d,
        ],
    ));
    raw.extend(tp(0xff04_de1b, &varint(25_000)));
    let observed = classify_h3_quic(1, "h3", vec![], &raw).unwrap();
    let structure = observed.transport_structure;
    assert_eq!(structure.initial_source_connection_id_length, Some(8));
    assert!(structure.stateless_reset_token_present);
    assert_eq!(structure.min_ack_delay, Some(25_000));
    let version = structure.version_information.unwrap();
    assert_eq!(version.chosen_version, 1);
    assert_eq!(version.available_versions, vec![1, 0xff00_001d]);
    assert_eq!(version.reserved_version_count, 1);
}

#[test]
fn cloudfront_exact_signature_originates_provider_without_using_tp_order() {
    let mut raw = Vec::new();
    for (id, value) in [
        (14, 3),
        (9, 5),
        (8, 128),
        (7, 5_242_880),
        (6, 5_242_880),
        (5, 5_242_880),
        (4, 10_485_760),
        (1, 300_000),
    ] {
        raw.extend(tp_varint(id, value));
    }
    raw.extend(tp(15, &[0; 20]));
    let observed = classify_h3_quic(1, "h3", vec![], &raw).unwrap();
    let exact = observed.exact_match.as_ref().unwrap();
    assert_eq!(exact.name, "aws-cloudfront-h3-current");
    assert_eq!(exact.kind, H3FingerprintMatchKind::Exact);
    assert_eq!(provider_signals(&observed)[0].provider, "aws-cloudfront");
}

#[test]
fn nginx_structural_family_is_implementation_only() {
    let mut raw = Vec::new();
    for (id, value) in [
        (4, (128 + 3) * 65_536),
        (5, 65_536),
        (6, 65_536),
        (7, 65_536),
        (8, 128),
        (9, 3),
    ] {
        raw.extend(tp_varint(id, value));
    }
    let observed = classify_h3_quic(
        1,
        "h3",
        vec![
            H3Setting { id: 1, value: 4096 },
            H3Setting { id: 7, value: 128 },
        ],
        &raw,
    )
    .unwrap();
    assert!(
        observed
            .family_matches
            .iter()
            .any(|m| m.name == "nginx-h3-source-relationship")
    );
    assert!(provider_signals(&observed).is_empty());
}

#[test]
fn h3_setting_grease_is_normalized_for_catalog_matching() {
    let mut raw = Vec::new();
    for (id, value) in [
        (1, 180_000),
        (3, 1350),
        (4, 10_000_000),
        (5, 1_000_000),
        (6, 1_000_000),
        (7, 1_000_000),
        (8, 100),
        (9, 3),
        (10, 3),
        (11, 25),
    ] {
        raw.extend(tp_varint(id, value));
    }
    raw.extend(tp(12, &[]));
    raw.extend(tp(15, &[0; 20]));
    let observed = classify_h3_quic(
        1,
        "h3",
        vec![
            H3Setting {
                id: 6,
                value: 131_072,
            },
            H3Setting {
                id: 0x21,
                value: 99,
            },
        ],
        &raw,
    )
    .unwrap();
    assert_eq!(
        observed.exact_match.as_ref().unwrap().name,
        "cloudflare-h3-marketing-config"
    );
    assert_eq!(provider_signals(&observed)[0].provider, "cloudflare");
}
