//! Diagnostic comparison of reported Cloudflare Ray response headers.
//!
//! Origin-Cf-Ray has no public hop contract. Differences in reported Ray IDs
//! or location suffixes are not proof of another provider, hop or termination.

use crate::model::{CfRayHeaderValue, CfRayProvenance, CfRayRelation, Header};

pub const CF_RAY_PROVENANCE_VERSION: &str = "builtin-cf-ray-provenance-v1";

fn parse_value(raw: &str) -> CfRayHeaderValue {
    let value = raw.trim();
    let parsed = value.split_once('-').filter(|(id, colo)| {
        !id.is_empty()
            && id.bytes().all(|byte| byte.is_ascii_hexdigit())
            && colo.len() == 3
            && colo.bytes().all(|byte| byte.is_ascii_alphabetic())
    });
    let (ray_id, colo) = parsed.map_or((None, None), |(id, colo)| {
        (
            Some(id.to_ascii_lowercase()),
            Some(colo.to_ascii_uppercase()),
        )
    });

    CfRayHeaderValue {
        value: raw.into(),
        ray_id,
        colo,
    }
}

/// Retain distinct HTTP header values; compare only when unambiguous.
/// This is not path-element classification or an edge-provider vote.
#[must_use]
pub fn detect_cf_ray_provenance(headers: &[Header]) -> Option<CfRayProvenance> {
    let origin_cf_ray = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("origin-cf-ray"))
        .map(|header| parse_value(&header.value))
        .collect::<Vec<_>>();
    if origin_cf_ray.is_empty() {
        return None;
    }
    let cf_ray = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("cf-ray"))
        .map(|header| parse_value(&header.value))
        .collect::<Vec<_>>();

    let relation = if cf_ray.is_empty() {
        CfRayRelation::MissingResponseRay
    } else if origin_cf_ray.len() != 1 || cf_ray.len() != 1 {
        CfRayRelation::MultipleValues
    } else {
        let origin = &origin_cf_ray[0];
        let response = &cf_ray[0];
        match (
            origin.ray_id.as_deref(),
            origin.colo.as_deref(),
            response.ray_id.as_deref(),
            response.colo.as_deref(),
        ) {
            (Some(origin_id), Some(origin_colo), Some(response_id), Some(response_colo)) => {
                match (origin_id == response_id, origin_colo == response_colo) {
                    (true, true) => CfRayRelation::Identical,
                    (true, false) => CfRayRelation::SameIdDifferentColo,
                    (false, true) => CfRayRelation::DifferentIdSameColo,
                    (false, false) => CfRayRelation::DifferentIdDifferentColo,
                }
            }
            _ => CfRayRelation::Unparseable,
        }
    };

    Some(CfRayProvenance {
        classifier: CF_RAY_PROVENANCE_VERSION.into(),
        origin_cf_ray,
        cf_ray,
        relation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, value: &str) -> Header {
        Header {
            name: name.into(),
            value: value.into(),
        }
    }

    fn relation(origin: &str, response: &str) -> CfRayRelation {
        detect_cf_ray_provenance(&[header("ORIGIN-cf-Ray", origin), header("Cf-RAY", response)])
            .unwrap()
            .relation
    }

    #[test]
    fn four_comparable_relationships() {
        assert_eq!(
            relation("a4f12fba2b1e0258-WAW", "A4F12FBA2B1E0258-waw"),
            CfRayRelation::Identical
        );
        assert_eq!(
            relation("a4f19422ddb5bfe4-FRA", "a4f19422ddb5bfe4-WAW"),
            CfRayRelation::SameIdDifferentColo
        );
        assert_eq!(
            relation("a4cc274b2ba58de0-WAW", "a4f113a11f27c3d8-WAW"),
            CfRayRelation::DifferentIdSameColo
        );
        assert_eq!(
            relation("a46f918fcf090d25-FRA", "a470db0ecd08526b-PRG"),
            CfRayRelation::DifferentIdDifferentColo
        );
    }

    #[test]
    fn retain_raw_values_and_omit_without_origin_reported_header() {
        assert!(detect_cf_ray_provenance(&[header("cf-ray", "a4f12fba2b1e0258-WAW")]).is_none());
        let result = detect_cf_ray_provenance(&[
            header("Origin-Cf-Ray", "  A4F12FBA2B1E0258-waw  "),
            header("Cf-Ray", "a4f12fba2b1e0258-WAW"),
        ])
        .unwrap();
        assert_eq!(result.classifier, CF_RAY_PROVENANCE_VERSION);
        assert_eq!(result.relation, CfRayRelation::Identical);
        assert_eq!(result.origin_cf_ray[0].value, "  A4F12FBA2B1E0258-waw  ");
        assert_eq!(
            result.origin_cf_ray[0].ray_id.as_deref(),
            Some("a4f12fba2b1e0258")
        );
        assert_eq!(result.origin_cf_ray[0].colo.as_deref(), Some("WAW"));
    }

    #[test]
    fn missing_and_duplicate_values_are_not_guessed() {
        let missing =
            detect_cf_ray_provenance(&[header("Origin-Cf-Ray", "a1fb2b14c9e983f6-DUB")]).unwrap();
        assert_eq!(missing.relation, CfRayRelation::MissingResponseRay);
        assert!(missing.cf_ray.is_empty());
        let duplicate = detect_cf_ray_provenance(&[
            header("Origin-Cf-Ray", "a1fb2b14c9e983f6-DUB"),
            header("Origin-Cf-Ray", "a1fb2b14c9e983f6-FRA"),
            header("Cf-Ray", "a1fb2b14c9e983f6-PRG"),
        ])
        .unwrap();
        assert_eq!(duplicate.relation, CfRayRelation::MultipleValues);
        assert_eq!(duplicate.origin_cf_ray.len(), 2);
        assert_eq!(duplicate.cf_ray.len(), 1);
    }

    #[test]
    fn malformed_values_are_preserved_without_fabricated_components() {
        for invalid in [
            "",
            "bogus",
            "zzz-WAW",
            "a4cc274b2ba58de0-WA",
            "a4cc274b2ba58de0-WAW, a4cc274b2ba58de0-PRG",
            "a4cc274b2ba58de0-WAW-extra",
        ] {
            let result = detect_cf_ray_provenance(&[
                header("Origin-Cf-Ray", invalid),
                header("Cf-Ray", "a4f113a11f27c3d8-WAW"),
            ])
            .unwrap();
            assert_eq!(result.relation, CfRayRelation::Unparseable);
            assert_eq!(result.origin_cf_ray[0].value, invalid);
            assert!(result.origin_cf_ray[0].ray_id.is_none());
            assert!(result.origin_cf_ray[0].colo.is_none());
        }
    }

    #[test]
    fn nonstandard_origin_ray_alone_never_identifies_a_cloudflare_edge() {
        let elements =
            crate::path::detect_path_elements(&[header("Origin-Cf-Ray", "a4f19422ddb5bfe4-FRA")]);
        assert!(!elements.iter().any(|el| el.product == "cloudflare"));
    }
}
