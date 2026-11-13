//! Where the authority DID of a Trust Check or a Trust Recorder entry came from.
//!
//! The DID is stored as plain text, so once an Authority is deleted its DID looks like one
//! typed in directly. [`AuthoritySource`] records that it was picked from the Authorities
//! register, so a Trust Check whose Authority is gone fails with `AUTHORITY_NOT_FOUND` and a
//! Trust Recorder entry stops writing, instead of both carrying on under a DID nothing vouches
//! for.

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::authorities::{AuthorityStore, types::Authority};
use crate::config::agent_surface::{AgentSurface, TransitPoint};
use crate::config::types::{TrustRecorderConfig, TrustRecorderEntry};
use crate::issuers::{IssuerStore, types::Issuer};
use crate::tenancy::can_reference;

use super::trust_check_element::TrustCheckElement;

/// The register a literal authority DID was found in. A DID in neither has no source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoritySource {
    /// The Authorities register. The Authority must still exist.
    Authority,
    /// The Issuers register.
    Issuer,
}

fn is_template(value: &str) -> bool {
    value.contains("{{")
}

fn requires_authority(
    did: &str,
    source: Option<AuthoritySource>,
) -> bool {
    source == Some(AuthoritySource::Authority) && !is_template(did)
}

/// Where on a surface a Trust Check runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustCheckPlacement {
    AccessPoint,
    Target,
    TransitPoint,
}

/// A Trust Check or Trust Recorder entry that sets an authority DID, as the delete
/// conflict of an Authority lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "element", rename_all = "snake_case")]
pub enum AuthorityUse {
    TrustCheck {
        id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        placement: Option<TrustCheckPlacement>,
        #[serde(skip_serializing_if = "Option::is_none")]
        transit_point: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        variant: Option<String>,
    },
    TrustRecorder {
        trust_registry_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        variant: Option<String>,
    },
}

impl AuthorityUse {
    fn trust_check(
        element: &TrustCheckElement,
        placement: Option<TrustCheckPlacement>,
        transit_point: Option<&str>,
        variant: Option<&str>,
    ) -> Self {
        Self::TrustCheck {
            id: element.id.clone(),
            name: element.name.clone(),
            placement,
            transit_point: transit_point.map(str::to_string),
            variant: variant.map(str::to_string),
        }
    }

    fn trust_recorder(
        entry: &TrustRecorderEntry,
        variant: Option<&str>,
    ) -> Self {
        Self::TrustRecorder {
            trust_registry_id: entry
                .trust_registry_id
                .clone(),
            variant: variant.map(str::to_string),
        }
    }

    fn label(&self) -> String {
        match self {
            Self::TrustCheck { id, .. } => format!("Trust Check '{id}'"),
            Self::TrustRecorder { trust_registry_id, .. } => {
                format!("Trust Recorder entry for trust registry '{trust_registry_id}'")
            }
        }
    }

    fn remedy(&self) -> &'static str {
        match self {
            Self::TrustCheck { .. } => "the Trust Check",
            Self::TrustRecorder { .. } => "the entry",
        }
    }
}

/// An authority DID set on a record, with the register it came from and where it is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityReference {
    pub did: String,
    pub source: Option<AuthoritySource>,
    pub used_by: AuthorityUse,
    /// The field that records `source`: `authority_source`, or `authority_sources` for a DID
    /// of `query.authority_ids`.
    pub source_field: &'static str,
}

type Visit<'v> = dyn FnMut(&str, &mut Option<AuthoritySource>, AuthorityUse, &'static str) + 'v;

/// Calls `visit` with every authority DID of `surface`, on its base and in each variant's
/// overrides, its source, and where it is set.
fn visit_surface(
    surface: &mut AgentSurface,
    visit: &mut Visit<'_>,
) {
    visit_legs(
        visit,
        None,
        Some(
            &mut surface
                .access_point
                .trust_check_list,
        ),
        Some(
            &mut surface
                .target
                .trust_check_list,
        ),
        surface
            .transit
            .as_mut()
            .map(|transit| transit.points.as_mut_slice()),
        surface
            .access_point
            .trust_recorder
            .as_mut(),
    );
    for variant in &mut surface.variants {
        let overrides = &mut variant.overrides;
        let (access_point, trust_recorder) = match overrides
            .access_point
            .as_mut()
        {
            Some(access_point) => (
                access_point
                    .trust_check_list
                    .as_deref_mut(),
                access_point
                    .trust_recorder
                    .as_mut(),
            ),
            None => (None, None),
        };
        visit_legs(
            visit,
            Some(&variant.alias),
            access_point,
            overrides
                .target
                .as_mut()
                .and_then(|target| {
                    target
                        .trust_check_list
                        .as_deref_mut()
                }),
            overrides
                .transit
                .as_mut()
                .and_then(|transit| transit.points.as_deref_mut()),
            trust_recorder,
        );
    }
}

fn visit_legs(
    visit: &mut Visit<'_>,
    variant: Option<&str>,
    access_point: Option<&mut [TrustCheckElement]>,
    target: Option<&mut [TrustCheckElement]>,
    transit_points: Option<&mut [TransitPoint]>,
    trust_recorder: Option<&mut TrustRecorderConfig>,
) {
    let legs = [(TrustCheckPlacement::AccessPoint, access_point), (TrustCheckPlacement::Target, target)];
    for (placement, elements) in legs {
        for element in elements.unwrap_or_default() {
            let used_by = AuthorityUse::trust_check(element, Some(placement), None, variant);
            visit_trust_check(element, used_by, visit);
        }
    }
    for point in transit_points.unwrap_or_default() {
        for element in &mut point.trust_check_list {
            let used_by = AuthorityUse::trust_check(
                element,
                Some(TrustCheckPlacement::TransitPoint),
                Some(&point.alias),
                variant,
            );
            visit_trust_check(element, used_by, visit);
        }
    }
    for entry in trust_recorder
        .map(|recorder| {
            recorder
                .entries
                .as_mut_slice()
        })
        .unwrap_or_default()
    {
        let used_by = AuthorityUse::trust_recorder(entry, variant);
        visit(&entry.authority_did, &mut entry.authority_source, used_by, "authority_source");
    }
}

/// Calls `visit` with the authority DID of `element` and its `authority_source`, or with each
/// DID of `query.authority_ids` and its entry in `authority_sources`, in list order. Entries
/// for DIDs the element does not list are dropped, and so is `authority_source` on a list.
fn visit_trust_check(
    element: &mut TrustCheckElement,
    used_by: AuthorityUse,
    visit: &mut Visit<'_>,
) {
    let Some(authorities) = &element.query.authority_ids else {
        element
            .authority_sources
            .clear();
        visit(&element.query.authority_id, &mut element.authority_source, used_by, "authority_source");
        return;
    };
    element.authority_source = None;
    let mut sources = BTreeMap::new();
    for did in authorities {
        let mut source = element
            .authority_sources
            .get(did)
            .copied();
        visit(did, &mut source, used_by.clone(), "authority_sources");
        if let Some(source) = source {
            sources.insert(did.clone(), source);
        }
    }
    element.authority_sources = sources;
}

/// Every authority DID a surface sets, on its base and in each variant's overrides.
pub fn surface_references(surface: &AgentSurface) -> Vec<AuthorityReference> {
    let mut surface = surface.clone();
    let mut references = Vec::new();
    visit_surface(&mut surface, &mut |did, source, used_by, source_field| {
        references.push(AuthorityReference {
            did: did.to_string(),
            source: *source,
            used_by,
            source_field,
        });
    });
    references
}

/// Every authority DID an STS client's Trust Checks set.
pub fn trust_check_references(elements: &[TrustCheckElement]) -> Vec<AuthorityReference> {
    let mut references = Vec::new();
    for element in elements {
        let used_by = AuthorityUse::trust_check(element, None, None, None);
        visit_trust_check(&mut element.clone(), used_by, &mut |did, source, used_by, source_field| {
            references.push(AuthorityReference {
                did: did.to_string(),
                source: *source,
                used_by,
                source_field,
            });
        });
    }
    references
}

/// The Authorities and Issuers an authority DID is classified against.
#[derive(Debug, Default)]
pub struct AuthorityRegisters {
    authorities: Vec<Authority>,
    issuers: Vec<Issuer>,
}

impl AuthorityRegisters {
    /// Reads both registers. Without an Issuer store no DID is classified as an Issuer's.
    pub async fn load(
        authorities: &dyn AuthorityStore,
        issuers: Option<&dyn IssuerStore>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            authorities: authorities.list_all().await?,
            issuers: match issuers {
                Some(store) => store.list_all().await?,
                None => Vec::new(),
            },
        })
    }

    fn authority(
        &self,
        did: &str,
        tenant_id: Option<&str>,
    ) -> Option<&Authority> {
        self.authorities
            .iter()
            .find(|authority| authority.did == did && can_reference(tenant_id, authority.tenant_id.as_deref()))
    }

    /// Sets the source of a literal DID: `authority` when it already is one, when `kept`
    /// holds it (the stored record had it as an Authority) or when an Authority a record of
    /// `tenant_id` may use has it; else `issuer` when such an Issuer has it; else none. A
    /// link to an Authority is never dropped, so a register read in part, or a client sending
    /// another source, cannot turn a deleted Authority into a plain DID. Returns whether the
    /// source changed.
    fn classify(
        &self,
        did: &str,
        source: &mut Option<AuthoritySource>,
        tenant_id: Option<&str>,
        kept: &HashSet<String>,
    ) -> bool {
        if is_template(did) {
            return false;
        }
        let classified = if *source == Some(AuthoritySource::Authority)
            || kept.contains(did)
            || self
                .authority(did, tenant_id)
                .is_some()
        {
            Some(AuthoritySource::Authority)
        } else if self
            .issuers
            .iter()
            .any(|issuer| issuer.did == did && can_reference(tenant_id, issuer.tenant_id.as_deref()))
        {
            Some(AuthoritySource::Issuer)
        } else {
            None
        };
        let changed = *source != classified;
        *source = classified;
        changed
    }

    /// Classifies every literal authority DID of `surface` (see [`Self::classify`]); `stored`
    /// is the surface as stored, if any. Returns whether any source changed.
    pub fn classify_surface(
        &self,
        surface: &mut AgentSurface,
        stored: Option<&AgentSurface>,
    ) -> bool {
        let kept = stored
            .map(|stored| authority_dids(&surface_references(stored)))
            .unwrap_or_default();
        let tenant_id = surface.tenant_id.clone();
        let mut changed = false;
        visit_surface(surface, &mut |did, source, _, _| {
            changed |= self.classify(did, source, tenant_id.as_deref(), &kept);
        });
        changed
    }

    /// As [`Self::classify_surface`], for an STS client's Trust Checks.
    pub fn classify_trust_checks(
        &self,
        elements: &mut [TrustCheckElement],
        tenant_id: Option<&str>,
        stored: Option<&[TrustCheckElement]>,
    ) -> bool {
        let kept = stored
            .map(|stored| authority_dids(&trust_check_references(stored)))
            .unwrap_or_default();
        let mut changed = false;
        for element in elements {
            let used_by = AuthorityUse::trust_check(element, None, None, None);
            visit_trust_check(element, used_by, &mut |did, source, _, _| {
                changed |= self.classify(did, source, tenant_id, &kept);
            });
        }
        changed
    }

    /// Refuses references a save may not store: a source on a template, or an Authority that
    /// does not exist or that a record of `tenant_id` may not use. Both cases of the second
    /// answer alike, so the refusal never says another tenant has the DID.
    pub fn check(
        &self,
        references: &[AuthorityReference],
        tenant_id: Option<&str>,
    ) -> Result<(), String> {
        for reference in references {
            if reference.source.is_some() && is_template(&reference.did) {
                return Err(format!(
                    "{}: {} cannot be set on a template; remove it or use a DID",
                    reference.used_by.label(),
                    reference.source_field
                ));
            }
            if requires_authority(&reference.did, reference.source)
                && self
                    .authority(&reference.did, tenant_id)
                    .is_none()
            {
                return Err(format!(
                    "{} uses Authority {}, which does not exist or belongs to another tenant. Pick another \
                     Authority or remove {}",
                    reference.used_by.label(),
                    reference.did,
                    reference.used_by.remedy()
                ));
            }
        }
        Ok(())
    }
}

/// The literal DIDs of `references` found in neither register, each once.
fn unlinked_dids(references: &[AuthorityReference]) -> Vec<&str> {
    let mut dids: Vec<&str> = references
        .iter()
        .filter(|reference| {
            reference.source.is_none()
                && !is_template(&reference.did)
                && !reference
                    .did
                    .trim()
                    .is_empty()
        })
        .map(|reference| reference.did.as_str())
        .collect();
    dids.sort_unstable();
    dids.dedup();
    dids
}

/// Warns about the literal DIDs `record` names that are in neither register. One that named an
/// Authority deleted before its link was recorded is indistinguishable from a DID typed in, so
/// its Trust Check keeps querying the registry and its Trust Recorder entry keeps writing.
pub fn warn_unlinked(
    record: &str,
    references: &[AuthorityReference],
) {
    let dids = unlinked_dids(references);
    if !dids.is_empty() {
        warn!(
            record,
            dids = ?dids,
            "Trust Checks or Trust Recorder entries name DIDs in neither the Authorities nor the Issuers register; \
             one that named an Authority deleted earlier is not checked against it, so point it at an Authority \
             or remove it"
        );
    }
}

fn authority_dids(references: &[AuthorityReference]) -> HashSet<String> {
    references
        .iter()
        .filter(|reference| requires_authority(&reference.did, reference.source))
        .map(|reference| reference.did.clone())
        .collect()
}

/// The DIDs picked from the Authorities register whose Authority no longer exists, read once
/// for a run of Trust Checks or a Trust Recorder write. A store that is missing or cannot be
/// read finds no Authority, so every such reference fails rather than runs unchecked. Whether
/// the record's tenant may use the Authority is checked when it is saved.
#[derive(Debug, Default)]
pub struct MissingAuthorities<'a>(HashSet<&'a str>);

impl<'a> MissingAuthorities<'a> {
    pub async fn find(
        references: impl IntoIterator<Item = (&'a str, Option<AuthoritySource>)>,
        store: Option<&dyn AuthorityStore>,
    ) -> Self {
        let required: HashSet<&str> = references
            .into_iter()
            .filter(|(did, source)| requires_authority(did, *source))
            .map(|(did, _)| did)
            .collect();
        if required.is_empty() {
            return Self(required);
        }
        let existing = existing_authority_dids(store).await;
        Self(
            required
                .into_iter()
                .filter(|did| !existing.contains(*did))
                .collect(),
        )
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether a Trust Check depends on an Authority that no longer exists.
    pub fn fails_check(
        &self,
        element: &TrustCheckElement,
    ) -> bool {
        self.fails(&element.query.authority_id, element.authority_source)
    }

    /// Whether a Trust Recorder entry depends on an Authority that no longer exists.
    pub fn fails_entry(
        &self,
        entry: &TrustRecorderEntry,
    ) -> bool {
        self.fails(&entry.authority_did, entry.authority_source)
    }

    fn fails(
        &self,
        did: &str,
        source: Option<AuthoritySource>,
    ) -> bool {
        requires_authority(did, source) && self.0.contains(did)
    }
}

async fn existing_authority_dids(store: Option<&dyn AuthorityStore>) -> HashSet<String> {
    let Some(store) = store else {
        warn!("The Authority store is not configured, so no Trust Check or Trust Recorder Authority can be found");
        return HashSet::new();
    };
    match store.list_all().await {
        Ok(authorities) => authorities
            .into_iter()
            .map(|authority| authority.did)
            .collect(),
        Err(error) => {
            warn!(%error, "Failed to read the Authority store; treating every Authority as not found");
            HashSet::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ACME: &str = "did:web:acme.example";
    const BILLING: &str = "did:web:gateway:issuers:billing";
    const TYPED: &str = "did:web:typed.example";

    fn authority(
        did: &str,
        tenant_id: Option<&str>,
    ) -> Authority {
        let mut authority = Authority::new(format!("id-{did}"), "Acme".to_string(), did.to_string(), None, None);
        authority.tenant_id = tenant_id.map(str::to_string);
        authority
    }

    fn issuer(did: &str) -> Issuer {
        Issuer::new(
            format!("id-{did}"),
            "Billing".to_string(),
            did.to_string(),
            serde_json::Value::Null,
            serde_json::Value::Null,
        )
    }

    fn registers(authorities: Vec<Authority>) -> AuthorityRegisters {
        AuthorityRegisters {
            authorities,
            issuers: vec![issuer(BILLING)],
        }
    }

    fn check(
        id: &str,
        did: &str,
        source: Option<&str>,
    ) -> serde_json::Value {
        let mut element = json!({
            "id": id, "trust_registry_id": "tr-1", "query_type": "recognition",
            "query": {"authority_id": did, "entity_id": "{{ input.agent.did }}"}
        });
        if let Some(source) = source {
            element["authority_source"] = json!(source);
        }
        element
    }

    fn recorder(did: &str) -> serde_json::Value {
        json!({"entries": [{"trust_registry_id": "tr-rec", "issuer_did": BILLING, "authority_did": did}]})
    }

    fn surface(
        access_point_checks: Vec<serde_json::Value>,
        recorder_did: &str,
    ) -> AgentSurface {
        serde_json::from_value(json!({
            "surface_id": "s", "name": "S",
            "access_point": {
                "listen_address": "0.0.0.0:8443", "route": "/s", "protocol": "a2a",
                "trust_check_list": access_point_checks,
                "trust_recorder": recorder(recorder_did)
            },
            "target": {"endpoint": "a2a-proxy://agent", "trust_check_list": [check("target", ACME, None)]},
            "transit": {"points": [{
                "id": "tp-id", "alias": "partner", "target_endpoint": "https://partner.example.com", "protocol": "a2a",
                "trust_check_list": [check("transit", ACME, None)]
            }]},
            "variants": [{
                "id": "staging-id", "alias": "staging", "name": "Staging",
                "overrides": {
                    "access_point": {"trust_check_list": [check("variant-caller", TYPED, None)], "trust_recorder": recorder(ACME)},
                    "target": {"trust_check_list": [check("variant-target", ACME, None)]},
                    "transit": {"points": [{
                        "id": "tp-variant", "alias": "partner-staging", "target_endpoint": "https://staging.example.com",
                        "protocol": "a2a", "trust_check_list": [check("variant-transit", ACME, None)]
                    }]}
                }
            }]
        }))
        .unwrap()
    }

    fn element(value: serde_json::Value) -> TrustCheckElement {
        serde_json::from_value(value).unwrap()
    }

    fn source_of(
        surface: &AgentSurface,
        id: &str,
    ) -> Option<AuthoritySource> {
        surface_references(surface)
            .into_iter()
            .find(|reference| matches!(&reference.used_by, AuthorityUse::TrustCheck { id: found, .. } if found == id))
            .unwrap_or_else(|| panic!("no Trust Check {id}"))
            .source
    }

    #[test]
    fn surface_references_list_every_leg_variant_and_recorder_entry() {
        let references = surface_references(&surface(vec![check("caller", ACME, None)], ACME));
        let used_by: Vec<serde_json::Value> = references
            .iter()
            .map(|reference| serde_json::to_value(&reference.used_by).unwrap())
            .collect();
        assert_eq!(
            used_by,
            vec![
                json!({"element": "trust_check", "id": "caller", "placement": "access_point"}),
                json!({"element": "trust_check", "id": "target", "placement": "target"}),
                json!({"element": "trust_check", "id": "transit", "placement": "transit_point", "transit_point": "partner"}),
                json!({"element": "trust_recorder", "trust_registry_id": "tr-rec"}),
                json!({"element": "trust_check", "id": "variant-caller", "placement": "access_point", "variant": "staging"}),
                json!({"element": "trust_check", "id": "variant-target", "placement": "target", "variant": "staging"}),
                json!({
                    "element": "trust_check", "id": "variant-transit", "placement": "transit_point",
                    "transit_point": "partner-staging", "variant": "staging"
                }),
                json!({"element": "trust_recorder", "trust_registry_id": "tr-rec", "variant": "staging"}),
            ]
        );
    }

    #[test]
    fn classify_links_every_authority_did_of_every_leg_variant_and_entry() {
        let mut surface = surface(vec![check("caller", ACME, None)], ACME);

        assert!(registers(vec![authority(ACME, None)]).classify_surface(&mut surface, None));

        let sources: Vec<(AuthorityUse, Option<AuthoritySource>)> = surface_references(&surface)
            .into_iter()
            .map(|reference| (reference.used_by, reference.source))
            .collect();
        for (used_by, source) in &sources {
            let expected = match used_by {
                AuthorityUse::TrustCheck { id, .. } if id == "variant-caller" => None,
                _ => Some(AuthoritySource::Authority),
            };
            assert_eq!(*source, expected, "{used_by:?}");
        }
        assert_eq!(sources.len(), 8);
    }

    #[test]
    fn classify_finds_issuers_and_leaves_templates_and_unknown_dids_without_a_source() {
        let mut surface = surface(
            vec![
                check("issuer", BILLING, None),
                check("typed", TYPED, None),
                check("template", "{{ input.agent.authority_did }}", None),
            ],
            "{{ surface.issuer_did }}",
        );

        registers(Vec::new()).classify_surface(&mut surface, None);

        assert_eq!(source_of(&surface, "issuer"), Some(AuthoritySource::Issuer));
        assert_eq!(source_of(&surface, "typed"), None);
        assert_eq!(source_of(&surface, "template"), None);
        assert_eq!(source_of(&surface, "target"), None, "ACME is in no register here");
    }

    #[test]
    fn classify_overrides_a_client_source_with_the_register_it_finds() {
        let mut surface =
            surface(vec![check("relabelled", ACME, Some("issuer")), check("stale", TYPED, Some("issuer"))], BILLING);

        registers(vec![authority(ACME, None)]).classify_surface(&mut surface, None);

        assert_eq!(source_of(&surface, "relabelled"), Some(AuthoritySource::Authority));
        assert_eq!(source_of(&surface, "stale"), None);
    }

    #[test]
    fn classify_never_drops_a_link_to_an_authority() {
        let registers = registers(Vec::new());
        let mut stored_link = surface(vec![check("caller", TYPED, Some("authority"))], BILLING);
        registers.classify_surface(&mut stored_link, None);
        assert_eq!(source_of(&stored_link, "caller"), Some(AuthoritySource::Authority));

        let mut dropped = surface(vec![check("caller", TYPED, None)], BILLING);
        registers.classify_surface(&mut dropped, Some(&stored_link));
        assert_eq!(source_of(&dropped, "caller"), Some(AuthoritySource::Authority));

        let mut relabelled = surface(vec![check("caller", TYPED, Some("issuer"))], BILLING);
        registers.classify_surface(&mut relabelled, Some(&stored_link));
        assert_eq!(source_of(&relabelled, "caller"), Some(AuthoritySource::Authority));
    }

    #[test]
    fn classify_leaves_a_classified_surface_unchanged() {
        let mut surface = surface(vec![check("caller", ACME, None)], BILLING);
        let registers = registers(vec![authority(ACME, None)]);
        assert!(registers.classify_surface(&mut surface, None));

        let before = surface_references(&surface);
        assert!(!registers.classify_surface(&mut surface, None));
        assert_eq!(surface_references(&surface), before);
    }

    #[test]
    fn classify_treats_another_tenants_authority_as_an_unknown_did() {
        let mut surface = surface(vec![check("caller", ACME, None)], BILLING);
        surface.tenant_id = Some("tenant-a".to_string());

        registers(vec![authority(ACME, Some("tenant-b"))]).classify_surface(&mut surface, None);

        assert_eq!(source_of(&surface, "caller"), None);
    }

    #[test]
    fn check_accepts_an_existing_authority_and_unlinked_dids() {
        let mut surface = surface(vec![check("caller", ACME, None), check("typed", TYPED, None)], BILLING);
        let registers = registers(vec![authority(ACME, None)]);
        registers.classify_surface(&mut surface, None);

        assert_eq!(registers.check(&surface_references(&surface), None), Ok(()));
    }

    #[test]
    fn check_refuses_a_link_to_an_authority_that_is_gone() {
        let mut saved = surface(vec![check("caller", TYPED, None)], BILLING);
        let stored = surface(vec![check("caller", TYPED, Some("authority"))], BILLING);
        let registers = registers(Vec::new());
        registers.classify_surface(&mut saved, Some(&stored));

        assert_eq!(
            registers.check(&surface_references(&saved), None),
            Err(format!(
                "Trust Check 'caller' uses Authority {TYPED}, which does not exist or belongs to another tenant. Pick \
                 another Authority or remove the Trust Check"
            ))
        );
    }

    #[test]
    fn check_refuses_an_authority_another_tenant_owns_as_it_refuses_a_missing_one() {
        let references = trust_check_references(&[element(check("caller", ACME, Some("authority")))]);
        let other_tenants = registers(vec![authority(ACME, Some("tenant-b"))]);

        let refusal = other_tenants
            .check(&references, Some("tenant-a"))
            .unwrap_err();
        assert_eq!(
            Err(refusal),
            registers(Vec::new()).check(&references, Some("tenant-a")),
            "another tenant's Authority is refused exactly as a missing one"
        );
        assert_eq!(other_tenants.check(&references, Some("tenant-b")), Ok(()));
    }

    #[test]
    fn check_refuses_a_source_on_a_template() {
        let surface = surface(vec![check("caller", "{{ input.agent.authority_did }}", Some("issuer"))], BILLING);

        assert_eq!(
            registers(Vec::new()).check(&surface_references(&surface), None),
            Err("Trust Check 'caller': authority_source cannot be set on a template; remove it or use a DID"
                .to_string())
        );
    }

    #[test]
    fn check_names_a_recorder_entry_whose_authority_is_gone() {
        let mut recording: AgentSurface = serde_json::from_value(json!({
            "surface_id": "s", "name": "S",
            "access_point": {"listen_address": "0.0.0.0:8443", "route": "/s", "protocol": "a2a", "trust_recorder": recorder(ACME)},
            "target": {"endpoint": "https://agent.example.com"}
        }))
        .unwrap();
        registers(vec![authority(ACME, None)]).classify_surface(&mut recording, None);

        assert_eq!(
            registers(Vec::new()).check(&surface_references(&recording), None),
            Err(format!(
                "Trust Recorder entry for trust registry 'tr-rec' uses Authority {ACME}, which does not exist or \
                 belongs to another tenant. Pick another Authority or remove the entry"
            ))
        );
    }

    async fn authority_store(dids: &[&str]) -> (crate::authorities::FileSystemAuthorityStore, tempfile::TempDir) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = crate::authorities::FileSystemAuthorityStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        for did in dids {
            store
                .create(&authority(did, None))
                .await
                .unwrap();
        }
        (store, dir)
    }

    #[test]
    fn unlinked_dids_are_the_literal_dids_in_neither_register() {
        let mut surface = surface(
            vec![
                check("issuer", BILLING, None),
                check("typed", TYPED, None),
                check("typed-again", TYPED, None),
                check("template", "{{ input.agent.authority_did }}", None),
            ],
            "{{ surface.issuer_did }}",
        );
        registers(vec![authority(ACME, None)]).classify_surface(&mut surface, None);

        assert_eq!(unlinked_dids(&surface_references(&surface)), [TYPED]);
    }

    #[tokio::test]
    async fn only_a_link_to_an_authority_that_is_gone_fails() {
        let (store, _dir) = authority_store(&[ACME]).await;
        let elements = [
            check("present", ACME, Some("authority")),
            check("gone", TYPED, Some("authority")),
            check("issuer", TYPED, Some("issuer")),
            check("unlinked", TYPED, None),
            check("template", "{{ input.agent.authority_did }}", Some("authority")),
        ]
        .map(element);

        let missing = MissingAuthorities::find(
            elements
                .iter()
                .map(|element| {
                    (
                        element
                            .query
                            .authority_id
                            .as_str(),
                        element.authority_source,
                    )
                }),
            Some(&store),
        )
        .await;

        let failing: Vec<&str> = elements
            .iter()
            .filter(|element| missing.fails_check(element))
            .map(|element| element.id.as_str())
            .collect();
        assert_eq!(failing, ["gone"]);
    }

    #[tokio::test]
    async fn without_an_authority_store_every_link_to_an_authority_fails() {
        let elements = [check("authority", ACME, Some("authority")), check("unlinked", ACME, None)].map(element);

        let missing = MissingAuthorities::find(
            elements
                .iter()
                .map(|element| {
                    (
                        element
                            .query
                            .authority_id
                            .as_str(),
                        element.authority_source,
                    )
                }),
            None,
        )
        .await;

        assert!(missing.fails_check(&elements[0]));
        assert!(!missing.fails_check(&elements[1]));
    }

    #[tokio::test]
    async fn references_that_need_no_authority_find_nothing_missing() {
        let elements = [check("unlinked", TYPED, None), check("issuer", BILLING, Some("issuer"))].map(element);

        let missing = MissingAuthorities::find(
            elements
                .iter()
                .map(|element| {
                    (
                        element
                            .query
                            .authority_id
                            .as_str(),
                        element.authority_source,
                    )
                }),
            None,
        )
        .await;

        assert!(missing.is_empty());
    }

    #[tokio::test]
    async fn a_recorder_entry_fails_only_when_linked_to_an_authority_that_is_gone() {
        let (store, _dir) = authority_store(&[ACME]).await;
        let entry = |did: &str, source: Option<AuthoritySource>| TrustRecorderEntry {
            trust_registry_id: "tr-rec".to_string(),
            issuer_did: BILLING.to_string(),
            authority_did: did.to_string(),
            authority_source: source,
            include_owned_agent: true,
            custom_resources: Vec::new(),
        };
        let entries = [
            entry(ACME, Some(AuthoritySource::Authority)),
            entry(TYPED, Some(AuthoritySource::Authority)),
            entry(TYPED, None),
        ];

        let missing = MissingAuthorities::find(
            entries
                .iter()
                .map(|entry| (entry.authority_did.as_str(), entry.authority_source)),
            Some(&store),
        )
        .await;

        let failing: Vec<bool> = entries
            .iter()
            .map(|entry| missing.fails_entry(entry))
            .collect();
        assert_eq!(failing, [false, true, false]);
    }

    fn listed(
        id: &str,
        dids: &[&str],
        sources: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "id": id, "trust_registry_id": "tr-1", "query_type": "recognition",
            "query": {"authority_ids": dids, "entity_id": "{{ input.agent.did }}"},
            "authority_sources": sources
        })
    }

    fn listed_sources(surface: &AgentSurface) -> serde_json::Value {
        serde_json::to_value(
            &surface
                .access_point
                .trust_check_list[0]
                .authority_sources,
        )
        .unwrap()
    }

    #[test]
    fn references_list_each_authority_of_a_list_with_its_own_source() {
        let element = element(listed("authority-recognised", &[ACME, TYPED], json!({ ACME: "authority" })));

        let references: Vec<(String, Option<AuthoritySource>, serde_json::Value)> = trust_check_references(&[element])
            .into_iter()
            .map(|reference| (reference.did, reference.source, serde_json::to_value(&reference.used_by).unwrap()))
            .collect();

        let used_by = json!({"element": "trust_check", "id": "authority-recognised"});
        assert_eq!(
            references,
            [(ACME.to_string(), Some(AuthoritySource::Authority), used_by.clone()), (TYPED.to_string(), None, used_by)]
        );
    }

    #[test]
    fn classify_sets_the_source_of_each_listed_did_and_drops_unlisted_ones() {
        let template = "{{ input.agent.authority_did }}";
        let unlisted = json!({ "did:web:unlisted.example": "authority" });
        let mut surface =
            surface(vec![listed("authority-recognised", &[ACME, BILLING, TYPED, template], unlisted)], BILLING);

        assert!(registers(vec![authority(ACME, None)]).classify_surface(&mut surface, None));

        assert_eq!(listed_sources(&surface), json!({ ACME: "authority", BILLING: "issuer" }));
    }

    #[test]
    fn classify_drops_a_single_authority_source_sent_beside_a_list() {
        let mut sent = listed("authority-recognised", &[ACME], json!({}));
        sent["authority_source"] = json!("authority");
        let mut surface = surface(vec![sent], BILLING);

        registers(vec![authority(ACME, None)]).classify_surface(&mut surface, None);

        assert_eq!(
            surface
                .access_point
                .trust_check_list[0]
                .authority_source,
            None
        );
    }

    #[test]
    fn classify_never_drops_a_link_of_a_listed_did() {
        let registers = registers(Vec::new());
        let stored = surface(vec![listed("authority-recognised", &[TYPED], json!({ TYPED: "authority" }))], BILLING);

        let mut dropped = surface(vec![listed("authority-recognised", &[TYPED], json!({}))], BILLING);
        registers.classify_surface(&mut dropped, Some(&stored));

        assert_eq!(listed_sources(&dropped), json!({ TYPED: "authority" }));
    }

    #[test]
    fn classify_trust_checks_sets_the_source_of_each_listed_did() {
        let mut elements = [element(listed("authority-recognised", &[ACME, TYPED], json!({ TYPED: "issuer" })))];

        assert!(registers(vec![authority(ACME, None)]).classify_trust_checks(&mut elements, None, None));

        assert_eq!(serde_json::to_value(&elements[0].authority_sources).unwrap(), json!({ ACME: "authority" }));
    }

    #[test]
    fn check_refuses_a_listed_authority_that_is_gone() {
        let surface =
            surface(vec![listed("authority-recognised", &[ACME, TYPED], json!({ TYPED: "authority" }))], BILLING);

        assert_eq!(
            registers(vec![authority(ACME, None)]).check(&surface_references(&surface), None),
            Err(format!(
                "Trust Check 'authority-recognised' uses Authority {TYPED}, which does not exist or belongs to another tenant. Pick \
                 another Authority or remove the Trust Check"
            ))
        );
    }

    #[test]
    fn check_refuses_a_listed_authority_another_tenant_owns_as_it_refuses_a_missing_one() {
        let references = trust_check_references(&[element(listed(
            "authority-recognised",
            &[TYPED, ACME],
            json!({ ACME: "authority" }),
        ))]);
        let other_tenants = registers(vec![authority(ACME, Some("tenant-b"))]);

        let refusal = other_tenants
            .check(&references, Some("tenant-a"))
            .unwrap_err();
        assert_eq!(
            Err(refusal),
            registers(Vec::new()).check(&references, Some("tenant-a")),
            "another tenant's listed Authority is refused exactly as a missing one"
        );
        assert_eq!(other_tenants.check(&references, Some("tenant-b")), Ok(()));
    }

    #[test]
    fn check_refuses_a_source_on_a_listed_template() {
        let template = "{{ input.agent.authority_did }}";
        let surface =
            surface(vec![listed("authority-recognised", &[ACME, template], json!({ template: "issuer" }))], BILLING);

        assert_eq!(
            registers(Vec::new()).check(&surface_references(&surface), None),
            Err("Trust Check 'authority-recognised': authority_sources cannot be set on a template; remove it or use a DID"
                .to_string())
        );
    }

    #[test]
    fn check_refuses_a_kept_listed_authority_that_is_gone() {
        let registers = registers(vec![authority(ACME, None)]);
        let stored = surface(
            vec![listed("authority-recognised", &[ACME, TYPED], json!({ ACME: "authority", TYPED: "authority" }))],
            BILLING,
        );
        let mut saved = surface(vec![listed("authority-recognised", &[ACME, TYPED], json!({}))], BILLING);
        registers.classify_surface(&mut saved, Some(&stored));

        assert_eq!(
            registers.check(&surface_references(&saved), None),
            Err(format!(
                "Trust Check 'authority-recognised' uses Authority {TYPED}, which does not exist or belongs to another tenant. Pick \
                 another Authority or remove the Trust Check"
            ))
        );
    }

    #[test]
    fn the_source_round_trips_and_is_omitted_when_absent() {
        let linked = element(check("caller", ACME, Some("authority")));
        assert_eq!(linked.authority_source, Some(AuthoritySource::Authority));
        assert_eq!(serde_json::to_value(&linked).unwrap()["authority_source"], json!("authority"));

        let unlinked = element(check("caller", ACME, None));
        assert!(
            serde_json::to_value(&unlinked)
                .unwrap()
                .get("authority_source")
                .is_none()
        );
        assert!(serde_json::from_value::<TrustCheckElement>(check("caller", ACME, Some("did"))).is_err());
    }
}
