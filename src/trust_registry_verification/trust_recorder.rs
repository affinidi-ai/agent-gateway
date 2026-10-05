//! Trust Recorder runtime stage.
//!
//! Writes `TrAdminRecordRequest`s to one or more configured trust registries
//! on the MA→AP response leg. Fire-and-forget: any per-record failure is
//! logged and the response continues.
//!
//! Wire path: `AgentSurface::access_point::trust_recorder`.
//! Frontend element: `www/default/src/components/surface-builder/elements/trust-recorder/`.
//!
//! Since removing the legacy `VCIssuer::register_agent_in_trust_registry`
//! writer, Trust Recorder is the **only** stage that writes agent-in-TR
//! records. Both the direct and `fabric://` request pipelines fire it on
//! discovery + response.

use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::config::agent_surface::AgentSurface;
use crate::config::types::{EntityTarget, TrustRecorderConfig, TrustRecorderEntry};
use crate::trust_registries::TrustRegistryListenerManager;
use crate::trust_registries::store::TrustRegistryStore;
use crate::trust_registries::types::TrAdminRecordRequest;

/// Template token operators can put in a `TrustRecorderEntry.authority_did`
/// slot to have the recorder resolve the surface's Issuer DID at write
/// time (instead of a static literal DID). Resolves to `Issuer.did` for
/// the surface's `issuer_id`; when that isn't configured or the issuer
/// can't be looked up, the entry is skipped with a WARN.
///
/// Kept in sync with the frontend constant of the same name in
/// `www/default/src/components/surface-builder/elements/trust-recorder/definition.ts`.
pub const SURFACE_ISSUER_DID_TEMPLATE: &str = "{{ surface.issuer_did }}";

/// Write all triples declared by `cfg` for `agent_did` to their target
/// trust registries. Runs sequentially per entry × per triple; errors are
/// logged and the loop continues (never fails the response leg).
///
/// Resolves each entry's `trust_registry_id` → TR DID via `tr_store`.
/// The TR DID is required by `TrustRegistryListenerManager::create_record`.
///
/// `resolved_issuer_did` is the pre-computed value for the
/// `{{ surface.issuer_did }}` template — usually the surface's `Issuer.did`
/// resolved by [`spawn_trust_recorder`] before firing the task. Pass
/// `None` when no surface Issuer is configured; entries whose
/// `authority_did` uses the template are then skipped with a WARN.
pub async fn apply_trust_recorder(
    cfg: &TrustRecorderConfig,
    agent_did: &str,
    resolved_issuer_did: Option<&str>,
    tr_manager: Arc<TrustRegistryListenerManager>,
    tr_store: Arc<dyn TrustRegistryStore>,
) {
    if cfg.entries.is_empty() {
        return;
    }
    info!(
        entry_count = cfg.entries.len(),
        agent_did = agent_did,
        "Trust Recorder: writing records for {} entry(ies)",
        cfg.entries.len()
    );

    for entry in &cfg.entries {
        let authority_did = match resolve_authority_did(entry, resolved_issuer_did) {
            Some(v) => v,
            None => continue,
        };

        let tr = match tr_store
            .get(&entry.trust_registry_id)
            .await
        {
            Ok(Some(tr)) => tr,
            Ok(None) => {
                warn!(
                    trust_registry_id = %entry.trust_registry_id,
                    "Trust Recorder: TR not found, skipping entry"
                );
                continue;
            }
            Err(e) => {
                warn!(
                    trust_registry_id = %entry.trust_registry_id,
                    error = %e,
                    "Trust Recorder: TR lookup failed, skipping entry"
                );
                continue;
            }
        };

        let tr_did = match tr
            .main_did
            .as_deref()
            .or(tr.registry_did.as_deref())
            .or(tr.did.as_deref())
        {
            Some(d) => d.to_string(),
            None => {
                warn!(
                    trust_registry_id = %entry.trust_registry_id,
                    "Trust Recorder: TR has no resolved DID (not connected yet), skipping entry"
                );
                continue;
            }
        };

        for record in build_records(entry, agent_did, &authority_did) {
            match tr_manager
                .create_record(&tr_did, &record)
                .await
            {
                Ok(_) => info!(
                    trust_registry_did = %tr_did,
                    authority = %record.authority_id,
                    entity = %record.entity_id,
                    action = %record.action,
                    resource = %record.resource,
                    "Trust Recorder: record created"
                ),
                Err(e) => {
                    // Duplicate records are expected on every subsequent
                    // response from the same managed agent — the recorder
                    // is idempotent by design. Drop these to debug so the
                    // warn stream stays actionable.
                    let msg = e.to_string();
                    if msg.contains("already exists") {
                        debug!(
                            trust_registry_did = %tr_did,
                            action = %record.action,
                            resource = %record.resource,
                            "Trust Recorder: record already exists (idempotent)"
                        );
                    } else {
                        warn!(
                            trust_registry_did = %tr_did,
                            error = %e,
                            action = %record.action,
                            resource = %record.resource,
                            "Trust Recorder: create_record failed (non-fatal)"
                        );
                    }
                }
            }
        }
    }
}

/// Resolve `entry.authority_did` for the current write, expanding the
/// `{{ surface.issuer_did }}` template against the surface-resolved issuer
/// DID. Returns `None` (with a WARN) when the template is used but no
/// resolved issuer is available — that entry is skipped fail-safe rather
/// than falling back to a literal template string, which would produce a
/// registry record with a `{{ … }}` `authority_id` (garbage).
fn resolve_authority_did(
    entry: &TrustRecorderEntry,
    resolved_issuer_did: Option<&str>,
) -> Option<String> {
    if entry.authority_did.trim() == SURFACE_ISSUER_DID_TEMPLATE {
        match resolved_issuer_did {
            Some(did) if !did.is_empty() => Some(did.to_string()),
            _ => {
                warn!(
                    trust_registry_id = %entry.trust_registry_id,
                    template = SURFACE_ISSUER_DID_TEMPLATE,
                    "Trust Recorder: `surface.issuer_did` template unresolved (surface has no issuer configured), skipping entry"
                );
                None
            }
        }
    } else {
        Some(entry.authority_did.clone())
    }
}

/// Fire-and-forget wrapper that spawns a `tokio` task to run
/// `apply_trust_recorder`. Centralises the gate every call site would
/// otherwise duplicate: `agent_did` must be `did:`-prefixed,
/// `surface.trust_recorder()` must have at least one entry, and a
/// `TrustRegistryListenerManager` must be available. The async
/// `tr_manager.store()` lookup runs inside the spawned task, so callers do
/// not need to `.await` before firing.
///
/// The spawned task also resolves `surface.issuer_id → Issuer.did` (via
/// the global `IssuerStore`) so entries authored with
/// `authority_did = "{{ surface.issuer_did }}"` write records whose
/// `authority_id` matches the surface's Issuer at record time.
///
/// Idempotent (`apply_trust_recorder` logs duplicates at `DEBUG`), so it is
/// safe to fire on every eligible request. Never blocks the response.
pub fn spawn_trust_recorder(
    surface: &AgentSurface,
    agent_did: &str,
    tr_manager: Option<Arc<TrustRegistryListenerManager>>,
) {
    if !agent_did.starts_with("did:") {
        return;
    }
    let Some(recorder_cfg) = surface.trust_recorder() else {
        return;
    };
    if recorder_cfg
        .entries
        .is_empty()
    {
        return;
    }
    let Some(tr_manager) = tr_manager else {
        return;
    };
    let cfg = recorder_cfg.clone();
    let did = agent_did.to_string();
    let issuer_id = surface.issuer_id.clone();
    tokio::spawn(async move {
        let Some(store) = tr_manager.store().await else {
            return;
        };
        let resolved_issuer_did = resolve_surface_issuer_did(issuer_id.as_deref()).await;
        apply_trust_recorder(&cfg, &did, resolved_issuer_did.as_deref(), tr_manager, store).await;
    });
}

/// Look up `surface.issuer_id → Issuer.did` via the process-global
/// `IssuerStore`. Returns `None` when the issuer_id is unset, the store
/// isn't initialised, or the lookup fails — the caller decides how to
/// treat the missing value (per-entry, whether to skip or use a literal).
async fn resolve_surface_issuer_did(issuer_id: Option<&str>) -> Option<String> {
    let issuer_id = issuer_id?;
    let store = crate::gateways::connection_points::get_issuer_store()?;
    match store.get(issuer_id).await {
        Ok(Some(issuer)) => Some(issuer.did),
        Ok(None) => {
            warn!(
                issuer_id = %issuer_id,
                "Trust Recorder: surface issuer_id not found in issuer store"
            );
            None
        }
        Err(e) => {
            warn!(
                issuer_id = %issuer_id,
                error = %e,
                "Trust Recorder: issuer store lookup failed"
            );
            None
        }
    }
}

/// Expand one `TrustRecorderEntry` into the concrete TrAdmin records it
/// declares: the optional `ownedAgent` triple plus a `custom_resources`
/// fan-out (each with its own action/resource/entity_target).
///
/// `authority_did` is the value passed to every emitted record — usually
/// `entry.authority_did` verbatim, but the `{{ surface.issuer_did }}`
/// template gets expanded upstream in [`resolve_authority_did`].
fn build_records(
    entry: &TrustRecorderEntry,
    agent_did: &str,
    authority_did: &str,
) -> Vec<TrAdminRecordRequest> {
    let mut out = Vec::new();

    if entry.include_owned_agent {
        out.push(TrAdminRecordRequest {
            authority_id: authority_did.to_string(),
            entity_id: agent_did.to_string(),
            action: "is".to_string(),
            resource: "ownedAgent".to_string(),
            record_type: "recognition".to_string(),
            authorized: true,
            recognized: true,
            context: None,
        });
    }
    for resource in &entry.custom_resources {
        let action = resource.action.trim();
        let res = resource.resource.trim();
        let record_type = resource.record_type.trim();
        if action.is_empty() || res.is_empty() || record_type.is_empty() {
            continue;
        }
        let entity_id = match resource.entity_target {
            EntityTarget::Issuer => entry.issuer_did.clone(),
            EntityTarget::Agent => agent_did.to_string(),
        };
        out.push(TrAdminRecordRequest {
            authority_id: authority_did.to_string(),
            entity_id,
            action: action.to_string(),
            resource: res.to_string(),
            record_type: record_type.to_string(),
            authorized: true,
            recognized: true,
            context: None,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::CustomResource;

    fn base_entry() -> TrustRecorderEntry {
        TrustRecorderEntry {
            trust_registry_id: "tr-1".into(),
            issuer_did: "did:example:issuer".into(),
            authority_did: "did:example:authority".into(),
            include_owned_agent: false,
            custom_resources: vec![],
        }
    }

    #[test]
    fn empty_entry_yields_no_records() {
        let e = base_entry();
        assert!(build_records(&e, "did:example:agent", &e.authority_did).is_empty());
    }

    #[test]
    fn owned_agent_uses_authority_did_and_agent_entity() {
        let mut e = base_entry();
        e.include_owned_agent = true;
        let recs = build_records(&e, "did:example:agent", &e.authority_did);
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.resource, "ownedAgent");
        assert_eq!(r.action, "is");
        assert_eq!(r.entity_id, "did:example:agent");
        assert_eq!(r.authority_id, "did:example:authority");
        assert_ne!(r.authority_id, r.entity_id);
    }

    #[test]
    fn custom_resources_respect_entity_target_and_skip_blanks() {
        let mut e = base_entry();
        e.custom_resources = vec![
            CustomResource {
                action: "is".into(),
                resource: "paymentAgent".into(),
                entity_target: EntityTarget::Agent,
                record_type: "recognition".into(),
            },
            CustomResource {
                action: "register".into(),
                resource: "agents".into(),
                entity_target: EntityTarget::Issuer,
                record_type: "authorization".into(),
            },
            CustomResource {
                action: "  ".into(),
                resource: "blank".into(),
                entity_target: EntityTarget::Agent,
                record_type: "recognition".into(),
            },
            CustomResource {
                action: "is".into(),
                resource: "  ".into(),
                entity_target: EntityTarget::Agent,
                record_type: "recognition".into(),
            },
            CustomResource {
                action: "is".into(),
                resource: "logs".into(),
                entity_target: EntityTarget::Agent,
                record_type: "  ".into(),
            },
        ];
        let recs = build_records(&e, "did:example:agent", &e.authority_did);
        assert_eq!(recs.len(), 2);

        assert_eq!(recs[0].action, "is");
        assert_eq!(recs[0].resource, "paymentAgent");
        assert_eq!(recs[0].entity_id, "did:example:agent");
        assert_eq!(recs[0].authority_id, "did:example:authority");
        assert_eq!(recs[0].record_type, "recognition");

        assert_eq!(recs[1].action, "register");
        assert_eq!(recs[1].resource, "agents");
        assert_eq!(recs[1].entity_id, "did:example:issuer");
        assert_eq!(recs[1].authority_id, "did:example:authority");
        assert_eq!(recs[1].record_type, "authorization");
    }

    #[test]
    fn resolve_authority_did_returns_literal_verbatim() {
        let e = base_entry();
        let resolved = resolve_authority_did(&e, Some("did:example:issuer-runtime"));
        assert_eq!(resolved.as_deref(), Some("did:example:authority"));
    }

    #[test]
    fn resolve_authority_did_expands_surface_issuer_template() {
        let mut e = base_entry();
        e.authority_did = SURFACE_ISSUER_DID_TEMPLATE.to_string();
        let resolved = resolve_authority_did(&e, Some("did:example:issuer-runtime"));
        assert_eq!(resolved.as_deref(), Some("did:example:issuer-runtime"));
    }

    #[test]
    fn resolve_authority_did_skips_entry_when_template_unresolved() {
        let mut e = base_entry();
        e.authority_did = SURFACE_ISSUER_DID_TEMPLATE.to_string();
        // No resolved issuer available (surface has no issuer_id or lookup failed).
        assert!(resolve_authority_did(&e, None).is_none());
        // Empty string is treated the same as None — never emit a record
        // with an empty `authority_id`.
        assert!(resolve_authority_did(&e, Some("")).is_none());
    }

    #[test]
    fn build_records_uses_template_expanded_authority_end_to_end() {
        let mut e = base_entry();
        e.authority_did = SURFACE_ISSUER_DID_TEMPLATE.to_string();
        e.include_owned_agent = true;
        e.custom_resources = vec![CustomResource {
            action: "sign".into(),
            resource: "invoice".into(),
            entity_target: EntityTarget::Agent,
            record_type: "authorization".into(),
        }];
        let resolved = resolve_authority_did(&e, Some("did:example:issuer-runtime")).unwrap();
        let recs = build_records(&e, "did:example:agent", &resolved);
        assert_eq!(recs.len(), 2);
        // Both emitted records now carry the resolved DID as authority_id,
        // matching what a downstream Trust Check `authority = verified issuer`
        // query will look for.
        assert_eq!(recs[0].authority_id, "did:example:issuer-runtime");
        assert_eq!(recs[1].authority_id, "did:example:issuer-runtime");
    }
}
