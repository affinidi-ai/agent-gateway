use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Value, json};

use crate::config::agent_surface::AgentSurface;
use crate::identity::IdentityStore;
use crate::identity::filesystem::{AgentIdentityRecord, ChannelUsage, FilesystemIdentityStore, IdentityOrigin};
use crate::identity::target_card_names::{CardLocation, TargetCardNameService, TargetCardSource};
use crate::metrics::MetricsStore;
use crate::observability::IdentityInfo;
use crate::observability::caller_names::{CallerNameService, CallerNameSources};
use crate::observability::dashboard::{build_identity_list_with, identities_changed_since};
use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};

const CALLER_DID: &str = "did:web:acme.com:billing";
const CARD_URL: &str = "https://acme.com/.well-known/agent-card.json";
const TARGET_URL: &str = "http://localhost:9000";

struct TargetDirectory;

#[async_trait]
impl TargetCardSource for TargetDirectory {
    async fn fetch_agent_card(
        &self,
        location: &CardLocation,
    ) -> Option<Value> {
        (location.endpoint == TARGET_URL).then(|| json!({ "name": "DateTime Agent" }))
    }
}

struct CallerDirectory;

#[async_trait]
impl CallerNameSources for CallerDirectory {
    async fn resolve_did_document(
        &self,
        did: &str,
    ) -> Result<Value, String> {
        Ok(json!({
            "id": did,
            "alsoKnownAs": ["acme.com/@Billing"],
            "service": [{ "id": format!("{did}#agent-card"), "type": "Other", "serviceEndpoint": { "uri": CARD_URL } }]
        }))
    }

    async fn verify_agent_name(
        &self,
        _name: &str,
    ) -> Result<String, String> {
        Err("alsoKnownAs back-claim does not match".to_string())
    }

    async fn fetch_agent_card(
        &self,
        url: &str,
    ) -> Result<Value, String> {
        if url == CARD_URL {
            Ok(json!({ "name": "Billing Bot" }))
        } else {
            Err("unexpected card URL".to_string())
        }
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    identities: Arc<dyn IdentityStore>,
    surfaces: Arc<FileSystemAgentSurfaceStore>,
    caller_names: Arc<CallerNameService>,
    card_names: Arc<TargetCardNameService>,
}

impl Fixture {
    async fn new(surfaces: &[(&str, &str)]) -> Self {
        let surfaces: Vec<(&str, &str, &str)> = surfaces
            .iter()
            .map(|(id, name)| (*id, *name, ""))
            .collect();
        Self::with_targets(&surfaces).await
    }

    async fn with_targets(surfaces: &[(&str, &str, &str)]) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let identities: Arc<dyn IdentityStore> = Arc::new(
            FilesystemIdentityStore::new(dir.path().join("identities"))
                .await
                .expect("identity store"),
        );
        let surface_store = Arc::new(
            FileSystemAgentSurfaceStore::new(dir.path().join("surfaces"))
                .await
                .expect("surface store"),
        );
        for (id, name, endpoint) in surfaces {
            let mut surface = AgentSurface {
                surface_id: id.to_string(),
                name: name.to_string(),
                ..Default::default()
            };
            surface.target.endpoint = endpoint.to_string();
            surface_store
                .save(&surface)
                .await
                .expect("save surface");
        }
        Self {
            _dir: dir,
            identities,
            surfaces: surface_store,
            caller_names: Arc::new(CallerNameService::new(Arc::new(CallerDirectory))),
            card_names: Arc::new(TargetCardNameService::new(Arc::new(TargetDirectory))),
        }
    }

    async fn rows(&self) -> HashMap<String, IdentityInfo> {
        build_identity_list_with(
            &self.identities,
            &[],
            &Arc::new(MetricsStore::new(10)),
            Some(&self.surfaces),
            &self.caller_names,
            &self.card_names,
        )
        .await
        .expect("identity list")
        .into_iter()
        .map(|row| (row.did.clone(), row))
        .collect()
    }

    async fn wait_for_caller_name(&self) {
        for _ in 0..200 {
            if self
                .caller_names
                .lookup_or_spawn(CALLER_DID)
                .into_name()
                .is_some()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("caller name for {CALLER_DID} never resolved");
    }

    async fn wait_for_target_card_name(
        &self,
        surface_id: &str,
    ) {
        let location = CardLocation {
            endpoint: TARGET_URL.to_string(),
            card_path: None,
        };
        for _ in 0..200 {
            if self
                .card_names
                .lookup_or_spawn(surface_id, &location)
                .is_some()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("target Agent Card name for {surface_id} never resolved");
    }
}

fn legacy_managed_record(
    did: &str,
    surface_ids: &[&str],
    fields: HashMap<String, Value>,
) -> AgentIdentityRecord {
    let now = Utc::now();
    AgentIdentityRecord {
        did: did.to_string(),
        identity_hash: format!("hash-{did}"),
        created_at: now,
        identity_fields: fields,
        usage_count: 1,
        last_used_at: Some(now),
        channel_usage: surface_ids
            .iter()
            .map(|id| ChannelUsage {
                channel_config_id: id.to_string(),
                usage_count: 1,
                last_used_at: now,
            })
            .collect(),
        private_key: None,
        channel_config_id: surface_ids
            .first()
            .map(|id| id.to_string()),
        is_local: true,
        verified: true,
        origin: None,
    }
}

async fn store_managed(
    fixture: &Fixture,
    record: AgentIdentityRecord,
) {
    let hash = record.identity_hash.clone();
    fixture
        .identities
        .create(record)
        .await
        .expect("create identity");
    fixture
        .identities
        .set_origin(&hash, IdentityOrigin::Managed)
        .await
        .expect("stamp managed origin");
}

#[tokio::test]
async fn managed_identity_shows_surface_name_and_credential_principal() {
    let fixture = Fixture::new(&[("oxygen", "OXYGEN")]).await;
    let fields = HashMap::from([("certificate_id".to_string(), json!("NITROGEN"))]);
    store_managed(&fixture, legacy_managed_record("did:example:oxygen", &["oxygen"], fields)).await;

    let row = serde_json::to_value(&fixture.rows().await["did:example:oxygen"]).expect("row JSON");

    assert_eq!(row["origin"], json!("managed"));
    assert_eq!(row["display_name"], json!("OXYGEN"));
    assert_eq!(row["display_name_source"], json!("surface_name"));
    assert_eq!(row["surface_id"], json!("oxygen"));
    assert_eq!(row["surface_name"], json!("OXYGEN"));
    assert_eq!(row["credential_principal"], json!({ "kind": "certificate", "id": "NITROGEN" }));
}

#[tokio::test]
async fn did_shared_by_two_surfaces_is_marked_as_a_name_conflict() {
    let fixture = Fixture::new(&[("oxygen", "OXYGEN"), ("helium", "HELIUM")]).await;
    store_managed(&fixture, legacy_managed_record("did:example:shared", &["oxygen", "helium"], HashMap::new())).await;

    let row = serde_json::to_value(&fixture.rows().await["did:example:shared"]).expect("row JSON");

    assert_eq!(row["name_conflict"], json!(true));
    assert!(
        row.get("display_name")
            .is_none(),
        "conflict row must not carry a name: {row}"
    );
    assert_eq!(row["surface_name"], json!("OXYGEN"));
}

#[tokio::test]
async fn external_caller_never_takes_surface_fields() {
    let fixture = Fixture::new(&[("oxygen", "OXYGEN")]).await;
    fixture
        .identities
        .store_external_did(
            CALLER_DID,
            HashMap::from([("certificate_id".to_string(), json!("NITROGEN"))]),
            Some("oxygen".to_string()),
            true,
        )
        .await
        .expect("store external caller");

    let row = serde_json::to_value(&fixture.rows().await[CALLER_DID]).expect("row JSON");

    assert_eq!(row["origin"], json!("external_caller"));
    for absent in ["display_name", "surface_id", "surface_name", "credential_principal", "name_conflict"] {
        assert!(row.get(absent).is_none(), "{absent} must be omitted for a caller row: {row}");
    }

    fixture
        .wait_for_caller_name()
        .await;
    let named = serde_json::to_value(&fixture.rows().await[CALLER_DID]).expect("row JSON");
    assert_eq!(named["display_name"], json!("Billing Bot"));
    assert_eq!(named["display_name_source"], json!("agent_card"));
    assert!(
        named
            .get("display_name_verified")
            .is_none(),
        "Agent Card names are unverified: {named}"
    );
}

#[tokio::test]
async fn delta_includes_caller_after_its_name_resolves() {
    let fixture = Fixture::new(&[]).await;
    fixture
        .identities
        .store_external_did(CALLER_DID, HashMap::new(), None, true)
        .await
        .expect("store external caller");
    let since = Utc::now() + chrono::Duration::milliseconds(1);
    tokio::time::sleep(Duration::from_millis(5)).await;

    let before: Vec<IdentityInfo> = fixture
        .rows()
        .await
        .into_values()
        .collect();
    let renamed: HashSet<String> = fixture
        .caller_names
        .changed_since(since)
        .into_iter()
        .collect();
    assert!(identities_changed_since(before, since, &renamed, &HashSet::new()).is_empty());

    fixture
        .wait_for_caller_name()
        .await;
    let after: Vec<IdentityInfo> = fixture
        .rows()
        .await
        .into_values()
        .collect();
    let renamed: HashSet<String> = fixture
        .caller_names
        .changed_since(since)
        .into_iter()
        .collect();
    let delta = identities_changed_since(after, since, &renamed, &HashSet::new());

    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].did, CALLER_DID);
    assert_eq!(
        delta[0]
            .display_name
            .as_deref(),
        Some("Billing Bot")
    );
}

#[tokio::test]
async fn managed_identity_shows_target_agent_card_name_once_resolved() {
    let fixture = Fixture::with_targets(&[("def", "DEF", TARGET_URL)]).await;
    store_managed(&fixture, legacy_managed_record("did:example:def", &["def"], HashMap::new())).await;

    let first = serde_json::to_value(&fixture.rows().await["did:example:def"]).expect("row JSON");
    assert_eq!(first["display_name"], json!("DEF"));
    assert_eq!(first["display_name_source"], json!("surface_name"));
    assert!(
        first
            .get("display_name_pending")
            .is_none(),
        "managed rows never wait on a lookup: {first}"
    );

    fixture
        .wait_for_target_card_name("def")
        .await;
    let row = serde_json::to_value(&fixture.rows().await["did:example:def"]).expect("row JSON");
    assert_eq!(row["display_name"], json!("DateTime Agent"));
    assert_eq!(row["display_name_source"], json!("target_agent_card"));
    assert!(
        row.get("display_name_verified")
            .is_none(),
        "target Agent Card names are unverified: {row}"
    );
    assert_eq!(row["surface_name"], json!("DEF"));
}

#[tokio::test]
async fn managed_identity_without_reachable_card_keeps_surface_name() {
    let fixture = Fixture::with_targets(&[("ghi", "GHI", "http://localhost:9999")]).await;
    store_managed(&fixture, legacy_managed_record("did:example:ghi", &["ghi"], HashMap::new())).await;

    fixture.rows().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let row = serde_json::to_value(&fixture.rows().await["did:example:ghi"]).expect("row JSON");
    assert_eq!(row["display_name"], json!("GHI"));
    assert_eq!(row["display_name_source"], json!("surface_name"));
}

#[tokio::test]
async fn delta_includes_managed_identity_after_its_card_name_resolves() {
    let fixture = Fixture::with_targets(&[("def", "DEF", TARGET_URL)]).await;
    store_managed(&fixture, legacy_managed_record("did:example:def", &["def"], HashMap::new())).await;
    let since = Utc::now() + chrono::Duration::milliseconds(1);
    tokio::time::sleep(Duration::from_millis(5)).await;

    fixture.rows().await;
    fixture
        .wait_for_target_card_name("def")
        .await;
    let after: Vec<IdentityInfo> = fixture
        .rows()
        .await
        .into_values()
        .collect();
    let renamed_surfaces: HashSet<String> = fixture
        .card_names
        .changed_since(since)
        .into_iter()
        .collect();
    let delta = identities_changed_since(after, since, &HashSet::new(), &renamed_surfaces);

    assert_eq!(delta.len(), 1);
    assert_eq!(delta[0].did, "did:example:def");
    assert_eq!(
        delta[0]
            .display_name
            .as_deref(),
        Some("DateTime Agent")
    );
}
