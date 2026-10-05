use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{Extension, Json, extract::Path};
use serde_json::json;

use super::helpers::{GatewayHarness, configure_admin_api};
use crate::authorities::handlers::{
    CreateAuthorityRequest, UpdateAuthorityRequest, create_authority, update_authority,
};
use crate::authorities::{AuthorityStore, FileSystemAuthorityStore};
use crate::config::agent_surface::AgentSurface;
use crate::identity::IdentityStore;
use crate::identity::filesystem::{FilesystemIdentityStore, IdentityOrigin};
use crate::issuers::types::Issuer;
use crate::trust_registries::reference_fields::test_support::{Call, FakeClient, conflict};
use crate::trust_registries::reference_fields::{PublishOutcome, ReferenceFieldPublisher, surface_reference_values};

const TR_DID: &str = "did:web:registry.example";
const AUTHORITY_DID: &str = "did:web:authority.example";
const UNREACHABLE_TR_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

async fn authority_store() -> (Arc<FileSystemAuthorityStore>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = FileSystemAuthorityStore::new(dir.path().to_path_buf())
        .await
        .unwrap();
    (Arc::new(store), dir)
}

async fn create_acme(store: &Arc<FileSystemAuthorityStore>) -> String {
    let (_, Json(created)) = create_authority(
        Extension(store.clone()),
        None,
        None,
        None,
        Json(CreateAuthorityRequest {
            tenant_id: None,
            name: "Acme".to_string(),
            did: AUTHORITY_DID.to_string(),
            description: Some("Acme root of trust".to_string()),
            context: None,
        }),
    )
    .await
    .unwrap();
    created.id
}

fn registered_issuer() -> Issuer {
    let mut issuer = Issuer::new(
        "issuer-1".to_string(),
        "Billing".to_string(),
        "did:web:gateway.example:issuers:issuer-1".to_string(),
        json!([]),
        json!({}),
    );
    issuer.description = Some("Billing department".to_string());
    issuer.trust_registry_did = Some(TR_DID.to_string());
    issuer.authority_did = Some(AUTHORITY_DID.to_string());
    issuer
}

fn created(
    field_type: &str,
    id: &str,
    name: &str,
    description: &str,
) -> Call {
    Call::Create(
        TR_DID.to_string(),
        json!({"id": id, "field_type": field_type, "name": name, "description": description}),
    )
}

#[tokio::test]
async fn issuer_registration_publishes_issuer_and_authority_names() {
    let (store, _dir) = authority_store().await;
    create_acme(&store).await;
    let issuer = registered_issuer();
    let client = FakeClient::default();
    let authority_store: Arc<dyn AuthorityStore> = store;

    let outcomes = ReferenceFieldPublisher::default()
        .publish_issuer_fields(&client, Some(authority_store.as_ref()), &issuer)
        .await;

    assert_eq!(outcomes, vec![PublishOutcome::Created, PublishOutcome::Created]);
    assert_eq!(
        client.calls(),
        vec![
            created("entity", &issuer.did, "Billing", "Billing department"),
            created("authority", AUTHORITY_DID, "Acme", "Acme root of trust"),
        ]
    );
}

#[tokio::test]
async fn authority_edit_republishes_authority_name() {
    let (store, _dir) = authority_store().await;
    let authority_id = create_acme(&store).await;
    let issuer = registered_issuer();
    let publisher = ReferenceFieldPublisher::default();
    let client = FakeClient::with_replies(vec![Ok(()), Ok(()), conflict()], vec![]);
    let authority_store: Arc<dyn AuthorityStore> = store.clone();
    publisher
        .publish_issuer_fields(&client, Some(authority_store.as_ref()), &issuer)
        .await;

    let Json(updated) = update_authority(
        Extension(store.clone()),
        Extension(None),
        Path(authority_id.clone()),
        None,
        None,
        Json(UpdateAuthorityRequest {
            name: "Acme Holdings".to_string(),
            did: AUTHORITY_DID.to_string(),
            description: None,
            context: None,
        }),
    )
    .await
    .unwrap();
    assert_eq!(updated.name, "Acme Holdings");
    let renamed = store
        .get(&authority_id)
        .await
        .unwrap()
        .unwrap();
    let outcomes = publisher
        .publish_authority_fields(&client, &[issuer], &renamed)
        .await;

    assert_eq!(outcomes, vec![PublishOutcome::Updated]);
    assert_eq!(
        client.calls()[3],
        Call::Update(
            TR_DID.to_string(),
            json!({"id": AUTHORITY_DID, "field_type": "authority", "name": "Acme Holdings", "description": ""})
        )
    );
}

#[tokio::test]
async fn surface_rename_republishes_managed_agent_name() {
    let dir = tempfile::tempdir().unwrap();
    let identity_store = FilesystemIdentityStore::new(dir.path())
        .await
        .unwrap();
    let mut managed = crate::identity::test_helpers::test_surface_identity_record("did:web:agent.example", "s1");
    managed.origin = Some(IdentityOrigin::Managed);
    identity_store
        .create(managed)
        .await
        .unwrap();
    let mut surface = AgentSurface {
        surface_id: "s1".to_string(),
        name: "OXYGEN".to_string(),
        ..Default::default()
    };
    let publisher = ReferenceFieldPublisher::default();
    let client = FakeClient::with_replies(vec![Ok(()), conflict()], vec![]);
    let registries = BTreeSet::from([TR_DID.to_string()]);
    let records = identity_store
        .list_all()
        .await
        .unwrap();
    publisher
        .publish_all(&client, &registries, &surface_reference_values(&surface, &records))
        .await;

    surface.name = "HELIUM".to_string();
    let outcomes = publisher
        .publish_all(&client, &registries, &surface_reference_values(&surface, &records))
        .await;

    assert_eq!(outcomes, vec![PublishOutcome::Updated]);
    assert_eq!(
        client.calls(),
        vec![
            Call::Create(
                TR_DID.to_string(),
                json!({"id": "did:web:agent.example", "field_type": "entity", "name": "OXYGEN"})
            ),
            Call::Create(
                TR_DID.to_string(),
                json!({"id": "did:web:agent.example", "field_type": "entity", "name": "HELIUM"})
            ),
            Call::Update(
                TR_DID.to_string(),
                json!({"id": "did:web:agent.example", "field_type": "entity", "name": "HELIUM", "description": ""})
            ),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn issuer_and_authority_writes_succeed_when_trust_registry_is_unreachable() {
    let mut admin = None;
    let harness = GatewayHarness::start(|_, _, bootstrap| {
        admin = Some(configure_admin_api(bootstrap));
    })
    .await;
    let admin = admin.expect("admin client");
    let api = |path: &str| format!("{}/api/v1/{path}", harness.gateway_base);

    let authority = admin
        .post(api("authorities"))
        .json(&json!({"name": "Acme", "did": AUTHORITY_DID}))
        .send()
        .await
        .unwrap();
    assert_eq!(authority.status(), 201);
    let authority: serde_json::Value = authority
        .json()
        .await
        .unwrap();

    let issuer = admin
        .post(api("issuers"))
        .json(&json!({"name": "Billing", "trust_registry_did": UNREACHABLE_TR_DID, "authority_did": AUTHORITY_DID}))
        .send()
        .await
        .unwrap();
    assert_eq!(issuer.status(), 201);
    let issuer: serde_json::Value = issuer.json().await.unwrap();
    assert_eq!(issuer["name"], "Billing");
    assert_eq!(issuer["tr_registered"], false);

    let renamed = admin
        .put(api(&format!(
            "authorities/{}",
            authority["id"]
                .as_str()
                .unwrap()
        )))
        .json(&json!({"name": "Acme Holdings", "did": AUTHORITY_DID}))
        .send()
        .await
        .unwrap();
    assert_eq!(renamed.status(), 200);
    let renamed: serde_json::Value = renamed.json().await.unwrap();
    assert_eq!(renamed["name"], "Acme Holdings");
}
