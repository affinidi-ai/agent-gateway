//! Idempotent publishing of human-readable names as trust-registry reference fields.
//!
//! Publishing is best effort: every entry point either spawns a task or returns a
//! [`PublishOutcome`]; none returns an error or blocks the operation that triggered it.

use std::collections::BTreeSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use dashmap::DashMap;
use tracing::{debug, info, warn};

use super::communication::{TrustRegistryError, TrustRegistryListenerManager};
use super::types::{CreateReferenceFieldRequest, ReferenceFieldType, UpdateReferenceFieldRequest};
use crate::authorities::{AuthorityStore, types::Authority};
use crate::config::agent_surface::AgentSurface;
use crate::identity::display_name::{DisplayName, resolve_managed_display_name, sanitize_description, surfaces_by_did};
use crate::identity::filesystem::AgentIdentityRecord;
use crate::issuers::{IssuerStore, types::Issuer};

const PUBLISHED_CACHE_CAP: usize = 10_000;

#[async_trait]
pub trait ReferenceFieldClient: Send + Sync {
    async fn create_reference_field(
        &self,
        tr_did: &str,
        request: &CreateReferenceFieldRequest,
    ) -> Result<(), TrustRegistryError>;

    async fn update_reference_field(
        &self,
        tr_did: &str,
        request: &UpdateReferenceFieldRequest,
    ) -> Result<(), TrustRegistryError>;
}

#[async_trait]
impl ReferenceFieldClient for TrustRegistryListenerManager {
    async fn create_reference_field(
        &self,
        tr_did: &str,
        request: &CreateReferenceFieldRequest,
    ) -> Result<(), TrustRegistryError> {
        TrustRegistryListenerManager::create_reference_field(self, tr_did, request).await
    }

    async fn update_reference_field(
        &self,
        tr_did: &str,
        request: &UpdateReferenceFieldRequest,
    ) -> Result<(), TrustRegistryError> {
        TrustRegistryListenerManager::update_reference_field(self, tr_did, request).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceFieldValue {
    pub field_type: ReferenceFieldType,
    pub id: String,
    pub name: DisplayName,
    pub description: Option<String>,
}

impl ReferenceFieldValue {
    pub fn entity(
        id: &str,
        name: DisplayName,
    ) -> Self {
        Self {
            field_type: ReferenceFieldType::Entity,
            id: id.to_string(),
            name,
            description: None,
        }
    }

    fn content_hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.name
            .as_str()
            .hash(&mut hasher);
        self.description
            .hash(&mut hasher);
        hasher.finish()
    }

    fn create_request(&self) -> CreateReferenceFieldRequest {
        CreateReferenceFieldRequest {
            id: self.id.clone(),
            field_type: self.field_type,
            name: self.name.as_str().to_string(),
            description: self.description.clone(),
            context: None,
        }
    }

    fn update_request(&self) -> UpdateReferenceFieldRequest {
        UpdateReferenceFieldRequest {
            id: self.id.clone(),
            field_type: self.field_type,
            name: Some(self.name.as_str().to_string()),
            description: Some(
                self.description
                    .clone()
                    .unwrap_or_default(),
            ),
            context: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishOutcome {
    Created,
    Updated,
    UpdatedAfterRetry,
    Unchanged,
    Failed,
}

type PublishedKey = (String, ReferenceFieldType, String);

/// Remembers the content last published per `(TR DID, field type, id)` so repeat
/// triggers with an unchanged name skip the wire. Only successes are remembered.
#[derive(Default)]
pub struct ReferenceFieldPublisher {
    published: DashMap<PublishedKey, u64>,
}

static GLOBAL_PUBLISHER: LazyLock<ReferenceFieldPublisher> = LazyLock::new(ReferenceFieldPublisher::default);

impl ReferenceFieldPublisher {
    pub fn global() -> &'static ReferenceFieldPublisher {
        &GLOBAL_PUBLISHER
    }

    /// Create the field; on a conflict update it, and on an update conflict resend
    /// the update once. Any other failure is logged and left for the next trigger.
    pub async fn publish(
        &self,
        client: &dyn ReferenceFieldClient,
        tr_did: &str,
        value: &ReferenceFieldValue,
    ) -> PublishOutcome {
        let key = (tr_did.to_string(), value.field_type, value.id.clone());
        let hash = value.content_hash();
        if self
            .published
            .get(&key)
            .is_some_and(|published| *published == hash)
        {
            return PublishOutcome::Unchanged;
        }

        let outcome = match client
            .create_reference_field(tr_did, &value.create_request())
            .await
        {
            Ok(_) => PublishOutcome::Created,
            Err(e) if e.is_conflict() => Self::update_with_retry(client, tr_did, value).await,
            Err(e) => {
                warn!(
                    trust_registry_did = %tr_did,
                    field_type = ?value.field_type,
                    id = %value.id,
                    error = %e,
                    "Reference field create failed; will retry on the next trigger"
                );
                PublishOutcome::Failed
            }
        };

        if outcome != PublishOutcome::Failed {
            if self.published.len() >= PUBLISHED_CACHE_CAP {
                self.published.clear();
            }
            self.published
                .insert(key, hash);
            info!(
                trust_registry_did = %tr_did,
                field_type = ?value.field_type,
                id = %value.id,
                outcome = ?outcome,
                "Reference field published"
            );
        }
        outcome
    }

    async fn update_with_retry(
        client: &dyn ReferenceFieldClient,
        tr_did: &str,
        value: &ReferenceFieldValue,
    ) -> PublishOutcome {
        let request = value.update_request();
        match client
            .update_reference_field(tr_did, &request)
            .await
        {
            Ok(_) => return PublishOutcome::Updated,
            Err(e) if e.is_conflict() => {
                debug!(
                    trust_registry_did = %tr_did,
                    id = %value.id,
                    "Reference field update hit a concurrent modification; retrying once"
                );
            }
            Err(e) => {
                warn!(
                    trust_registry_did = %tr_did,
                    field_type = ?value.field_type,
                    id = %value.id,
                    error = %e,
                    "Reference field update failed; will retry on the next trigger"
                );
                return PublishOutcome::Failed;
            }
        }
        match client
            .update_reference_field(tr_did, &request)
            .await
        {
            Ok(_) => PublishOutcome::UpdatedAfterRetry,
            Err(e) => {
                warn!(
                    trust_registry_did = %tr_did,
                    field_type = ?value.field_type,
                    id = %value.id,
                    error = %e,
                    "Reference field update retry failed; giving up until the next trigger"
                );
                PublishOutcome::Failed
            }
        }
    }

    pub async fn publish_all(
        &self,
        client: &dyn ReferenceFieldClient,
        tr_dids: &BTreeSet<String>,
        values: &[ReferenceFieldValue],
    ) -> Vec<PublishOutcome> {
        let mut outcomes = Vec::with_capacity(tr_dids.len() * values.len());
        for tr_did in tr_dids {
            for value in values {
                outcomes.push(
                    self.publish(client, tr_did, value)
                        .await,
                );
            }
        }
        outcomes
    }

    pub async fn publish_issuer_fields(
        &self,
        client: &dyn ReferenceFieldClient,
        authority_store: Option<&dyn AuthorityStore>,
        issuer: &Issuer,
    ) -> Vec<PublishOutcome> {
        let Some(tr_did) = issuer
            .trust_registry_did
            .as_deref()
        else {
            return Vec::new();
        };
        let authority = match (
            authority_store,
            issuer
                .authority_did
                .as_deref(),
        ) {
            (Some(store), Some(authority_did)) => match store
                .find_by_did(authority_did)
                .await
            {
                Ok(authority) => authority.filter(|a| authority_visible_to_issuer(a, issuer)),
                Err(e) => {
                    warn!(issuer_id = %issuer.id, error = %e, "Authority lookup for reference field failed");
                    None
                }
            },
            _ => None,
        };
        let values = issuer_reference_values(issuer, authority.as_ref());
        self.publish_all(client, &BTreeSet::from([tr_did.to_string()]), &values)
            .await
    }

    pub async fn publish_authority_fields(
        &self,
        client: &dyn ReferenceFieldClient,
        issuers: &[Issuer],
        authority: &Authority,
    ) -> Vec<PublishOutcome> {
        let Some(value) = authority_reference_value(authority) else {
            return Vec::new();
        };
        self.publish_all(client, &registries_for_authority(authority, issuers), &[value])
            .await
    }
}

fn authority_visible_to_issuer(
    authority: &Authority,
    issuer: &Issuer,
) -> bool {
    authority.tenant_id.is_none() || authority.tenant_id == issuer.tenant_id
}

fn named_value(
    field_type: ReferenceFieldType,
    id: &str,
    raw_name: &str,
    raw_description: Option<&str>,
) -> Option<ReferenceFieldValue> {
    match DisplayName::parse(raw_name) {
        Ok(name) => Some(ReferenceFieldValue {
            field_type,
            id: id.to_string(),
            name,
            description: sanitize_description(raw_description),
        }),
        Err(e) => {
            warn!(field_type = ?field_type, id, error = %e, "Skipping reference field with an invalid name");
            None
        }
    }
}

/// Entity field for the issuer and, when known, the authority field for its authority.
pub fn issuer_reference_values(
    issuer: &Issuer,
    authority: Option<&Authority>,
) -> Vec<ReferenceFieldValue> {
    named_value(ReferenceFieldType::Entity, &issuer.did, &issuer.name, issuer.description.as_deref())
        .into_iter()
        .chain(authority.and_then(authority_reference_value))
        .collect()
}

pub fn authority_reference_value(authority: &Authority) -> Option<ReferenceFieldValue> {
    named_value(
        ReferenceFieldType::Authority,
        &authority.did,
        &authority.name,
        authority
            .description
            .as_deref(),
    )
}

/// Authority field for a DID written as a record's `authority_id`: the Authority
/// register entry with that DID, else the Issuer with that DID.
pub async fn authority_value_for_did(
    did: &str,
    authorities: Option<&dyn AuthorityStore>,
    issuers: Option<&dyn IssuerStore>,
) -> Option<ReferenceFieldValue> {
    if let Some(authority) = find_authority(did, authorities).await {
        return authority_reference_value(&authority);
    }
    let issuer = find_issuer(did, issuers).await?;
    named_value(ReferenceFieldType::Authority, &issuer.did, &issuer.name, issuer.description.as_deref())
}

/// Entity field for an Issuer DID written as a record's `entity_id`.
pub async fn issuer_entity_value_for_did(
    did: &str,
    issuers: Option<&dyn IssuerStore>,
) -> Option<ReferenceFieldValue> {
    let issuer = find_issuer(did, issuers).await?;
    named_value(ReferenceFieldType::Entity, &issuer.did, &issuer.name, issuer.description.as_deref())
}

async fn find_authority(
    did: &str,
    authorities: Option<&dyn AuthorityStore>,
) -> Option<Authority> {
    match authorities?
        .find_by_did(did)
        .await
    {
        Ok(authority) => authority,
        Err(e) => {
            warn!(did, error = %e, "Authority lookup for reference field failed");
            None
        }
    }
}

async fn find_issuer(
    did: &str,
    issuers: Option<&dyn IssuerStore>,
) -> Option<Issuer> {
    match issuers?
        .find_by_did(did)
        .await
    {
        Ok(issuer) => issuer,
        Err(e) => {
            warn!(did, error = %e, "Issuer lookup for reference field failed");
            None
        }
    }
}

/// Trust registries the authority's issuers are registered with.
pub fn registries_for_authority(
    authority: &Authority,
    issuers: &[Issuer],
) -> BTreeSet<String> {
    issuers
        .iter()
        .filter(|issuer| {
            issuer
                .authority_did
                .as_deref()
                == Some(authority.did.as_str())
        })
        .filter(|issuer| authority_visible_to_issuer(authority, issuer))
        .filter_map(|issuer| {
            issuer
                .trust_registry_did
                .clone()
        })
        .collect()
}

/// Entity fields naming every managed DID of `surface`; conflicted DIDs publish nothing.
pub fn surface_reference_values(
    surface: &AgentSurface,
    records: &[AgentIdentityRecord],
) -> Vec<ReferenceFieldValue> {
    let mut by_did: Vec<_> = surfaces_by_did(records)
        .into_iter()
        .filter(|(_, surfaces)| surfaces.contains(&surface.surface_id))
        .collect();
    by_did.sort_by(|a, b| a.0.cmp(&b.0));
    by_did
        .into_iter()
        .filter_map(|(did, surfaces)| {
            resolve_managed_display_name(surface, &surfaces, None)
                .publishable(&did)
                .map(|name| ReferenceFieldValue::entity(&did, name.clone()))
        })
        .collect()
}

pub fn spawn_issuer_publish(
    client: Arc<dyn ReferenceFieldClient>,
    authority_store: Option<Arc<dyn AuthorityStore>>,
    issuer: Issuer,
) {
    tokio::spawn(async move {
        ReferenceFieldPublisher::global()
            .publish_issuer_fields(client.as_ref(), authority_store.as_deref(), &issuer)
            .await;
    });
}

pub fn spawn_authority_publish(
    client: Arc<dyn ReferenceFieldClient>,
    issuer_store: Arc<dyn IssuerStore>,
    authority: Authority,
) {
    tokio::spawn(async move {
        let issuers = match issuer_store.list_all().await {
            Ok(issuers) => issuers,
            Err(e) => {
                warn!(authority_id = %authority.id, error = %e, "Issuer lookup for authority reference field failed");
                return;
            }
        };
        ReferenceFieldPublisher::global()
            .publish_authority_fields(client.as_ref(), &issuers, &authority)
            .await;
    });
}

/// Republish the entity fields of a surface's managed DIDs to the trust registries its
/// Trust Recorder writes to, after the surface was renamed.
pub fn spawn_surface_rename_publish(surface: AgentSurface) {
    let Some(recorder) = surface
        .trust_recorder()
        .filter(|cfg| !cfg.entries.is_empty())
        .cloned()
    else {
        return;
    };
    let Some(manager) = crate::gateways::connection_points::get_trust_registry_listener_manager() else {
        return;
    };
    let Some(vc_issuer) = crate::gateways::connection_points::get_vc_issuer() else {
        return;
    };
    tokio::spawn(async move {
        let Some(tr_store) = manager.store().await else {
            return;
        };
        let records = match vc_issuer
            .get_identity_store()
            .list_all()
            .await
        {
            Ok(records) => records,
            Err(e) => {
                warn!(surface_id = %surface.surface_id, error = %e, "Identity lookup for surface rename failed");
                return;
            }
        };
        let values = surface_reference_values(&surface, &records);
        if values.is_empty() {
            return;
        }
        let tr_dids =
            crate::trust_registry_verification::trust_recorder::recorder_registry_dids(&recorder, tr_store.as_ref())
                .await;
        ReferenceFieldPublisher::global()
            .publish_all(manager.as_ref(), &tr_dids, &values)
            .await;
    });
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum Call {
        Create(String, serde_json::Value),
        Update(String, serde_json::Value),
    }

    pub(crate) type Reply = Result<(), TrustRegistryError>;

    #[derive(Default)]
    pub(crate) struct FakeClient {
        calls: Mutex<Vec<Call>>,
        create_replies: Mutex<Vec<Reply>>,
        update_replies: Mutex<Vec<Reply>>,
    }

    impl FakeClient {
        pub(crate) fn with_replies(
            create: Vec<Reply>,
            update: Vec<Reply>,
        ) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                create_replies: Mutex::new(create),
                update_replies: Mutex::new(update),
            }
        }

        pub(crate) fn calls(&self) -> Vec<Call> {
            self.calls
                .lock()
                .unwrap()
                .clone()
        }

        fn next(replies: &Mutex<Vec<Reply>>) -> Reply {
            let mut replies = replies.lock().unwrap();
            if replies.is_empty() {
                Ok(())
            } else {
                replies.remove(0)
            }
        }
    }

    #[async_trait]
    impl ReferenceFieldClient for FakeClient {
        async fn create_reference_field(
            &self,
            tr_did: &str,
            request: &CreateReferenceFieldRequest,
        ) -> Result<(), TrustRegistryError> {
            let body = serde_json::to_value(request).unwrap();
            self.calls
                .lock()
                .unwrap()
                .push(Call::Create(tr_did.to_string(), body));
            Self::next(&self.create_replies)
        }

        async fn update_reference_field(
            &self,
            tr_did: &str,
            request: &UpdateReferenceFieldRequest,
        ) -> Result<(), TrustRegistryError> {
            let body = serde_json::to_value(request).unwrap();
            self.calls
                .lock()
                .unwrap()
                .push(Call::Update(tr_did.to_string(), body));
            Self::next(&self.update_replies)
        }
    }

    pub(crate) fn conflict() -> Reply {
        Err(TrustRegistryError::ProblemReport(
            crate::trust_registries::communication::TR_CONFLICT_CODE.to_string(),
            "exists".to_string(),
        ))
    }

    pub(crate) fn internal_error() -> Reply {
        Err(TrustRegistryError::ProblemReport("e.p.msg.internal-error".to_string(), "missing".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::identity::filesystem::IdentityOrigin;
    use crate::identity::test_helpers::test_surface_identity_record;

    fn value(name: &str) -> ReferenceFieldValue {
        ReferenceFieldValue::entity("did:web:agent", DisplayName::parse(name).unwrap())
    }

    fn issuer(
        did: &str,
        authority_did: Option<&str>,
        tr_did: Option<&str>,
    ) -> Issuer {
        let mut issuer = Issuer::new(
            format!("id-{did}"),
            "Billing Issuer".to_string(),
            did.to_string(),
            serde_json::Value::Null,
            serde_json::Value::Null,
        );
        issuer.authority_did = authority_did.map(str::to_string);
        issuer.trust_registry_did = tr_did.map(str::to_string);
        issuer
    }

    fn authority(name: &str) -> Authority {
        let now = chrono::Utc::now();
        Authority {
            id: "auth-1".to_string(),
            tenant_id: None,
            name: name.to_string(),
            description: Some("Root of trust".to_string()),
            did: "did:web:authority".to_string(),
            context: None,
            created_at: now,
            updated_at: now,
        }
    }

    async fn stores_with(
        authorities: &[Authority],
        issuers: &[Issuer],
    ) -> (crate::authorities::FileSystemAuthorityStore, crate::issuers::FileSystemIssuerStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let authority_store = crate::authorities::FileSystemAuthorityStore::new(dir.path().join("authorities"))
            .await
            .unwrap();
        let issuer_store = crate::issuers::FileSystemIssuerStore::new(dir.path().join("issuers"))
            .await
            .unwrap();
        for a in authorities {
            authority_store
                .create(a)
                .await
                .unwrap();
        }
        for i in issuers {
            issuer_store
                .create(i)
                .await
                .unwrap();
        }
        (authority_store, issuer_store, dir)
    }

    #[tokio::test]
    async fn authority_value_for_did_names_an_authority_register_entry() {
        let (authorities, issuers, _dir) = stores_with(&[authority("ABC Authority")], &[]).await;

        let value = authority_value_for_did("did:web:authority", Some(&authorities), Some(&issuers))
            .await
            .unwrap();

        assert_eq!(value.field_type, ReferenceFieldType::Authority);
        assert_eq!(value.id, "did:web:authority");
        assert_eq!(value.name.as_str(), "ABC Authority");
        assert_eq!(value.description.as_deref(), Some("Root of trust"));
    }

    #[tokio::test]
    async fn authority_value_for_did_names_an_issuer_used_as_authority() {
        let gateway_did = "did:web:gateway";
        let issuer_did = "did:web:gateway:issuers:abc";
        let (authorities, issuers, _dir) = stores_with(&[], &[issuer(issuer_did, Some(gateway_did), None)]).await;

        let value = authority_value_for_did(issuer_did, Some(&authorities), Some(&issuers))
            .await
            .unwrap();

        assert_eq!(value.field_type, ReferenceFieldType::Authority);
        assert_eq!(value.id, issuer_did);
        assert_eq!(value.name.as_str(), "Billing Issuer");
        assert!(
            authority_value_for_did(gateway_did, Some(&authorities), Some(&issuers))
                .await
                .is_none(),
            "an Issuer's registration authority is not the Issuer"
        );
    }

    #[tokio::test]
    async fn authority_value_for_did_is_none_for_unknown_did_or_missing_stores() {
        let (authorities, issuers, _dir) = stores_with(&[authority("ABC Authority")], &[]).await;

        assert!(
            authority_value_for_did("did:web:unknown", Some(&authorities), Some(&issuers))
                .await
                .is_none()
        );
        assert!(
            authority_value_for_did("did:web:authority", None, None)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn issuer_entity_value_for_did_names_the_issuer_as_an_entity() {
        let issuer_did = "did:web:gateway:issuers:abc";
        let (_authorities, issuers, _dir) = stores_with(&[], &[issuer(issuer_did, None, None)]).await;

        let value = issuer_entity_value_for_did(issuer_did, Some(&issuers))
            .await
            .unwrap();

        assert_eq!(value.field_type, ReferenceFieldType::Entity);
        assert_eq!(value.id, issuer_did);
        assert_eq!(value.name.as_str(), "Billing Issuer");
        assert!(
            issuer_entity_value_for_did("did:web:unknown", Some(&issuers))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn publish_creates_and_caches() {
        let client = FakeClient::default();
        let publisher = ReferenceFieldPublisher::default();

        assert_eq!(
            publisher
                .publish(&client, "did:tr", &value("OXYGEN"))
                .await,
            PublishOutcome::Created
        );
        assert_eq!(
            publisher
                .publish(&client, "did:tr", &value("OXYGEN"))
                .await,
            PublishOutcome::Unchanged
        );

        assert_eq!(
            client.calls(),
            vec![Call::Create(
                "did:tr".to_string(),
                serde_json::json!({"id": "did:web:agent", "field_type": "entity", "name": "OXYGEN"})
            )]
        );
    }

    #[tokio::test]
    async fn publish_updates_on_create_conflict() {
        let client = FakeClient::with_replies(vec![conflict()], vec![]);
        let publisher = ReferenceFieldPublisher::default();

        assert_eq!(
            publisher
                .publish(&client, "did:tr", &value("OXYGEN"))
                .await,
            PublishOutcome::Updated
        );

        assert_eq!(
            client.calls()[1],
            Call::Update(
                "did:tr".to_string(),
                serde_json::json!({"id": "did:web:agent", "field_type": "entity", "name": "OXYGEN", "description": ""})
            )
        );
    }

    #[tokio::test]
    async fn publish_retries_update_once_after_conflict() {
        let client = FakeClient::with_replies(vec![conflict()], vec![conflict()]);
        let publisher = ReferenceFieldPublisher::default();

        assert_eq!(
            publisher
                .publish(&client, "did:tr", &value("OXYGEN"))
                .await,
            PublishOutcome::UpdatedAfterRetry
        );
        assert_eq!(client.calls().len(), 3);
    }

    #[tokio::test]
    async fn publish_gives_up_after_second_update_conflict_and_does_not_cache() {
        let client = FakeClient::with_replies(vec![conflict()], vec![conflict(), conflict()]);
        let publisher = ReferenceFieldPublisher::default();

        assert_eq!(
            publisher
                .publish(&client, "did:tr", &value("OXYGEN"))
                .await,
            PublishOutcome::Failed
        );
        assert_eq!(client.calls().len(), 3);

        assert_eq!(
            publisher
                .publish(&client, "did:tr", &value("OXYGEN"))
                .await,
            PublishOutcome::Created
        );
        assert_eq!(client.calls().len(), 4);
    }

    #[tokio::test]
    async fn publish_internal_error_fails_without_caching() {
        let client = FakeClient::with_replies(vec![conflict()], vec![internal_error()]);
        let publisher = ReferenceFieldPublisher::default();

        assert_eq!(
            publisher
                .publish(&client, "did:tr", &value("OXYGEN"))
                .await,
            PublishOutcome::Failed
        );
        assert_eq!(client.calls().len(), 2);
        assert!(publisher.published.is_empty());
    }

    #[tokio::test]
    async fn publish_unreachable_registry_fails_without_update() {
        let client = FakeClient::with_replies(vec![Err(TrustRegistryError::Timeout("down".to_string()))], vec![]);
        let publisher = ReferenceFieldPublisher::default();

        assert_eq!(
            publisher
                .publish(&client, "did:tr", &value("OXYGEN"))
                .await,
            PublishOutcome::Failed
        );
        assert_eq!(client.calls().len(), 1);
    }

    #[tokio::test]
    async fn publish_rename_updates_existing_field() {
        let client = FakeClient::with_replies(vec![Ok(()), conflict()], vec![]);
        let publisher = ReferenceFieldPublisher::default();
        publisher
            .publish(&client, "did:tr", &value("OXYGEN"))
            .await;

        assert_eq!(
            publisher
                .publish(&client, "did:tr", &value("HELIUM"))
                .await,
            PublishOutcome::Updated
        );

        match &client.calls()[2] {
            Call::Update(_, body) => assert_eq!(body["name"], "HELIUM"),
            other => panic!("Expected update, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_caches_per_registry() {
        let client = FakeClient::default();
        let publisher = ReferenceFieldPublisher::default();
        let outcomes = publisher
            .publish_all(&client, &BTreeSet::from(["did:tr:a".to_string(), "did:tr:b".to_string()]), &[value("OXYGEN")])
            .await;

        assert_eq!(outcomes, vec![PublishOutcome::Created, PublishOutcome::Created]);
    }

    #[test]
    fn create_request_serializes_with_tr_field_names() {
        let mut value = value("OXYGEN");
        value.field_type = ReferenceFieldType::Authority;
        value.description = Some("desc".to_string());

        assert_eq!(
            serde_json::to_value(value.create_request()).unwrap(),
            serde_json::json!({"id": "did:web:agent", "field_type": "authority", "name": "OXYGEN", "description": "desc"})
        );
    }

    #[test]
    fn issuer_values_include_entity_and_authority() {
        let issuer = issuer("did:web:issuer", Some("did:web:authority"), Some("did:tr"));

        let values = issuer_reference_values(&issuer, Some(&authority("Acme")));

        assert_eq!(values.len(), 2);
        assert_eq!(values[0].field_type, ReferenceFieldType::Entity);
        assert_eq!(values[0].id, "did:web:issuer");
        assert_eq!(values[0].name.as_str(), "Billing Issuer");
        assert_eq!(values[1].field_type, ReferenceFieldType::Authority);
        assert_eq!(values[1].id, "did:web:authority");
        assert_eq!(values[1].name.as_str(), "Acme");
        assert_eq!(
            values[1]
                .description
                .as_deref(),
            Some("Root of trust")
        );
    }

    #[test]
    fn issuer_values_skip_invalid_names() {
        let mut issuer = issuer("did:web:issuer", None, Some("did:tr"));
        issuer.name = "bad\nname".to_string();

        assert!(issuer_reference_values(&issuer, Some(&authority("  "))).is_empty());
    }

    #[test]
    fn registries_for_authority_deduplicates_and_filters() {
        let authority = authority("Acme");
        let mut other_tenant = issuer("did:web:i4", Some("did:web:authority"), Some("did:tr:c"));
        other_tenant.tenant_id = Some("t2".to_string());
        let mut scoped = authority.clone();
        scoped.tenant_id = Some("t1".to_string());
        let issuers = vec![
            issuer("did:web:i1", Some("did:web:authority"), Some("did:tr:a")),
            issuer("did:web:i2", Some("did:web:authority"), Some("did:tr:a")),
            issuer("did:web:i3", Some("did:web:authority"), Some("did:tr:b")),
            issuer("did:web:i5", Some("did:web:other"), Some("did:tr:d")),
            issuer("did:web:i6", Some("did:web:authority"), None),
            other_tenant,
        ];

        assert_eq!(
            registries_for_authority(&authority, &issuers),
            BTreeSet::from(["did:tr:a".to_string(), "did:tr:b".to_string(), "did:tr:c".to_string()])
        );
        assert!(registries_for_authority(&scoped, &issuers).is_empty());
    }

    #[test]
    fn surface_values_name_managed_dids_and_skip_conflicts() {
        let surface = AgentSurface {
            surface_id: "s1".to_string(),
            name: "OXYGEN".to_string(),
            ..Default::default()
        };
        let mut managed = test_surface_identity_record("did:web:managed", "s1");
        managed.origin = Some(IdentityOrigin::Managed);
        let mut shared = test_surface_identity_record("did:web:shared", "s1");
        shared.origin = Some(IdentityOrigin::Managed);
        let mut shared_elsewhere = test_surface_identity_record("did:web:shared", "s2");
        shared_elsewhere.identity_hash = "other".to_string();
        shared_elsewhere.origin = Some(IdentityOrigin::Managed);
        let mut caller = test_surface_identity_record("did:web:caller", "s1");
        caller.origin = Some(IdentityOrigin::ExternalCaller);
        let unrelated = test_surface_identity_record("did:web:unrelated", "s9");

        let values = surface_reference_values(&surface, &[managed, shared, shared_elsewhere, caller, unrelated]);

        assert_eq!(values, vec![ReferenceFieldValue::entity("did:web:managed", DisplayName::parse("OXYGEN").unwrap())]);
    }

    #[test]
    fn surface_values_skip_legacy_records_without_origin() {
        let surface = AgentSurface {
            surface_id: "s1".to_string(),
            name: "OXYGEN".to_string(),
            ..Default::default()
        };
        let mut legacy = test_surface_identity_record("did:web:legacy", "s1");
        legacy.origin = None;
        legacy.is_local = true;
        let mut managed = test_surface_identity_record("did:web:managed", "s1");
        managed.origin = Some(IdentityOrigin::Managed);

        let values = surface_reference_values(&surface, &[legacy, managed]);

        assert_eq!(values, vec![ReferenceFieldValue::entity("did:web:managed", DisplayName::parse("OXYGEN").unwrap())]);
    }
}
