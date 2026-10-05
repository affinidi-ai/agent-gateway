//! HTTP handlers for certificate endpoints

use super::{CertificateStore, CreateCertificateRequest, UpdateCertificateRequest};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::info;

use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};

fn tenant_context(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(context)| context)
}

fn resource_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(scope)| scope)
}

pub async fn list_certificates(
    State(store): State<Arc<dyn CertificateStore>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("[Certificates] Listing all certificates");
    match store.list_all().await {
        Ok(mut certificates) => {
            let context = tenant_context(&context);
            let scope = resource_scope(&scope);
            certificates.retain(|certificate| {
                can_access(
                    certificate
                        .tenant_id
                        .as_deref(),
                    context,
                ) && scope_allows_resource(scope, context, ResourceKind::Certificates, &certificate.id)
            });
            info!("[Certificates] Found {} certificates", certificates.len());
            Ok(Json(certificates))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub async fn get_certificate(
    State(store): State<Arc<dyn CertificateStore>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("[Certificates] Getting certificate: {}", id);
    match store.get(&id).await {
        Ok(Some(certificate))
            if can_access(
                certificate
                    .tenant_id
                    .as_deref(),
                tenant_context(&context),
            ) && scope_allows_resource(
                resource_scope(&scope),
                tenant_context(&context),
                ResourceKind::Certificates,
                &certificate.id,
            ) =>
        {
            Ok(Json(certificate))
        }
        Ok(Some(_)) => Err((StatusCode::NOT_FOUND, format!("Certificate not found: {id}"))),
        Ok(None) => {
            info!("[Certificates] Certificate not found: {}", id);
            Err((StatusCode::NOT_FOUND, format!("Certificate not found: {}", id)))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub async fn create_certificate(
    State(store): State<Arc<dyn CertificateStore>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut request): Json<CreateCertificateRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    request.tenant_id = tenant_for_create(request.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    let id = uuid::Uuid::new_v4().to_string();
    let certificate_id = uuid::Uuid::new_v4().to_string();
    if !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::Certificates, &id) {
        return Err((StatusCode::FORBIDDEN, "certificate is outside this token's permitted scope".into()));
    }
    crate::config::enforce_add("secrets.certificates")
        .await
        .map_err(|e| (StatusCode::FORBIDDEN, e.message()))?;
    info!("[Certificates] CREATE request received for: {}", request.name);
    match store
        .create_with_ids(request, id, certificate_id)
        .await
    {
        Ok(certificate) => Ok((StatusCode::CREATED, Json(certificate))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub async fn update_certificate(
    State(store): State<Arc<dyn CertificateStore>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<UpdateCertificateRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let existing = store
        .get(&id)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("Certificate not found: {id}")))?;
    if !can_access(existing.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::Certificates, &id)
    {
        return Err((StatusCode::FORBIDDEN, "certificate is outside this token's permitted scope".into()));
    }
    info!("[Certificates] UPDATE request received for: {}", id);
    match store
        .update(&id, request)
        .await
    {
        Ok(certificate) => Ok(Json(certificate)),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub async fn delete_certificate(
    State(store): State<Arc<dyn CertificateStore>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let existing = store
        .get(&id)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("Certificate not found: {id}")))?;
    if !can_access(existing.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::Certificates, &id)
    {
        return Err((StatusCode::FORBIDDEN, "certificate is outside this token's permitted scope".into()));
    }
    info!("[Certificates] DELETE request received for: {}", id);
    match store.delete(&id).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use regex::Regex;

    use super::*;

    struct CountingStore {
        creates: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl CertificateStore for CountingStore {
        async fn list_all(&self) -> Result<Vec<super::super::CertificateListItem>, String> {
            Ok(Vec::new())
        }

        async fn get(
            &self,
            _id: &str,
        ) -> Result<Option<super::super::Certificate>, String> {
            Ok(None)
        }

        async fn create_with_ids(
            &self,
            _request: CreateCertificateRequest,
            _id: String,
            _certificate_id: String,
        ) -> Result<super::super::Certificate, String> {
            self.creates
                .fetch_add(1, Ordering::SeqCst);
            unreachable!()
        }

        async fn update(
            &self,
            _id: &str,
            _request: UpdateCertificateRequest,
        ) -> Result<super::super::Certificate, String> {
            unreachable!()
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> Result<(), String> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn out_of_scope_certificate_is_rejected_before_store_write() {
        let counting_store = Arc::new(CountingStore { creates: AtomicUsize::new(0) });
        let store: Arc<dyn CertificateStore> = counting_store.clone();
        let scope = PatResourceScope(Arc::new(Regex::new(r"\Anever-match\z").unwrap()));
        let request = CreateCertificateRequest {
            tenant_id: None,
            name: "test".into(),
            description: None,
            tags: None,
            kind: Default::default(),
            certificate_pem: "pem".into(),
            private_key_pem: None,
            expires_at: None,
            active: None,
            identity_did: None,
        };

        let result = create_certificate(State(store.clone()), None, None, Some(Extension(scope)), Json(request)).await;

        match result {
            Err((status, _)) => assert_eq!(status, StatusCode::FORBIDDEN),
            Ok(_) => panic!("out-of-scope certificate creation unexpectedly succeeded"),
        }
        assert_eq!(
            counting_store
                .creates
                .load(Ordering::SeqCst),
            0
        );
    }
}
