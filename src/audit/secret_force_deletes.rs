//! The record of a secret deleted with `force=true`. It names the actor of the management
//! request it is built in and is written only when a sink selects its event.

use crate::audit::context::current_actor;
use crate::credential_providers::references::Referrer;
use crate::delegation_vault::audit::{
    DelegationAuditAction, SecretForceDeleteDetails, SecretReferrerDetails, action_category, audit_event, emit,
};

/// Records that the secret `secret_id` was force-deleted while `referrers` still used it,
/// listed by kind and id. Writes nothing outside a management request.
pub fn secret_force_deleted(
    secret_id: &str,
    referrers: &[Referrer],
) {
    let Some(actor) = current_actor() else {
        return;
    };
    let mut referrers: Vec<SecretReferrerDetails> = referrers
        .iter()
        .map(|referrer| SecretReferrerDetails {
            kind: referrer
                .kind_label()
                .to_string(),
            id: referrer.id.clone(),
        })
        .collect();
    referrers.sort_by(|a, b| (&a.kind, &a.id).cmp(&(&b.kind, &b.id)));
    let action = DelegationAuditAction::SecretForceDeleted(Box::new(SecretForceDeleteDetails {
        actor,
        secret_id: secret_id.to_string(),
        force: true,
        referrers,
    }));
    emit(action_category(&action), move || audit_event(action, None, None, None, None));
}
