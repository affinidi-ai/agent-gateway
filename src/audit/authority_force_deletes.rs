//! The record of an Authority deleted with `force=true`. It names the actor of the management
//! request it is built in and is written only when a sink selects its event.

use crate::audit::context::current_actor;
use crate::audit::secret_force_deletes::referrer_details;
use crate::authorities::types::Authority;
use crate::credential_providers::references::Referrer;
use crate::delegation_vault::audit::{
    AuthorityForceDeleteDetails, DelegationAuditAction, action_category, audit_event, emit,
};

/// Records that `authority` was force-deleted while `referrers` still used it, listed by
/// kind and id. Writes nothing outside a management request.
pub fn authority_force_deleted(
    authority: &Authority,
    referrers: &[Referrer],
) {
    let Some(actor) = current_actor() else {
        return;
    };
    let action = DelegationAuditAction::AuthorityForceDeleted(Box::new(AuthorityForceDeleteDetails {
        actor,
        authority_id: authority.id.clone(),
        did: authority.did.clone(),
        force: true,
        referrers: referrer_details(referrers),
    }));
    emit(action_category(&action), move || audit_event(action, None, None, None, None));
}
