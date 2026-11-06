use std::collections::HashSet;

use crate::a2a_proxies::A2aProxyStore;
use crate::auth_manager::pat::PatResourceScope;
use crate::config::agent_surface::{AgentSurface, McpToolGatingConfig};
use crate::config::credential_policy::RuleMode;
use crate::config::{CustomMetadata, TargetAuthConfig, TargetAuthMethod};
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::gateways::GatewayStore;
use crate::identity::state::IdentityApiState;
use crate::issuers::IssuerStore;
use crate::mcp_proxies::McpProxyStore;
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::{
    PatTenantContext, ResourceKind, SurfaceTenancy, can_reference, can_reference_with_rule, scope_allows_resource,
};
use crate::trust_registries::TrustRegistryStore;

use super::surfaces::SurfaceApiError;

/// Validates the resources a surface references and the rules its Target authentication
/// must meet. A tenant surface may not send an
/// appliance-wide secret or credential provider upstream or back to its caller, nor the gateway
/// credential of a provider holding a secret outside the provider's tenant: a reference that
/// breaks that rule is refused unless `stored` (the surface as stored, if any) already sent it
/// to every destination that it goes to now, and even then when
/// `tenant_credential_isolation` is `enforce`. An API Key Provider key id `stored` already
/// derived a DID from is kept the same way, and kept even when the key no longer exists.
pub async fn validate_surface_references(
    state: &IdentityApiState,
    surface: &AgentSurface,
    stored: Option<&AgentSurface>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<(), SurfaceApiError> {
    let isolation = crate::config::credential_policy::credential_policy().tenant_credential_isolation;
    let grandfathered = match stored {
        Some(stored) if stored.tenant_id == surface.tenant_id => {
            let mut grandfathered =
                grandfathered_references(&sent_credentials(stored).unwrap_or_default(), &sent_credentials(surface)?);
            grandfathered.extend(
                provider_key_ids(stored)
                    .unwrap_or_default()
                    .all()
                    .map(|key_id| (ResourceKind::ApiKeys, key_id.clone())),
            );
            grandfathered
        }
        _ => Vec::new(),
    };
    let authorizer = ReferenceAuthorizer {
        state,
        owner_tenant_id: surface.tenant_id.as_deref(),
        context,
        scope,
        current_surface_id: &surface.surface_id,
        isolation,
        grandfathered,
    };

    for reference in collect_surface_reference_keys(surface)? {
        if !reference.is_checked_on(surface) {
            continue;
        }
        authorizer
            .validate_reference(&reference)
            .await?;
    }
    authorizer
        .provider_keys(&provider_key_ids(surface)?)
        .await?;
    validate_target_auth_methods(state, surface).await?;
    let https_proxies = super::surface_target_auth::https_mcp_proxies(state).await;
    super::surface_target_auth::validate_target_auth_rules(surface, stored, &https_proxies)
}

pub(crate) const TARGET_AUTH_NEEDS_CONSENT: &str =
    "Target authentication cannot use an oauth2_authorization_code credential provider: it needs a user's consent";

/// The target authentication methods of every Target and Transit Point, in every
/// variant, must be usable: `credential_lookup` was never implemented, and a provider
/// that needs a user's consent cannot authenticate the gateway to its target.
async fn validate_target_auth_methods(
    state: &IdentityApiState,
    surface: &AgentSurface,
) -> Result<(), SurfaceApiError> {
    use crate::credential_providers::CredentialProviderType;

    for view in resolved_views(surface)? {
        let transit_points = view
            .transit
            .iter()
            .flat_map(|transit| transit.points.iter());
        let methods = view
            .target
            .auth
            .iter()
            .chain(transit_points.filter_map(|point| point.target_auth.as_ref()))
            .map(|authentication| &authentication.method);
        for method in methods {
            match method {
                TargetAuthMethod::StaticSecret { .. } => {}
                TargetAuthMethod::CredentialLookup => {
                    return Err(SurfaceApiError::BadRequest(
                        "Target authentication method credential_lookup is not supported; use static_secret or credential_provider".into(),
                    ));
                }
                TargetAuthMethod::CredentialProvider { provider_id, .. } => {
                    let provider = state
                        .credential_provider_store
                        .as_ref()
                        .ok_or_else(|| unavailable("Credential provider"))?
                        .get(provider_id)
                        .await
                        .map_err(|error| internal("Credential provider", error))?
                        .ok_or_else(|| inaccessible("Credential provider"))?;
                    if provider.provider_type == CredentialProviderType::OAuth2AuthorizationCode {
                        return Err(SurfaceApiError::BadRequest(TARGET_AUTH_NEEDS_CONSENT.into()));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Check the credential bindings of a surface, its base and each variant, for
/// external consent:
///
/// - `consent_mode: external` is a Transit Point's `transit_credentials`, or
///   the Access Point Target's binding: the only binding of surface-level
///   `outbound_credentials`, on a surface without Transit Points. A surface
///   with `outbound_credentials` has no Transit Point that says it.
/// - Such a binding names a `subject`, and no other binding does.
/// - Its provider has an issuer and the surface's own tenant, exactly; a
///   provider with an issuer is bound by no other consent mode.
/// - Its Transit Point, or the Target, sends the grants only to the provider's
///   `resource`: a public `https` target with that origin, never a `fabric://`
///   route, and that resource is permitted for the provider's issuer.
/// - The Target's grant goes in a header, in place of the caller's credential
///   and of any `target.auth` credential of the Target's own.
/// - Its Transit Point id names one Transit Point in one place: it appears
///   once, in the surface's own points or in one variant's, and nowhere else;
///   and the Target's binding is held in one place, the surface's
///   `outbound_credentials` or one variant's.
/// - At-rest encryption is active and the identity hash pepper is configured,
///   since its grants are kept only then.
pub async fn validate_external_consent_bindings(
    state: &IdentityApiState,
    surface: &AgentSurface,
) -> Result<(), SurfaceApiError> {
    check_external_consent_bindings(
        state
            .credential_provider_store
            .as_ref(),
        surface,
        GrantStorage {
            encrypted: crate::storage::filesystem::at_rest_encryption_active(),
            stable_ids: crate::identity::credential_identity::pepper_is_configured(),
        },
        &state
            .network_config
            .external_consent_resource_origins,
        state
            .network_config
            .external_consent_issuers
            .as_ref(),
    )
    .await
}

/// Whether the vault can keep grants by binding: it encrypts at rest, and the
/// identity hash pepper their ids derive from is configured, not generated
/// for this process.
#[derive(Clone, Copy)]
struct GrantStorage {
    encrypted: bool,
    stable_ids: bool,
}

async fn check_external_consent_bindings(
    providers: Option<&std::sync::Arc<dyn CredentialProviderStorage>>,
    surface: &AgentSurface,
    storage: GrantStorage,
    resource_origins: &std::collections::HashMap<String, Vec<String>>,
    issuers: Option<&std::collections::HashMap<String, Vec<String>>>,
) -> Result<(), SurfaceApiError> {
    check_external_transit_point_ids(surface)?;
    check_access_point_target_places(surface)?;
    let mut views = vec![(String::new(), surface.clone())];
    for (variant, resolved) in surface.variants.iter().zip(
        resolved_views(surface)?
            .into_iter()
            .skip(1),
    ) {
        views.push((format!("variant '{}' ", variant.alias), resolved));
    }
    let rules = GrantRules {
        providers,
        tenant_id: surface.tenant_id.as_deref(),
        storage,
        resource_origins,
        issuers,
    };
    for (prefix, view) in &views {
        for (index, binding) in view
            .outbound_credentials
            .iter()
            .enumerate()
        {
            let refuse =
                |reason: &str| SurfaceApiError::BadRequest(format!("{prefix}outbound_credentials[{index}]: {reason}"));
            if !binding.is_external() {
                if binding.subject.is_some() {
                    return Err(refuse("subject is set only with consent_mode external"));
                }
                if credential_provider_has_issuer(providers, &binding.credential_provider_id).await? {
                    return Err(refuse("a credential provider with an issuer needs consent_mode external"));
                }
                continue;
            }
            let Some(subject) = binding.subject else {
                return Err(refuse("consent_mode external needs a subject: owner or caller"));
            };
            check_callers(&views, subject).map_err(refuse)?;
            check_access_point_target_binding(view, binding).map_err(refuse)?;
            rules
                .check(&binding.credential_provider_id, &view.target.endpoint, &refuse)
                .await?;
        }
        for (index, point) in view
            .transit_points()
            .iter()
            .enumerate()
        {
            let Some(binding) = point
                .transit_credentials
                .as_ref()
            else {
                continue;
            };
            let refuse = |reason: &str| {
                SurfaceApiError::BadRequest(format!("{prefix}transit.points[{index}].transit_credentials: {reason}"))
            };
            if !binding.is_external() {
                if binding.subject.is_some() {
                    return Err(refuse("subject is set only with consent_mode external"));
                }
                if credential_provider_has_issuer(providers, &binding.credential_provider_id).await? {
                    return Err(refuse("a credential provider with an issuer needs consent_mode external"));
                }
                continue;
            }
            let Some(subject) = binding.subject else {
                return Err(refuse("consent_mode external needs a subject: owner or caller"));
            };
            check_callers(&views, subject).map_err(refuse)?;
            if !view
                .outbound_credentials
                .is_empty()
            {
                return Err(refuse(
                    "consent_mode external cannot be used on a surface with outbound_credentials, which apply on \
                     every Transit Point",
                ));
            }
            if point.presents_the_agent() {
                return Err(refuse(
                    "consent_mode external sends the vendor no presentation of the agent: turn off the Transit \
                     Point's identity_injection.inject_vp and workload_binding, and remove its managed_identity",
                ));
            }
            rules
                .check(&binding.credential_provider_id, &point.target_endpoint, &refuse)
                .await?;
        }
    }
    check_inherited_owner_binding(surface, &views)
}

/// Every caller of an owner binding acts as the owner, so a variant that keeps
/// the surface's `outbound_credentials`, and with them the Access Point
/// Target's owner binding, keeps what of the surface's chooses those callers:
/// its caller authentication, its Access Point's `inbound_policy` and
/// `trust_check_list`, and its Target's `policy`. One of its own could let
/// through callers the surface's would not, and which is wider cannot be told,
/// so any other is refused, in every variant, enabled or not. The Target's own
/// `trust_check_list` is not among them: it applies to `a2a-proxy://` and
/// Fabric targets, never to the `https` Target such a binding has.
fn check_inherited_owner_binding(
    surface: &AgentSurface,
    views: &[(String, AgentSurface)],
) -> Result<(), SurfaceApiError> {
    if !surface
        .target_external_credentials()
        .is_some_and(|binding| binding.subject == Some(crate::config::agent_surface::GrantSubject::Owner))
    {
        return Ok(());
    }
    let held = |view: &AgentSurface| {
        [
            (
                "access_point.caller_authentication",
                "caller authentication",
                serde_json::to_value(
                    &view
                        .access_point
                        .caller_authentication,
                )
                .ok(),
            ),
            (
                "access_point.inbound_policy",
                "inbound policy",
                serde_json::to_value(
                    &view
                        .access_point
                        .inbound_policy,
                )
                .ok(),
            ),
            ("target.policy", "Target policy", serde_json::to_value(&view.target.policy).ok()),
            (
                "access_point.trust_check_list",
                "caller trust checks",
                serde_json::to_value(
                    &view
                        .access_point
                        .trust_check_list,
                )
                .ok(),
            ),
        ]
    };
    let surfaces = held(surface);
    for (variant, (prefix, view)) in surface
        .variants
        .iter()
        .zip(views.iter().skip(1))
    {
        if variant
            .overrides
            .outbound_credentials
            .is_some()
        {
            continue;
        }
        if let Some((field, name, _)) = held(view)
            .into_iter()
            .zip(&surfaces)
            .find_map(|(variants, surfaces)| (variants.2 != surfaces.2).then_some(variants))
        {
            return Err(SurfaceApiError::BadRequest(format!(
                "{prefix}overrides.{field}: a variant that keeps the Access Point Target's owner binding keeps the \
                 surface's {name}, since every caller it lets through acts as the owner; keep the surface's, or \
                 give the variant outbound_credentials of its own"
            )));
        }
    }
    Ok(())
}

/// The callers of a surface, in any of its views, are authenticated by
/// something the gateway can check, as every `consent_mode: external` binding
/// for `subject` needs ([`crate::proxy::target_grant::unchecked_callers`]). A
/// caller of one view's Access Point may hold a transit token any Transit
/// Point of the surface takes, so every view's callers count.
fn check_callers(
    views: &[(String, AgentSurface)],
    subject: crate::config::agent_surface::GrantSubject,
) -> Result<(), &'static str> {
    match views
        .iter()
        .find_map(|(_, view)| crate::proxy::target_grant::unchecked_callers(view, subject))
    {
        Some(unchecked) => Err(unchecked.refusal()),
        None => Ok(()),
    }
}

/// What every `consent_mode: external` binding needs, wherever it is.
struct GrantRules<'a> {
    providers: Option<&'a std::sync::Arc<dyn CredentialProviderStorage>>,
    tenant_id: Option<&'a str>,
    storage: GrantStorage,
    resource_origins: &'a std::collections::HashMap<String, Vec<String>>,
    issuers: Option<&'a std::collections::HashMap<String, Vec<String>>>,
}

impl GrantRules<'_> {
    /// The vault can keep the binding's grants, and its provider, of the
    /// surface's own tenant and with an issuer, sends them only to
    /// `destination`, the origin of its permitted `resource`, under an issuer
    /// the operator permits.
    async fn check(
        &self,
        provider_id: &str,
        destination: &str,
        refuse: &(dyn Fn(&str) -> SurfaceApiError + Sync),
    ) -> Result<(), SurfaceApiError> {
        if !self.storage.encrypted {
            return Err(refuse(
                "consent_mode external needs at-rest encryption: enable [encryption] with a key from the \
                 environment, a file or AWS KMS",
            ));
        }
        if !self.storage.stable_ids {
            return Err(refuse(
                "consent_mode external needs a configured identity hash pepper: set AG_IDENTITY_HASH_PEPPER, the \
                 same on every node, since grant ids derive from it",
            ));
        }
        let provider = self
            .providers
            .ok_or_else(|| unavailable("Credential provider"))?
            .get(provider_id)
            .await
            .map_err(|error| internal("Credential provider", error))?
            .ok_or_else(|| inaccessible("Credential provider"))?;
        if !provider.is_external_consent() {
            return Err(refuse("consent_mode external needs a credential provider with an issuer"));
        }
        if provider.tenant_id.as_deref() != self.tenant_id {
            return Err(refuse("consent_mode external needs a credential provider of the surface's own tenant"));
        }
        crate::credential_providers::external::check_grant_destination(&provider, destination, None)
            .await
            .map_err(refuse)?;
        if !crate::credential_providers::external::resource_permitted(&provider, self.resource_origins) {
            return Err(refuse(
                "the credential provider's resource is not permitted for its issuer: on the issuer's host or one of \
                 its subdomains, or listed for the issuer in the gateway's external_consent_resource_origins",
            ));
        }
        if let Err(field) = crate::credential_providers::external::issuer_permitted(&provider, self.issuers) {
            return Err(refuse(&format!(
                "the credential provider's {field} is not permitted by the gateway's external_consent_issuers"
            )));
        }
        Ok(())
    }
}

/// The Access Point Target's `consent_mode: external` binding sends the
/// grant, in a header, in place of every other credential: it is the only
/// binding of `outbound_credentials`, which would otherwise apply on every
/// Transit Point too, so the surface has none; and neither the caller's
/// credential (`forward_header`) nor a `target.auth` credential of the
/// Target's own goes with it.
fn check_access_point_target_binding(
    view: &AgentSurface,
    binding: &crate::config::types::OutboundCredentialBinding,
) -> Result<(), &'static str> {
    crate::proxy::target_grant::target_binding_violation(view, binding)
        .map_or(Ok(()), |violation| Err(violation.refusal()))
}

/// The Access Point Target's `consent_mode: external` binding is held in one
/// place: the surface's `outbound_credentials` or one variant's. Its grants
/// are kept under the hop `target`, so they are used only under that one
/// place's settings, never under another variant's copy of the binding. A
/// variant that keeps the surface's `outbound_credentials` serves the
/// surface's binding.
fn check_access_point_target_places(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    let places = std::iter::once((
        String::new(),
        Some(
            surface
                .outbound_credentials
                .as_slice(),
        ),
    ))
    .chain(
        surface
            .variants
            .iter()
            .map(|variant| {
                (
                    format!("variant '{}' ", variant.alias),
                    variant
                        .overrides
                        .outbound_credentials
                        .as_deref(),
                )
            }),
    );
    let mut held = false;
    for (prefix, bindings) in places {
        let Some(index) = bindings
            .unwrap_or_default()
            .iter()
            .position(crate::config::types::OutboundCredentialBinding::is_external)
        else {
            continue;
        };
        if held {
            return Err(SurfaceApiError::BadRequest(format!(
                "{prefix}outbound_credentials[{index}]: the Access Point Target's consent_mode external binding is \
                 held in more than one place, the surface's outbound_credentials and a variant's, or two variants'; \
                 its grants are kept under the hop `{}` and used under one place's settings, so keep it in one",
                crate::delegation_vault::grants::ACCESS_POINT_TARGET_HOP
            )));
        }
        held = true;
    }
    Ok(())
}

/// The surface's lists of Transit Points as stored: its own, then each
/// variant's replacement list, with the prefix that names each in a refusal. A
/// resolved view's points are always one of these lists.
pub(crate) fn transit_point_lists(
    surface: &AgentSurface
) -> Vec<(String, &[crate::config::agent_surface::TransitPoint])> {
    let mut lists = vec![(String::new(), surface.transit_points())];
    for variant in &surface.variants {
        if let Some(points) = variant
            .overrides
            .transit
            .as_ref()
            .and_then(|transit| transit.points.as_deref())
        {
            lists.push((format!("variant '{}' ", variant.alias), points));
        }
    }
    lists
}

/// Every credential provider the surface binds or authenticates its targets
/// with, in its base or any variant: its credential bindings, and the
/// `credential_provider` target authentication of its Target and Transit
/// Points. Read from the stored lists without resolving the variants, so a
/// surface whose variants cannot be resolved still names the providers it
/// uses.
pub(crate) fn bound_credential_provider_ids(surface: &AgentSurface) -> HashSet<&str> {
    let outbound = surface
        .outbound_credentials
        .iter()
        .chain(
            surface
                .variants
                .iter()
                .filter_map(|variant| {
                    variant
                        .overrides
                        .outbound_credentials
                        .as_ref()
                })
                .flatten(),
        )
        .map(|binding| {
            binding
                .credential_provider_id
                .as_str()
        });
    let points: Vec<&crate::config::agent_surface::TransitPoint> = transit_point_lists(surface)
        .into_iter()
        .flat_map(|(_, points)| points.iter())
        .collect();
    let transit = points
        .iter()
        .filter_map(|point| {
            point
                .transit_credentials
                .as_ref()
        })
        .map(|binding| {
            binding
                .credential_provider_id
                .as_str()
        });
    let target_auth = surface
        .target
        .auth
        .iter()
        .chain(
            surface
                .variants
                .iter()
                .filter_map(|variant| {
                    variant
                        .overrides
                        .target
                        .as_ref()
                        .and_then(|target| target.auth.as_ref())
                }),
        )
        .chain(
            points
                .iter()
                .filter_map(|point| point.target_auth.as_ref()),
        )
        .filter_map(|authentication| match &authentication.method {
            TargetAuthMethod::CredentialProvider { provider_id, .. } => Some(provider_id.as_str()),
            _ => None,
        });
    outbound
        .chain(transit)
        .chain(target_auth)
        .collect()
}

/// The hop that names the grants of a surface's Access Point Target, which no
/// Transit Point with `consent_mode: external` may take as its id: its grants
/// are kept under its id, and would share the Target's.
pub(crate) const RESERVED_TARGET_HOP: &str = crate::delegation_vault::grants::ACCESS_POINT_TARGET_HOP;

/// A Transit Point id with a `consent_mode: external` binding anywhere in the
/// surface names one Transit Point in one place: it appears once, in the
/// surface's own list or in one variant's, and in no other list, whatever its
/// target or binding there. Its grants are kept under that id, so they are
/// used only under that one Transit Point's settings, never under another
/// variant's copy of it.
pub(super) fn check_external_transit_point_ids(surface: &AgentSurface) -> Result<(), SurfaceApiError> {
    let lists = transit_point_lists(surface);
    let external: HashSet<&str> = lists
        .iter()
        .flat_map(|(_, points)| points.iter())
        .filter(|point| {
            point
                .transit_credentials
                .as_ref()
                .is_some_and(|binding| binding.is_external())
        })
        .map(|point| point.id.as_str())
        .collect();
    let mut placed: HashSet<&str> = HashSet::new();
    for (prefix, points) in &lists {
        let mut seen = HashSet::new();
        for (index, point) in points.iter().enumerate() {
            let binds_externally = point
                .transit_credentials
                .as_ref()
                .is_some_and(|binding| binding.is_external());
            if binds_externally && point.id.is_empty() {
                return Err(SurfaceApiError::BadRequest(format!(
                    "{prefix}transit.points[{index}]: a Transit Point with consent_mode external needs an id, which \
                     its grants are kept under"
                )));
            }
            if !external.contains(point.id.as_str()) {
                continue;
            }
            if point.id == RESERVED_TARGET_HOP {
                return Err(SurfaceApiError::BadRequest(format!(
                    "{prefix}transit.points[{index}]: the id `{RESERVED_TARGET_HOP}` is reserved for the grants of \
                     the surface's Access Point Target; give the Transit Point with consent_mode external another id"
                )));
            }
            if !seen.insert(point.id.as_str()) {
                return Err(SurfaceApiError::BadRequest(format!(
                    "{prefix}transit.points[{index}]: the id of a Transit Point with consent_mode external is used \
                     twice; give each Transit Point an id of its own"
                )));
            }
            if !placed.insert(point.id.as_str()) {
                return Err(SurfaceApiError::BadRequest(format!(
                    "{prefix}transit.points[{index}]: the id of a Transit Point with consent_mode external is used in \
                     more than one place, the surface's Transit Points and a variant's, or two variants'; its grants \
                     are kept under its id and used under one Transit Point's settings, so give each place's Transit \
                     Point an id of its own"
                )));
            }
        }
    }
    Ok(())
}

async fn credential_provider_has_issuer(
    providers: Option<&std::sync::Arc<dyn CredentialProviderStorage>>,
    id: &str,
) -> Result<bool, SurfaceApiError> {
    let Some(store) = providers else {
        return Ok(false);
    };
    Ok(store
        .get(id)
        .await
        .map_err(|error| internal("Credential provider", error))?
        .is_some_and(|provider| provider.is_external_consent()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SurfaceReferenceKey {
    pub kind: ResourceKind,
    pub id: String,
    /// A secret a tenant surface sends upstream, which must not be appliance-wide.
    pub same_tenant: bool,
    /// Named only by `$SECRET:` helpers in custom metadata. A surface with no tenant may name
    /// any secret there, even one that does not exist.
    pub custom_metadata: bool,
}

impl SurfaceReferenceKey {
    /// Whether a save of `surface` checks this reference: every one but a `custom_metadata`
    /// one of a surface with no tenant.
    fn is_checked_on(
        &self,
        surface: &AgentSurface,
    ) -> bool {
        !(self.custom_metadata && surface.tenant_id.is_none())
    }
}

/// The secrets a save of `surface` requires to exist.
pub(crate) fn checked_secret_ids(surface: &AgentSurface) -> Result<Vec<String>, SurfaceApiError> {
    Ok(collect_surface_reference_keys(surface)?
        .into_iter()
        .filter(|reference| reference.kind == ResourceKind::Secrets && reference.is_checked_on(surface))
        .map(|reference| reference.id)
        .collect())
}

pub(crate) fn collect_surface_reference_keys(
    surface: &AgentSurface
) -> Result<Vec<SurfaceReferenceKey>, SurfaceApiError> {
    let mut references = Vec::new();
    if let Some(issuer_id) = surface.issuer_id.as_deref() {
        push_reference(&mut references, ResourceKind::Issuers, issuer_id);
    }
    for effective in resolved_views(surface)? {
        collect_effective_surface_references(&effective, &mut references);
    }
    references.sort_by(|left, right| {
        left.kind
            .as_str()
            .cmp(right.kind.as_str())
            .then_with(|| left.id.cmp(&right.id))
    });
    references.dedup_by(|later, kept| {
        let duplicate = later.kind == kept.kind && later.id == kept.id;
        if duplicate {
            kept.same_tenant |= later.same_tenant;
            kept.custom_metadata &= later.custom_metadata;
        }
        duplicate
    });
    Ok(references)
}

/// Where a credential goes: a leg's endpoint, or the caller, which receives response custom
/// metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Destination {
    Endpoint(String),
    Caller,
}

/// A credential a surface sends, with the leg that sends it: the Target, or a Transit Point
/// by `id`, of the base surface or of a variant by `id`, and where it goes. Ids, not aliases
/// or positions, name the legs, so renaming or reordering variants and Transit Points keeps
/// them. `sent` is false for a secret named only by disabled custom metadata, which the
/// surface holds but does not send.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SentCredential {
    variant_id: Option<String>,
    transit_point_id: Option<String>,
    destination: Destination,
    kind: ResourceKind,
    id: String,
    sent: bool,
}

impl SentCredential {
    fn held_by(
        &self,
        stored: &SentCredential,
    ) -> bool {
        self.variant_id == stored.variant_id
            && self.transit_point_id == stored.transit_point_id
            && self.destination == stored.destination
            && self.kind == stored.kind
            && self.id == stored.id
            && (stored.sent || !self.sent)
    }
}

/// Every Target authentication secret or provider, every `outbound_credentials` or
/// `transit_credentials` provider and every custom metadata secret, on each leg that sends
/// it, or would send it once its disabled custom metadata is enabled. A surface's
/// `outbound_credentials` are sent on its Target and on each of its Transit Points; the
/// Target's custom metadata goes to the Target's endpoint, the shared transit custom metadata
/// to each Transit Point's, and both response custom metadata to the caller.
fn sent_credentials(surface: &AgentSurface) -> Result<Vec<SentCredential>, SurfaceApiError> {
    let variant_ids = std::iter::once(None).chain(
        surface
            .variants
            .iter()
            .map(|variant| Some(variant.id.clone())),
    );
    let mut sent = Vec::new();
    for (variant_id, view) in variant_ids.zip(resolved_views(surface)?) {
        let bindings = view
            .outbound_credentials
            .iter()
            .map(|binding| {
                binding
                    .credential_provider_id
                    .as_str()
            });
        let mut legs = vec![(
            None,
            Destination::Endpoint(view.target.endpoint.clone()),
            view.target.auth.as_ref(),
            None,
            vec![
                view.target
                    .custom_metadata
                    .as_ref(),
            ],
        )];
        legs.extend(
            view.transit
                .iter()
                .flat_map(|transit| transit.points.iter())
                .map(|point| {
                    (
                        Some(point.id.as_str()),
                        Destination::Endpoint(point.target_endpoint.clone()),
                        point.target_auth.as_ref(),
                        point
                            .transit_credentials
                            .as_ref()
                            .map(|credentials| {
                                credentials
                                    .credential_provider_id
                                    .as_str()
                            }),
                        vec![transit_metadata(&view)],
                    )
                }),
        );
        legs.push((None, Destination::Caller, None, None, response_metadata(&view).to_vec()));
        for (transit_point_id, destination, authentication, transit_provider, metadata) in legs {
            let mut references = Vec::new();
            let mut held = Vec::new();
            collect_target_auth_reference(authentication, &mut references);
            for metadata in metadata.into_iter().flatten() {
                let references = if metadata.enabled {
                    &mut references
                } else {
                    &mut held
                };
                collect_custom_metadata_references(Some(metadata), references);
            }
            for id in bindings
                .clone()
                .chain(transit_provider)
                .filter(|_| destination != Destination::Caller)
            {
                push_reference(&mut references, ResourceKind::CredentialProviders, id);
            }
            sent.extend(
                references
                    .into_iter()
                    .map(|reference| (reference, true))
                    .chain(
                        held.into_iter()
                            .map(|reference| (reference, false)),
                    )
                    .map(|(reference, is_sent)| SentCredential {
                        variant_id: variant_id.clone(),
                        transit_point_id: transit_point_id.map(str::to_string),
                        destination: destination.clone(),
                        kind: reference.kind,
                        id: reference.id,
                        sent: is_sent,
                    }),
            );
        }
    }
    Ok(sent)
}

/// The references `saved` keeps from `stored`: those that every leg of `saved` sending them
/// already sent, to the same destination, in `stored`. A reference that `saved` names only
/// in disabled custom metadata needs `stored` only to have held it there, sent or not.
fn grandfathered_references(
    stored: &[SentCredential],
    saved: &[SentCredential],
) -> Vec<(ResourceKind, String)> {
    let mut grandfathered: Vec<(ResourceKind, String)> = Vec::new();
    for credential in saved {
        let key = (credential.kind, credential.id.clone());
        if !grandfathered.contains(&key)
            && saved
                .iter()
                .filter(|other| other.kind == credential.kind && other.id == credential.id)
                .all(|other| {
                    stored
                        .iter()
                        .any(|held| other.held_by(held))
                })
        {
            grandfathered.push(key);
        }
    }
    grandfathered
}

pub(crate) fn resolved_views(surface: &AgentSurface) -> Result<Vec<AgentSurface>, SurfaceApiError> {
    let mut views = vec![surface.clone()];
    for variant in &surface.variants {
        let mut resolvable = surface.clone();
        if let Some(candidate) = resolvable
            .variants
            .iter_mut()
            .find(|candidate| candidate.id == variant.id)
        {
            candidate.enabled = true;
        }
        let resolved = resolvable
            .resolve_variant(Some(&variant.alias))
            .map_err(|error| {
                SurfaceApiError::BadRequest(format!(
                    "Variant '{}' references could not be resolved: {}",
                    variant.alias, error
                ))
            })?;
        views.push(resolved);
    }
    Ok(views)
}

struct ReferenceAuthorizer<'a> {
    state: &'a IdentityApiState,
    owner_tenant_id: Option<&'a str>,
    context: Option<&'a PatTenantContext>,
    scope: Option<&'a PatResourceScope>,
    current_surface_id: &'a str,
    isolation: RuleMode,
    grandfathered: Vec<(ResourceKind, String)>,
}

impl ReferenceAuthorizer<'_> {
    fn rule_for(
        &self,
        kind: ResourceKind,
        id: &str,
    ) -> RuleMode {
        reference_rule(&self.grandfathered, self.isolation, kind, id)
    }

    async fn validate_reference(
        &self,
        reference: &SurfaceReferenceKey,
    ) -> Result<(), SurfaceApiError> {
        match reference.kind {
            ResourceKind::Issuers => {
                self.issuer(&reference.id)
                    .await
            }
            ResourceKind::PolicyDefinitions => {
                self.policy(&reference.id)
                    .await
            }
            ResourceKind::Secrets => self.secret(reference).await,
            ResourceKind::Certificates => {
                self.certificate(&reference.id)
                    .await
            }
            ResourceKind::JwtVerificationStrategies => {
                self.jwt_strategy(&reference.id)
                    .await
            }
            ResourceKind::CredentialProviders => {
                self.credential_provider(&reference.id)
                    .await
            }
            ResourceKind::McpProxies => {
                self.mcp_proxy(&reference.id)
                    .await
            }
            ResourceKind::A2aProxies => {
                self.a2a_proxy(&reference.id)
                    .await
            }
            ResourceKind::Gateways => {
                self.gateway(&reference.id)
                    .await
            }
            ResourceKind::TrustRegistries => {
                self.trust_registry(&reference.id)
                    .await
            }
            ResourceKind::ApiKeys => {
                self.api_key_parent(&reference.id, &reference.id)
                    .await
            }
            _ => Err(SurfaceApiError::InternalError(format!("Unsupported Surface reference kind: {}", reference.kind))),
        }
    }

    fn ensure(
        &self,
        resource_tenant_id: Option<&str>,
        kind: ResourceKind,
        id: &str,
        label: &str,
    ) -> Result<(), SurfaceApiError> {
        if !can_reference(self.owner_tenant_id, resource_tenant_id)
            || !scope_allows_resource(self.scope, self.context, kind, id)
        {
            return Err(inaccessible(label));
        }
        Ok(())
    }

    async fn issuer(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .issuer_store
            .as_ref()
            .ok_or_else(|| unavailable("Issuer"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("Issuer", error))?
            .ok_or_else(|| inaccessible("Issuer"))?;
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::Issuers, &resource.id, "Issuer")
    }

    async fn policy(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .policy_definition_store
            .as_ref()
            .ok_or_else(|| unavailable("Policy definition"))?;
        let resource = store
            .get(id)
            .await
            .ok_or_else(|| inaccessible("Policy definition"))?;
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::PolicyDefinitions, &resource.id, "Policy definition")
    }

    async fn secret(
        &self,
        reference: &SurfaceReferenceKey,
    ) -> Result<(), SurfaceApiError> {
        let id = reference.id.as_str();
        let store = self
            .state
            .secrets_store
            .as_ref()
            .ok_or_else(|| unavailable("Secret"))?;
        let Some(resource) = store
            .get_by_secret_id(id)
            .await
            .map_err(|error| internal("Secret", error))?
        else {
            return Err(inaccessible("Secret"));
        };
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::Secrets, &resource.secret_id, "Secret")?;
        if reference.same_tenant
            && !can_reference_with_rule(
                self.owner_tenant_id,
                resource.tenant_id.as_deref(),
                self.rule_for(ResourceKind::Secrets, id),
            )
        {
            return Err(inaccessible("Secret"));
        }
        Ok(())
    }

    async fn certificate(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .certificate_store
            .as_ref()
            .ok_or_else(|| unavailable("Certificate"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("Certificate", error))?
            .ok_or_else(|| inaccessible("Certificate"))?;
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::Certificates, &resource.id, "Certificate")
    }

    async fn jwt_strategy(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .jwt_verification_strategy_store
            .as_ref()
            .ok_or_else(|| unavailable("JWT verification strategy"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("JWT verification strategy", error))?
            .ok_or_else(|| inaccessible("JWT verification strategy"))?;
        self.ensure(
            resource.tenant_id.as_deref(),
            ResourceKind::JwtVerificationStrategies,
            &resource.id,
            "JWT verification strategy",
        )
    }

    async fn credential_provider(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .credential_provider_store
            .as_ref()
            .ok_or_else(|| unavailable("Credential provider"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("Credential provider", error))?
            .ok_or_else(|| inaccessible("Credential provider"))?;
        let tenancy = SurfaceTenancy {
            tenant_id: self.owner_tenant_id,
            mode: self.rule_for(ResourceKind::CredentialProviders, id),
        };
        if !resource.usable_by(tenancy)
            || self
                .sends_secret_outside_provider_tenant(&resource, tenancy.mode)
                .await?
        {
            return Err(inaccessible("Credential provider"));
        }
        self.ensure(
            resource.tenant_id.as_deref(),
            ResourceKind::CredentialProviders,
            &resource.id,
            "Credential provider",
        )
    }

    /// Would a tenant surface send the gateway credential of a provider holding a secret outside
    /// the provider's tenant, under `mode`, the provider reference's rule on this surface?
    async fn sends_secret_outside_provider_tenant(
        &self,
        provider: &crate::credential_providers::CredentialProvider,
        mode: RuleMode,
    ) -> Result<bool, SurfaceApiError> {
        if self.owner_tenant_id.is_none()
            || !mode.is_enforced()
            || !provider
                .provider_type
                .sends_gateway_credential()
        {
            return Ok(false);
        }
        let references = provider.secret_refs();
        if references.is_empty() {
            return Ok(false);
        }
        let store = self
            .state
            .secrets_store
            .as_ref()
            .ok_or_else(|| unavailable("Secret"))?;
        let mut tenants = Vec::with_capacity(references.len());
        for secret_ref in references {
            if let Some(secret) = store
                .get_by_secret_id(secret_ref)
                .await
                .map_err(|error| internal("Secret", error))?
            {
                tenants.push((secret_ref, secret.tenant_id));
            }
        }
        let secret_tenants = tenants
            .iter()
            .map(|(secret_ref, tenant)| (*secret_ref, tenant.as_deref()))
            .collect();
        Ok(provider.uses_secret_outside_tenant(&secret_tenants))
    }

    async fn mcp_proxy(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .mcp_proxy_store
            .as_ref()
            .ok_or_else(|| unavailable("MCP proxy"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("MCP proxy", error))?
            .ok_or_else(|| inaccessible("MCP proxy"))?;
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::McpProxies, &resource.id, "MCP proxy")
    }

    async fn a2a_proxy(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .a2a_proxy_store
            .as_ref()
            .ok_or_else(|| unavailable("A2A proxy"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("A2A proxy", error))?
            .ok_or_else(|| inaccessible("A2A proxy"))?;
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::A2aProxies, &resource.id, "A2A proxy")
    }

    async fn gateway(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .gateway_store
            .as_ref()
            .ok_or_else(|| unavailable("Gateway"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("Gateway", error))?
            .ok_or_else(|| inaccessible("Gateway"))?;
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::Gateways, &resource.id, "Gateway")
    }

    async fn trust_registry(
        &self,
        id: &str,
    ) -> Result<(), SurfaceApiError> {
        let store = self
            .state
            .trust_registry_store
            .as_ref()
            .ok_or_else(|| unavailable("Trust Registry"))?;
        let resource = store
            .get(id)
            .await
            .map_err(|error| internal("Trust Registry", error))?
            .ok_or_else(|| inaccessible("Trust Registry"))?;
        self.ensure(resource.tenant_id.as_deref(), ResourceKind::TrustRegistries, &resource.id, "Trust Registry")
    }

    /// The surface `id` owning API keys must be one this surface may reference, and `scope_id`,
    /// the surface id or a key id, must match the token's API key pattern.
    async fn api_key_parent(
        &self,
        id: &str,
        scope_id: &str,
    ) -> Result<(), SurfaceApiError> {
        let tenant_id = self
            .api_key_parent_tenant(id)
            .await?
            .ok_or_else(|| inaccessible("API-key parent Surface"))?;
        self.ensure(tenant_id.as_deref(), ResourceKind::ApiKeys, scope_id, "API-key parent Surface")
    }

    /// The tenant of the surface `id` owning API keys, or `None` when that surface no longer
    /// exists.
    async fn api_key_parent_tenant(
        &self,
        id: &str,
    ) -> Result<Option<Option<String>>, SurfaceApiError> {
        if id == self.current_surface_id {
            return Ok(Some(
                self.owner_tenant_id
                    .map(str::to_string),
            ));
        }
        let store = self
            .state
            .agent_surface_store
            .as_ref()
            .ok_or_else(|| unavailable("API-key parent Surface"))?;
        Ok(store
            .get(id)
            .await
            .map_err(|error| internal("API-key parent Surface", error))?
            .map(|surface| surface.tenant_id))
    }

    /// A provider key a surface derives a DID from must exist and have an owning surface, unless
    /// the stored surface already named it, and that owning surface must be one this surface may
    /// reference. A tenant surface names a key of a surface with no tenant only as it sends an
    /// appliance-wide secret upstream. A surface names only its own keys: another surface's key
    /// the stored surface already named is kept under `warn`. The token's API key pattern must
    /// match every key id.
    async fn provider_keys(
        &self,
        ids: &ProviderKeyIds,
    ) -> Result<(), SurfaceApiError> {
        if ids.is_empty() {
            return Ok(());
        }
        let owners = provider_key_owners(self.state).await?;
        for secret_id in &ids.legacy_secrets {
            self.legacy_secret(secret_id, &owners)
                .await?;
        }
        for key_id in &ids.keys {
            let kept = is_grandfathered(&self.grandfathered, ResourceKind::ApiKeys, key_id);
            if !scope_allows_resource(self.scope, self.context, ResourceKind::ApiKeys, key_id) {
                return Err(inaccessible("API-key parent Surface"));
            }
            let Some(surface_ids) = owners.get(key_id) else {
                if kept {
                    continue;
                }
                return Err(inaccessible("API key"));
            };
            let rule = self.rule_for(ResourceKind::ApiKeys, key_id);
            for surface_id in surface_ids {
                let Some(tenant_id) = self
                    .api_key_parent_tenant(surface_id)
                    .await?
                else {
                    if kept {
                        continue;
                    }
                    return Err(inaccessible("API-key parent Surface"));
                };
                if !can_reference_with_rule(self.owner_tenant_id, tenant_id.as_deref(), rule) {
                    return Err(inaccessible("API-key parent Surface"));
                }
                if surface_id != self.current_surface_id && rule.is_enforced() {
                    return Err(another_surfaces_key(key_id));
                }
            }
        }
        Ok(())
    }

    /// A Caller Context API Key `secret_id` shaped like a key id, on a view whose inbound
    /// Identity is From API Key, shares the DID of a key of that id. A new one is refused when
    /// that key belongs to another surface; one the stored surface already named is kept under
    /// `warn`. An id no key has stays a plain secret.
    async fn legacy_secret(
        &self,
        secret_id: &str,
        owners: &std::collections::HashMap<String, Vec<String>>,
    ) -> Result<(), SurfaceApiError> {
        let rule = self.rule_for(ResourceKind::ApiKeys, secret_id);
        for surface_id in owners
            .get(secret_id)
            .into_iter()
            .flatten()
        {
            let Some(tenant_id) = self
                .api_key_parent_tenant(surface_id)
                .await?
            else {
                continue;
            };
            let breaks = !can_reference(self.owner_tenant_id, tenant_id.as_deref())
                || crate::tenancy::breaks_tenant_isolation(self.owner_tenant_id, tenant_id.as_deref());
            if breaks && rule.is_enforced() {
                return Err(inaccessible("API-key parent Surface"));
            }
            if surface_id != self.current_surface_id && rule.is_enforced() {
                return Err(another_surfaces_key(secret_id));
            }
        }
        Ok(())
    }
}

/// How strictly a reference is held to tenant isolation: one the save keeps from the stored
/// surface (`grandfathered`) is held only to `isolation`, any other is held to `enforce`.
fn reference_rule(
    grandfathered: &[(ResourceKind, String)],
    isolation: RuleMode,
    kind: ResourceKind,
    id: &str,
) -> RuleMode {
    if is_grandfathered(grandfathered, kind, id) {
        isolation
    } else {
        RuleMode::Enforce
    }
}

fn is_grandfathered(
    grandfathered: &[(ResourceKind, String)],
    kind: ResourceKind,
    id: &str,
) -> bool {
    grandfathered
        .iter()
        .any(|(stored_kind, stored_id)| *stored_kind == kind && stored_id == id)
}

fn collect_effective_surface_references(
    surface: &AgentSurface,
    references: &mut Vec<SurfaceReferenceKey>,
) {
    let mut policy_ids = HashSet::new();
    collect_policy_ids(surface, &mut policy_ids);
    for id in policy_ids {
        push_reference(references, ResourceKind::PolicyDefinitions, id);
    }

    for trust_check in surface
        .access_point
        .trust_check_list
        .iter()
        .chain(
            surface
                .target
                .trust_check_list
                .iter(),
        )
    {
        push_reference(references, ResourceKind::TrustRegistries, &trust_check.trust_registry_id);
    }
    if let Some(trust_recorder) = surface
        .access_point
        .trust_recorder
        .as_ref()
    {
        for entry in &trust_recorder.entries {
            push_reference(references, ResourceKind::TrustRegistries, &entry.trust_registry_id);
        }
    }

    if let Some(authentication) = surface
        .access_point
        .caller_authentication
        .as_ref()
    {
        for method in &authentication.methods {
            collect_source_auth_references(method, references);
        }
    }
    if let Some(source_auth) = surface
        .transit
        .as_ref()
        .and_then(|transit| {
            transit
                .shared
                .source_auth
                .as_ref()
        })
    {
        collect_source_auth_references(source_auth, references);
    }

    collect_target_auth_reference(surface.target.auth.as_ref(), references);
    for metadata in std::iter::once(
        surface
            .target
            .custom_metadata
            .as_ref(),
    )
    .chain(response_metadata(surface))
    {
        collect_custom_metadata_references(metadata, references);
    }
    collect_identity_injection_references(
        &surface
            .target
            .identity_injection,
        references,
    );
    for identity in [
        surface
            .identity_slots
            .inbound
            .as_ref(),
        surface
            .identity_slots
            .protected
            .as_ref(),
        surface
            .identity_slots
            .external
            .as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        collect_managed_identity_reference(identity, references);
    }

    for binding in &surface.outbound_credentials {
        push_reference(references, ResourceKind::CredentialProviders, &binding.credential_provider_id);
    }

    if let Some(transit) = surface.transit.as_ref() {
        for point in &transit.points {
            for trust_check in &point.trust_check_list {
                push_reference(references, ResourceKind::TrustRegistries, &trust_check.trust_registry_id);
            }
            collect_target_auth_reference(point.target_auth.as_ref(), references);
            collect_custom_metadata_references(transit_metadata(surface), references);
            if let Some(source_auth) = point.source_auth.as_ref() {
                collect_source_auth_references(source_auth, references);
            }
            collect_identity_injection_references(&point.identity_injection, references);
            if let Some(identity) = point
                .managed_identity
                .as_ref()
            {
                collect_managed_identity_reference(identity, references);
            }
            if let Some(credentials) = point
                .transit_credentials
                .as_ref()
            {
                push_reference(references, ResourceKind::CredentialProviders, &credentials.credential_provider_id);
            }
            if let Some(id) = endpoint_id(&point.target_endpoint, "fabric://") {
                push_reference(references, ResourceKind::Gateways, id);
            }
        }
    }

    if let Some(id) = surface
        .target
        .mcp_proxy_id
        .as_deref()
    {
        push_reference(references, ResourceKind::McpProxies, id);
    }
    if let Some(id) = endpoint_id(&surface.target.endpoint, "proxy://") {
        push_reference(references, ResourceKind::McpProxies, id);
    }
    if let Some(id) = surface
        .target
        .a2a_proxy_id
        .as_deref()
    {
        push_reference(references, ResourceKind::A2aProxies, id);
    }
    if let Some(id) = endpoint_id(&surface.target.endpoint, "a2a-proxy://") {
        push_reference(references, ResourceKind::A2aProxies, id);
    }
    if let Some(id) = endpoint_id(&surface.target.endpoint, "fabric://") {
        push_reference(references, ResourceKind::Gateways, id);
    }
    if let Some(policy) = surface.agent_pay_policy() {
        push_reference(references, ResourceKind::Gateways, &policy.payment_gateway_id);
    }
}

/// The Target's and the Access Point's response custom metadata, both returned to the caller.
fn response_metadata(surface: &AgentSurface) -> [Option<&CustomMetadata>; 2] {
    [
        surface
            .target
            .response_custom_metadata
            .as_ref(),
        surface
            .access_point
            .response_custom_metadata
            .as_ref(),
    ]
}

fn transit_metadata(surface: &AgentSurface) -> Option<&CustomMetadata> {
    surface
        .transit
        .as_ref()
        .and_then(|transit| {
            transit
                .shared
                .custom_metadata
                .as_ref()
        })
}

fn collect_custom_metadata_references(
    metadata: Option<&CustomMetadata>,
    references: &mut Vec<SurfaceReferenceKey>,
) {
    if let Some(payload) = metadata.and_then(|metadata| metadata.payload.as_ref()) {
        collect_secret_helpers(payload, references);
    }
}

fn collect_secret_helpers(
    value: &serde_json::Value,
    references: &mut Vec<SurfaceReferenceKey>,
) {
    match value {
        serde_json::Value::String(value) => {
            if let Some(id) = crate::protocols::extensions::secret_helper_id(value) {
                push_reference_key(references, ResourceKind::Secrets, id, true, true);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_secret_helpers(item, references);
            }
        }
        serde_json::Value::Object(fields) => {
            for field in fields.values() {
                collect_secret_helpers(field, references);
            }
        }
        _ => {}
    }
}

fn collect_target_auth_reference(
    authentication: Option<&TargetAuthConfig>,
    references: &mut Vec<SurfaceReferenceKey>,
) {
    match authentication.map(|authentication| &authentication.method) {
        Some(TargetAuthMethod::StaticSecret { secret_id, .. }) => {
            push_reference_with_rule(references, ResourceKind::Secrets, secret_id, true)
        }
        Some(TargetAuthMethod::CredentialProvider { provider_id, .. }) => {
            push_reference(references, ResourceKind::CredentialProviders, provider_id)
        }
        Some(TargetAuthMethod::CredentialLookup) | None => {}
    }
}

fn collect_source_auth_references(
    authentication: &crate::source_auth::SourceAuthConfig,
    references: &mut Vec<SurfaceReferenceKey>,
) {
    use crate::source_auth::models::{MtlsTrust, SourceAuthConfig};
    match authentication {
        SourceAuthConfig::JwtBearer(config) => {
            push_reference(references, ResourceKind::JwtVerificationStrategies, &config.jwt_verification_strategy_id)
        }
        SourceAuthConfig::ApiKey(config) => push_reference(references, ResourceKind::Secrets, &config.secret_id),
        SourceAuthConfig::ApiKeyProvider(config) => push_reference(references, ResourceKind::ApiKeys, &config.agent_id),
        SourceAuthConfig::DidAuth(_) => {}
        SourceAuthConfig::Mtls(config) => {
            let ids = match &config.trust {
                MtlsTrust::Pinned { certificate_ids } => certificate_ids,
                MtlsTrust::Ca { ca_certificate_ids, .. } => ca_certificate_ids,
            };
            for id in ids {
                push_reference(references, ResourceKind::Certificates, id);
            }
        }
    }
}

fn collect_managed_identity_reference(
    identity: &crate::source_auth::ManagedIdentityConfig,
    references: &mut Vec<SurfaceReferenceKey>,
) {
    match identity {
        crate::source_auth::ManagedIdentityConfig::FromMtls { certificate_id } => {
            push_reference(references, ResourceKind::Certificates, certificate_id)
        }
        crate::source_auth::ManagedIdentityConfig::FromApiKey { api_key_id: Some(api_key_id) }
            if !api_key_id.starts_with(crate::api_keys::KEY_ID_PREFIX) =>
        {
            push_reference(references, ResourceKind::Secrets, api_key_id)
        }
        _ => {}
    }
}

fn collect_identity_injection_references(
    identity: &crate::config::agent_surface::IdentityInjectionConfig,
    references: &mut Vec<SurfaceReferenceKey>,
) {
    if let Some(certificate_id) = identity
        .certificate_id
        .as_deref()
    {
        push_reference(references, ResourceKind::Certificates, certificate_id);
    }
    if let Some(api_key_id) = identity
        .api_key_id
        .as_deref()
        .filter(|id| !id.starts_with(crate::api_keys::KEY_ID_PREFIX))
    {
        push_reference(references, ResourceKind::Secrets, api_key_id);
    }
}

/// The API Key Provider key ids a surface, or one of its views, derives a DID from (`keys`),
/// and the Caller Context API Key `secret_id`s shaped like a key id on a view whose inbound
/// Identity is From API Key (`legacy_secrets`), which a secret stored before the prefix was
/// reserved can still carry. Both sorted and without duplicates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProviderKeyIds {
    pub keys: Vec<String>,
    pub legacy_secrets: Vec<String>,
}

impl ProviderKeyIds {
    pub(crate) fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.legacy_secrets.is_empty()
    }

    pub(crate) fn all(&self) -> impl Iterator<Item = &String> + Clone {
        self.keys
            .iter()
            .chain(&self.legacy_secrets)
    }

    fn add_view(
        &mut self,
        view: &AgentSurface,
    ) {
        use crate::source_auth::{ManagedIdentityConfig, SourceAuthConfig};
        let mut push = |identity: Option<&ManagedIdentityConfig>| {
            if let Some(ManagedIdentityConfig::FromApiKey { api_key_id: Some(id) }) = identity
                && id.starts_with(crate::api_keys::KEY_ID_PREFIX)
            {
                self.keys.push(id.clone());
            }
        };
        push(
            view.identity_slots
                .protected
                .as_ref(),
        );
        push(
            view.identity_slots
                .external
                .as_ref(),
        );
        push(
            crate::config::agent_surface_compat::identity_injection_to_managed_identity(
                &view.target.identity_injection,
            )
            .as_ref(),
        );
        for point in view
            .transit
            .iter()
            .flat_map(|transit| &transit.points)
        {
            push(
                point
                    .managed_identity
                    .as_ref(),
            );
        }
        if matches!(view.inbound_identity(), Some(ManagedIdentityConfig::FromApiKey { .. })) {
            for method in view
                .access_point
                .caller_authentication
                .iter()
                .flat_map(|authentication| &authentication.methods)
            {
                if let SourceAuthConfig::ApiKey(config) = method
                    && config
                        .secret_id
                        .starts_with(crate::api_keys::KEY_ID_PREFIX)
                {
                    self.legacy_secrets
                        .push(config.secret_id.clone());
                }
            }
        }
    }

    fn finish(mut self) -> Self {
        self.keys.sort();
        self.keys.dedup();
        self.legacy_secrets
            .retain(|id| !self.keys.contains(id));
        self.legacy_secrets.sort();
        self.legacy_secrets.dedup();
        self
    }
}

/// [`ProviderKeyIds`] of a surface in its base and every variant.
pub(crate) fn provider_key_ids(surface: &AgentSurface) -> Result<ProviderKeyIds, SurfaceApiError> {
    let mut ids = ProviderKeyIds::default();
    for view in resolved_views(surface)? {
        ids.add_view(&view);
    }
    Ok(ids.finish())
}

/// [`ProviderKeyIds`] of a surface as served: a resolved view, which has no variants, is read in
/// place; a surface with variants is read in every view.
pub(crate) fn served_provider_key_ids(surface: &AgentSurface) -> Result<ProviderKeyIds, SurfaceApiError> {
    if !surface.variants.is_empty() {
        return provider_key_ids(surface);
    }
    let mut ids = ProviderKeyIds::default();
    ids.add_view(surface);
    Ok(ids.finish())
}

/// Why a stored surface's use of an API Key Provider key id is reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProviderKeyIssueKind {
    /// The key belongs to a surface the surface may not reference: another tenant's, or a
    /// tenant's key on a surface with no tenant. A breach only when enforced, as a stored one is
    /// kept serving under `warn`.
    OtherTenant { enforced: bool },
    /// A tenant surface names the key of a surface with no tenant; a breach only when enforced.
    ApplianceKey { enforced: bool },
    /// The key belongs to another surface the surface may reference: a surface names only its
    /// own keys. A breach only when enforced.
    OtherSurface { enforced: bool },
    /// No key has this id; key ids are never reused, so its DID is no other key's.
    MissingKey,
    /// The surface owning the key no longer exists, so its tenant cannot be told; a breach only
    /// when enforced.
    MissingOwner { enforced: bool },
    /// The API key store is unavailable, so the key's owner cannot be told.
    StoreUnavailable,
}

impl ProviderKeyIssueKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::OtherTenant { .. } => "other_tenant",
            Self::ApplianceKey { .. } => "appliance_key",
            Self::OtherSurface { .. } => "other_surface",
            Self::MissingKey => "missing_key",
            Self::MissingOwner { .. } => "missing_owner",
            Self::StoreUnavailable => "store_unavailable",
        }
    }

    /// Whether the surface must not serve while it names the key.
    pub(crate) fn is_breach(self) -> bool {
        matches!(
            self,
            Self::StoreUnavailable
                | Self::OtherTenant { enforced: true }
                | Self::ApplianceKey { enforced: true }
                | Self::OtherSurface { enforced: true }
                | Self::MissingOwner { enforced: true }
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProviderKeyIssue {
    pub key_id: String,
    pub kind: ProviderKeyIssueKind,
}

/// Every API Key Provider key id a stored surface derives a DID from that it may not use, or
/// whose key or owner is gone ([`judge_provider_keys`] on [`provider_key_ids`]).
pub(crate) fn provider_key_verdict(
    surface: &AgentSurface,
    owners: Option<&std::collections::HashMap<String, Vec<String>>>,
    surface_tenants: &std::collections::HashMap<&str, Option<&str>>,
    isolation: RuleMode,
) -> Result<Vec<ProviderKeyIssue>, SurfaceApiError> {
    Ok(judge_provider_keys(
        &surface.surface_id,
        surface.tenant_id.as_deref(),
        &provider_key_ids(surface)?,
        owners,
        surface_tenants,
        isolation,
    ))
}

/// The issues of the key ids `ids` the surface `surface_id` of `tenant_id` names. A key the
/// surface owns itself has none, whatever tenant the stores read for it. A key of another
/// tenant is reported as that, not also as another surface's. A legacy secret is
/// reported only when a key of that id belongs to another surface. `owners` is `None` when the
/// API key store is unavailable; `surface_tenants` maps every stored surface id to its tenant.
pub(crate) fn judge_provider_keys(
    surface_id: &str,
    tenant_id: Option<&str>,
    ids: &ProviderKeyIds,
    owners: Option<&std::collections::HashMap<String, Vec<String>>>,
    surface_tenants: &std::collections::HashMap<&str, Option<&str>>,
    isolation: RuleMode,
) -> Vec<ProviderKeyIssue> {
    let mut issues = Vec::new();
    let mut issue = |key_id: &str, kind| {
        issues.push(ProviderKeyIssue {
            key_id: key_id.to_string(),
            kind,
        })
    };
    let Some(owners) = owners else {
        for key_id in ids.all() {
            issue(key_id, ProviderKeyIssueKind::StoreUnavailable);
        }
        return issues;
    };
    for (key_id, legacy) in ids
        .keys
        .iter()
        .map(|key_id| (key_id, false))
        .chain(
            ids.legacy_secrets
                .iter()
                .map(|key_id| (key_id, true)),
        )
    {
        let Some(owner_ids) = owners.get(key_id) else {
            if !legacy {
                issue(key_id, ProviderKeyIssueKind::MissingKey);
            }
            continue;
        };
        for owner_id in owner_ids {
            if owner_id == surface_id {
                continue;
            }
            let Some(owner_tenant) = surface_tenants.get(owner_id.as_str()) else {
                if !legacy {
                    issue(
                        key_id,
                        ProviderKeyIssueKind::MissingOwner {
                            enforced: isolation.is_enforced(),
                        },
                    );
                }
                continue;
            };
            if !can_reference(tenant_id, *owner_tenant) {
                issue(
                    key_id,
                    ProviderKeyIssueKind::OtherTenant {
                        enforced: isolation.is_enforced(),
                    },
                );
            } else if crate::tenancy::breaks_tenant_isolation(tenant_id, *owner_tenant) {
                issue(
                    key_id,
                    ProviderKeyIssueKind::ApplianceKey {
                        enforced: isolation.is_enforced(),
                    },
                );
            } else {
                issue(
                    key_id,
                    ProviderKeyIssueKind::OtherSurface {
                        enforced: isolation.is_enforced(),
                    },
                );
            }
        }
    }
    issues
}

/// The surfaces owning each API Key Provider key, by key id.
pub(crate) async fn provider_key_owners(
    state: &IdentityApiState
) -> Result<std::collections::HashMap<String, Vec<String>>, SurfaceApiError> {
    provider_key_owners_in(
        state
            .api_key_store
            .as_deref()
            .ok_or_else(|| unavailable("API key"))?,
    )
    .await
}

/// Refuses a new surface whose id's key folder holds any API key record, readable or not, such
/// as the keys kept from a deleted surface of that id, so a new surface never takes over another
/// surface's keys and the DIDs derived from them. Only the key folder of `surface_id` is read,
/// from disk; when it cannot be read the create is refused as unavailable.
pub(crate) async fn refuse_id_owning_api_keys(
    state: &IdentityApiState,
    surface_id: &str,
) -> Result<(), SurfaceApiError> {
    let Some(store) = state.api_key_store.as_deref() else {
        return Ok(());
    };
    let holds_keys = store
        .holds_key_records(surface_id)
        .await
        .map_err(|error| {
            tracing::error!(surface = %surface_id, %error, "Could not read the API keys of a new surface's id");
            SurfaceApiError::Unavailable("API key store is unavailable".to_string())
        })?;
    if holds_keys {
        return Err(SurfaceApiError::BadRequest(format!("Surface ID '{surface_id}' is not available")));
    }
    Ok(())
}

/// [`provider_key_owners`] read from `store`. A key folder that could not be loaded is left out.
pub(crate) async fn provider_key_owners_in(
    store: &dyn crate::api_keys::store::ApiKeyStore
) -> Result<std::collections::HashMap<String, Vec<String>>, SurfaceApiError> {
    owners_by_key(store.list_all().await)
}

/// [`provider_key_owners_in`], an error when the keys of an agent could not be loaded.
pub(crate) async fn complete_provider_key_owners_in(
    store: &dyn crate::api_keys::store::ApiKeyStore
) -> Result<std::collections::HashMap<String, Vec<String>>, SurfaceApiError> {
    owners_by_key(
        store
            .list_all_complete()
            .await,
    )
}

fn owners_by_key(
    keys: crate::api_keys::ApiKeyResult<Vec<crate::api_keys::ApiKeyMeta>>
) -> Result<std::collections::HashMap<String, Vec<String>>, SurfaceApiError> {
    let mut owners: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for key in keys.map_err(|error| internal("API key", error))? {
        owners
            .entry(key.key_id)
            .or_default()
            .push(key.agent_id);
    }
    Ok(owners)
}

fn push_reference(
    references: &mut Vec<SurfaceReferenceKey>,
    kind: ResourceKind,
    id: &str,
) {
    push_reference_with_rule(references, kind, id, false);
}

fn push_reference_with_rule(
    references: &mut Vec<SurfaceReferenceKey>,
    kind: ResourceKind,
    id: &str,
    same_tenant: bool,
) {
    push_reference_key(references, kind, id, same_tenant, false);
}

fn push_reference_key(
    references: &mut Vec<SurfaceReferenceKey>,
    kind: ResourceKind,
    id: &str,
    same_tenant: bool,
    custom_metadata: bool,
) {
    if !id.trim().is_empty() {
        references.push(SurfaceReferenceKey {
            kind,
            id: id.to_string(),
            same_tenant,
            custom_metadata,
        });
    }
}

fn collect_policy_ids<'a>(
    surface: &'a AgentSurface,
    ids: &mut HashSet<&'a str>,
) {
    if let Some(policy) = surface
        .access_point
        .inbound_policy
        .as_ref()
    {
        ids.insert(&policy.policy_definition_id);
    }
    if let Some(policy) = surface.target.policy.as_ref() {
        ids.insert(&policy.policy_definition_id);
    }
    if let Some(policy) = surface
        .target
        .response_policy
        .as_ref()
    {
        ids.insert(&policy.policy_definition_id);
    }
    ids.extend(
        surface
            .target
            .mcp_tool_policies
            .iter()
            .map(|policy| {
                policy
                    .policy_definition_id
                    .as_str()
            }),
    );
    collect_gating_policy_ids(
        surface
            .target
            .mcp_tool_gating
            .as_ref(),
        ids,
    );

    if let Some(transit) = surface.transit.as_ref() {
        if let Some(policy) = transit
            .shared
            .transit_policy
            .as_ref()
        {
            ids.insert(&policy.policy_definition_id);
        }
        if let Some(id) = transit
            .shared
            .opa_policy_definition_id
            .as_deref()
        {
            ids.insert(id);
        }
        for point in &transit.points {
            if let Some(policy) = point.policy.as_ref() {
                ids.insert(&policy.policy_definition_id);
            }
            if let Some(policy) = point.response_policy.as_ref() {
                ids.insert(&policy.policy_definition_id);
            }
            collect_gating_policy_ids(point.mcp_tool_gating.as_ref(), ids);
        }
    }
}

fn collect_gating_policy_ids<'a>(
    gating: Option<&'a McpToolGatingConfig>,
    ids: &mut HashSet<&'a str>,
) {
    if let Some(gating) = gating {
        ids.extend(
            gating
                .gates
                .iter()
                .filter_map(|gate| {
                    gate.condition_policy_definition_id
                        .as_deref()
                }),
        );
    }
}

fn endpoint_id<'a>(
    endpoint: &'a str,
    prefix: &str,
) -> Option<&'a str> {
    endpoint
        .strip_prefix(prefix)
        .and_then(|rest| rest.split('/').next())
        .filter(|id| !id.is_empty())
}

pub(super) fn inaccessible(label: &str) -> SurfaceApiError {
    SurfaceApiError::BadRequest(format!("{label} reference is not accessible"))
}

fn another_surfaces_key(key_id: &str) -> SurfaceApiError {
    SurfaceApiError::BadRequest(format!(
        "API key '{key_id}' belongs to another surface; a surface names only its own API keys"
    ))
}

fn unavailable(label: &str) -> SurfaceApiError {
    SurfaceApiError::InternalError(format!("{label} store is not configured"))
}

pub(super) fn internal(
    label: &str,
    error: impl std::fmt::Display,
) -> SurfaceApiError {
    SurfaceApiError::InternalError(format!("Failed to validate {label} reference: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_surface_variants::{
        AccessPointOverrides, SurfaceOverrides, SurfaceVariant, TargetOverrides, TransitOverrides,
    };
    use crate::config::types::{TrustRecorderConfig, TrustRecorderEntry};
    use crate::trust_registry_verification::TrustCheckElement;

    fn trust_check(
        id: &str,
        trust_registry_id: &str,
    ) -> TrustCheckElement {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "trust_registry_id": trust_registry_id,
            "query_type": "authorization",
            "query": {
                "authority_id": "did:web:authority.example",
                "entity_id": "{{ caller.did }}",
                "action": "invoke"
            }
        }))
        .unwrap()
    }

    fn transit_point(
        alias: &str,
        trust_registry_id: &str,
    ) -> crate::config::agent_surface::TransitPoint {
        let mut point: crate::config::agent_surface::TransitPoint = serde_json::from_value(serde_json::json!({
            "alias": alias,
            "target_endpoint": "https://partner.example/a2a",
            "protocol": "a2a"
        }))
        .unwrap();
        point.trust_check_list = vec![trust_check(&format!("{alias}-check"), trust_registry_id)];
        point
    }

    #[test]
    fn a_target_auth_credential_provider_is_a_reference_of_the_target_and_each_transit_point() {
        let mut surface = AgentSurface::default();
        surface.target.auth = Some(
            serde_json::from_value(
                serde_json::json!({"method": {"credential_provider": {"provider_id": "cp-target"}}}),
            )
            .unwrap(),
        );
        let mut point = transit_point("partner", "tr-partner");
        point.target_auth = Some(
            serde_json::from_value(
                serde_json::json!({"method": {"credential_provider": {"provider_id": "cp-partner"}}}),
            )
            .unwrap(),
        );
        surface.transit = Some(crate::config::agent_surface::TransitConfig {
            points: vec![point],
            outbound_listen_address: None,
            shared: Default::default(),
        });

        let providers: HashSet<_> = collect_surface_reference_keys(&surface)
            .unwrap()
            .into_iter()
            .filter(|reference| reference.kind == ResourceKind::CredentialProviders)
            .map(|reference| reference.id)
            .collect();

        assert_eq!(providers, HashSet::from(["cp-target".to_string(), "cp-partner".to_string()]));
    }

    fn static_secret_auth(secret_id: &str) -> crate::config::TargetAuthConfig {
        serde_json::from_value(
            serde_json::json!({"method": {"static_secret": {"secret_id": secret_id, "header_name": "x-key"}}}),
        )
        .unwrap()
    }

    fn key<'a>(
        keys: &'a [SurfaceReferenceKey],
        kind: ResourceKind,
        id: &str,
    ) -> &'a SurfaceReferenceKey {
        keys.iter()
            .find(|key| key.kind == kind && key.id == id)
            .unwrap()
    }

    #[test]
    fn the_target_auth_secret_of_the_target_and_each_transit_point_must_be_same_tenant_and_a_caller_secret_need_not() {
        let mut surface = AgentSurface::default();
        surface.target.auth = Some(static_secret_auth("target-secret"));
        surface.access_point.caller_authentication = Some(
            serde_json::from_value(serde_json::json!({"methods": [
                {"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "caller-secret"}
            ]}))
            .unwrap(),
        );
        let mut point = transit_point("partner", "tr-partner");
        point.target_auth = Some(static_secret_auth("point-secret"));
        surface.transit = Some(crate::config::agent_surface::TransitConfig {
            points: vec![point],
            outbound_listen_address: None,
            shared: Default::default(),
        });

        let keys = collect_surface_reference_keys(&surface).unwrap();

        assert!(key(&keys, ResourceKind::Secrets, "target-secret").same_tenant);
        assert!(key(&keys, ResourceKind::Secrets, "point-secret").same_tenant);
        assert!(!key(&keys, ResourceKind::Secrets, "caller-secret").same_tenant);
    }

    #[test]
    fn a_secret_used_as_target_auth_and_elsewhere_stays_same_tenant_after_deduplication() {
        let mut surface = AgentSurface::default();
        surface.target.auth = Some(static_secret_auth("shared-secret"));
        surface.access_point.caller_authentication = Some(
            serde_json::from_value(serde_json::json!({"methods": [
                {"type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "shared-secret"}
            ]}))
            .unwrap(),
        );

        let keys = collect_surface_reference_keys(&surface).unwrap();

        let shared: Vec<_> = keys
            .iter()
            .filter(|key| key.kind == ResourceKind::Secrets)
            .collect();
        assert_eq!(shared.len(), 1);
        assert!(shared[0].same_tenant);
    }

    #[test]
    fn a_stored_reference_is_held_to_the_mode_and_a_new_one_always_to_enforce() {
        let stored = vec![(ResourceKind::Secrets, "old".to_string())];

        assert_eq!(reference_rule(&stored, RuleMode::Warn, ResourceKind::Secrets, "old"), RuleMode::Warn);
        assert_eq!(reference_rule(&stored, RuleMode::Enforce, ResourceKind::Secrets, "old"), RuleMode::Enforce);
        assert_eq!(reference_rule(&stored, RuleMode::Warn, ResourceKind::Secrets, "new"), RuleMode::Enforce);
        assert_eq!(
            reference_rule(&stored, RuleMode::Warn, ResourceKind::CredentialProviders, "old"),
            RuleMode::Enforce
        );
        assert_eq!(reference_rule(&[], RuleMode::Warn, ResourceKind::Secrets, "old"), RuleMode::Enforce);
    }

    #[test]
    fn provider_key_ids_are_collected_from_every_slot_that_derives_a_did_from_them() {
        let from_api_key =
            |id: &str| serde_json::from_value(serde_json::json!({"type": "from_api_key", "api_key_id": id})).unwrap();
        let mut surface = AgentSurface::default();
        surface.identity_slots.inbound = Some(from_api_key("atgk_inbound"));
        surface
            .identity_slots
            .protected = Some(from_api_key("atgk_shared"));
        surface
            .identity_slots
            .external = Some(from_api_key("plain-secret"));
        surface
            .target
            .identity_injection =
            serde_json::from_value(serde_json::json!({"type": "from_api_key", "api_key_id": "atgk_injected"})).unwrap();
        surface.access_point.caller_authentication = Some(
            serde_json::from_value(serde_json::json!({"methods": [
                {"type": "api_key", "extraction": {"source": "http_header", "field": "X-API-Key"}, "secret_id": "atgk_shared"},
                {"type": "api_key", "extraction": {"source": "http_header", "field": "X-Other"}, "secret_id": "atgk_secret"}
            ]}))
            .unwrap(),
        );
        surface.transit = Some(crate::config::agent_surface::TransitConfig {
            points: vec![
                serde_json::from_value(serde_json::json!({
                    "id": "partner-id", "alias": "partner", "target_endpoint": "https://partner.example",
                    "protocol": "a2a", "managed_identity": {"type": "from_api_key", "api_key_id": "atgk_point"},
                    "identity_injection": {"inject_vp": true, "type": "from_api_key", "api_key_id": "atgk_point_injection"}
                }))
                .unwrap(),
            ],
            outbound_listen_address: None,
            shared: Default::default(),
        });

        surface.variants = serde_json::from_value(serde_json::json!([{
            "id": "variant-id", "alias": "variant", "name": "Variant",
            "overrides": {"identity_slots": {"protected": {"type": "from_api_key", "api_key_id": "atgk_variant"}}}
        }]))
        .unwrap();

        let keys = provider_key_ids(&surface)
            .unwrap()
            .keys;

        assert_eq!(keys, ["atgk_injected", "atgk_point", "atgk_shared", "atgk_variant"]);
        assert!(
            provider_key_ids(&AgentSurface::default())
                .unwrap()
                .is_empty()
        );
        let mut untyped = AgentSurface::default();
        untyped
            .target
            .identity_injection = serde_json::from_value(
            serde_json::json!({"type": "from_mtls", "certificate_id": "cert", "api_key_id": "atgk_unread"}),
        )
        .unwrap();
        assert!(
            provider_key_ids(&untyped)
                .unwrap()
                .is_empty()
        );
    }

    fn legs_surface() -> AgentSurface {
        let mut surface = AgentSurface::default();
        surface.target.endpoint = "https://target.example".into();
        surface.target.auth = Some(static_secret_auth("target-secret"));
        surface.outbound_credentials =
            serde_json::from_value(serde_json::json!([{"credential_provider_id": "bound"}])).unwrap();
        let point = |alias: &str, extra: serde_json::Value| {
            let mut point = serde_json::json!({
                "id": format!("{alias}-id"), "alias": alias,
                "target_endpoint": format!("https://{alias}.example"), "protocol": "a2a"
            });
            point
                .as_object_mut()
                .unwrap()
                .extend(
                    extra
                        .as_object()
                        .unwrap()
                        .clone(),
                );
            serde_json::from_value(point).unwrap()
        };
        surface.transit = Some(crate::config::agent_surface::TransitConfig {
            points: vec![
                point(
                    "partner",
                    serde_json::json!({"target_auth": {"method": {"credential_provider": {"provider_id": "partner-provider"}}}}),
                ),
                point("peer", serde_json::json!({"transit_credentials": {"credential_provider_id": "peer-provider"}})),
            ],
            outbound_listen_address: None,
            shared: Default::default(),
        });
        surface.variants = vec![
            serde_json::from_value(serde_json::json!({
                "id": "staging-id", "alias": "staging", "name": "Staging",
                "overrides": {"target": {"endpoint": "https://staging.example"}}
            }))
            .unwrap(),
        ];
        surface
    }

    fn kept(
        stored: &AgentSurface,
        saved: &AgentSurface,
    ) -> Vec<String> {
        let mut kept: Vec<String> =
            grandfathered_references(&sent_credentials(stored).unwrap(), &sent_credentials(saved).unwrap())
                .into_iter()
                .map(|(kind, id)| format!("{kind}:{id}"))
                .collect();
        kept.sort();
        kept
    }

    fn all_kept() -> Vec<String> {
        let mut all: Vec<String> = [
            (ResourceKind::CredentialProviders, "bound"),
            (ResourceKind::CredentialProviders, "partner-provider"),
            (ResourceKind::CredentialProviders, "peer-provider"),
            (ResourceKind::Secrets, "target-secret"),
        ]
        .into_iter()
        .map(|(kind, id)| format!("{kind}:{id}"))
        .collect();
        all.sort();
        all
    }

    fn without(removed: &[&str]) -> Vec<String> {
        all_kept()
            .into_iter()
            .filter(|key| {
                !removed
                    .iter()
                    .any(|id| key.ends_with(&format!(":{id}")))
            })
            .collect()
    }

    fn points(surface: &mut AgentSurface) -> &mut Vec<crate::config::agent_surface::TransitPoint> {
        &mut surface
            .transit
            .as_mut()
            .unwrap()
            .points
    }

    fn destination(credential: &SentCredential) -> &str {
        match &credential.destination {
            Destination::Endpoint(endpoint) => endpoint,
            Destination::Caller => "caller",
        }
    }

    #[test]
    fn a_credential_is_sent_on_each_leg_of_the_base_and_each_variant_with_the_legs_endpoint() {
        let sent = sent_credentials(&legs_surface()).unwrap();
        let legs: HashSet<_> = sent
            .iter()
            .map(|credential| {
                (
                    credential
                        .variant_id
                        .as_deref(),
                    credential
                        .transit_point_id
                        .as_deref(),
                    destination(credential),
                    credential.id.as_str(),
                )
            })
            .collect();

        let mut expected = HashSet::new();
        for (variant, target_endpoint) in
            [(None, "https://target.example"), (Some("staging-id"), "https://staging.example")]
        {
            expected.extend([
                (variant, None, target_endpoint, "target-secret"),
                (variant, None, target_endpoint, "bound"),
                (variant, Some("partner-id"), "https://partner.example", "partner-provider"),
                (variant, Some("partner-id"), "https://partner.example", "bound"),
                (variant, Some("peer-id"), "https://peer.example", "peer-provider"),
                (variant, Some("peer-id"), "https://peer.example", "bound"),
            ]);
        }
        assert_eq!(legs, expected);
        assert_eq!(sent.len(), expected.len());
        assert!(
            sent.iter()
                .all(|credential| (credential.kind == ResourceKind::Secrets) == (credential.id == "target-secret"))
        );
    }

    #[test]
    fn a_stored_credential_is_kept_while_each_leg_that_sends_it_keeps_its_endpoint() {
        let stored = legs_surface();
        assert_eq!(kept(&stored, &stored), all_kept());

        let mut renamed = legs_surface();
        renamed.name = "renamed".into();
        points(&mut renamed).reverse();
        for point in points(&mut renamed) {
            point.alias = format!("{}-renamed", point.alias);
            point.name = "Renamed".into();
        }
        renamed.variants[0].alias = "staging-renamed".into();
        assert_eq!(kept(&stored, &renamed), all_kept());

        let mut dropped = legs_surface();
        points(&mut dropped).remove(1);
        assert_eq!(kept(&stored, &dropped), without(&["peer-provider"]));
    }

    #[test]
    fn a_stored_credential_is_not_kept_when_a_leg_that_sends_it_is_redirected_moved_or_new() {
        let stored = legs_surface();

        let mut target = legs_surface();
        target.target.endpoint = "https://tenant.example".into();
        assert_eq!(kept(&stored, &target), without(&["target-secret", "bound"]));

        let mut variant = legs_surface();
        variant.variants[0]
            .overrides
            .target
            .as_mut()
            .unwrap()
            .endpoint = Some("https://tenant.example".into());
        assert_eq!(kept(&stored, &variant), without(&["target-secret", "bound"]));

        let mut partner = legs_surface();
        points(&mut partner)[0].target_endpoint = "https://tenant.example".into();
        assert_eq!(kept(&stored, &partner), without(&["partner-provider", "bound"]));

        let mut moved = legs_surface();
        let authentication = points(&mut moved)[0]
            .target_auth
            .take();
        points(&mut moved)[1].target_auth = authentication;
        assert_eq!(kept(&stored, &moved), without(&["partner-provider"]));

        let mut replaced = legs_surface();
        points(&mut replaced)[1].id = "peer-replacement-id".into();
        assert_eq!(kept(&stored, &replaced), without(&["peer-provider", "bound"]));

        let mut added = legs_surface();
        let mut extra = points(&mut added)[1].clone();
        extra.id = "extra-id".into();
        extra.alias = "extra".into();
        extra.transit_credentials = None;
        extra.target_endpoint = "https://tenant.example".into();
        points(&mut added).push(extra);
        assert_eq!(kept(&stored, &added), without(&["bound"]));

        let mut removed_variant = legs_surface();
        removed_variant.variants[0].id = "other-variant-id".into();
        assert_eq!(kept(&stored, &removed_variant), Vec::<String>::new());

        assert_eq!(kept(&AgentSurface::default(), &stored), Vec::<String>::new());
    }

    #[test]
    fn an_appliance_wide_secret_is_refused_on_a_tenant_surface_when_new_and_when_enforced_but_not_when_stored_in_warn_mode()
     {
        let stored = vec![(ResourceKind::Secrets, "old".to_string())];
        let allowed = |isolation: RuleMode, id: &str, secret_tenant: Option<&str>| {
            can_reference_with_rule(
                Some("tenant-a"),
                secret_tenant,
                reference_rule(&stored, isolation, ResourceKind::Secrets, id),
            )
        };

        assert!(!allowed(RuleMode::Warn, "new", None));
        assert!(allowed(RuleMode::Warn, "old", None));
        assert!(!allowed(RuleMode::Enforce, "old", None));
        assert!(allowed(RuleMode::Warn, "new", Some("tenant-a")));
        assert!(allowed(RuleMode::Enforce, "new", Some("tenant-a")));
        assert!(!allowed(RuleMode::Warn, "old", Some("tenant-b")));
    }

    fn custom_metadata(payload: serde_json::Value) -> Option<crate::config::CustomMetadata> {
        Some(serde_json::from_value(serde_json::json!({"enabled": true, "payload": payload})).unwrap())
    }

    fn metadata_surface() -> AgentSurface {
        let mut surface = legs_surface();
        surface.target.custom_metadata = custom_metadata(serde_json::json!({"a": {"b": ["$SECRET:target-meta"]}}));
        surface
            .target
            .response_custom_metadata = custom_metadata(serde_json::json!({"x": "$SECRET:target-response"}));
        surface
            .access_point
            .response_custom_metadata = custom_metadata(serde_json::json!({"y": [{"z": "$SECRET:ap-response"}]}));
        surface
            .transit
            .as_mut()
            .unwrap()
            .shared
            .custom_metadata = custom_metadata(serde_json::json!({"t": {"u": "$SECRET:transit-meta"}}));
        surface
    }

    fn metadata_secrets(keys: &[SurfaceReferenceKey]) -> Vec<(String, bool, bool)> {
        keys.iter()
            .filter(|key| key.kind == ResourceKind::Secrets && key.id != "target-secret")
            .map(|key| (key.id.clone(), key.same_tenant, key.custom_metadata))
            .collect()
    }

    #[test]
    fn a_secret_helper_nested_in_any_custom_metadata_is_a_same_tenant_custom_metadata_reference() {
        let keys = collect_surface_reference_keys(&metadata_surface()).unwrap();

        assert_eq!(
            metadata_secrets(&keys),
            vec![
                ("ap-response".to_string(), true, true),
                ("target-meta".to_string(), true, true),
                ("target-response".to_string(), true, true),
                ("transit-meta".to_string(), true, true),
            ]
        );
        assert!(!key(&keys, ResourceKind::Secrets, "target-secret").custom_metadata);
    }

    #[test]
    fn only_a_whole_string_secret_helper_in_custom_metadata_is_a_reference() {
        let mut surface = AgentSurface::default();
        surface.target.custom_metadata = custom_metadata(serde_json::json!({
            "timestamp": "$TIMESTAMP", "surface": "$SURFACE_ID", "request": "$REQUEST_ID", "plain": "value",
            "embedded": "prefix $SECRET:embedded", "empty": "$SECRET:", "number": 7, "list": ["$TIMESTAMP", null]
        }));

        let keys = collect_surface_reference_keys(&surface).unwrap();

        assert_eq!(metadata_secrets(&keys), Vec::<(String, bool, bool)>::new());
    }

    #[test]
    fn shared_transit_custom_metadata_is_sent_only_through_a_transit_point() {
        let mut surface = AgentSurface {
            transit: Some(crate::config::agent_surface::TransitConfig {
                points: Vec::new(),
                outbound_listen_address: None,
                shared: serde_json::from_value(
                    serde_json::json!({"custom_metadata": {"payload": {"t": "$SECRET:transit-meta"}}}),
                )
                .unwrap(),
            }),
            ..Default::default()
        };
        assert_eq!(
            metadata_secrets(&collect_surface_reference_keys(&surface).unwrap()),
            Vec::<(String, bool, bool)>::new()
        );

        points(&mut surface).push(transit_point("partner", "tr-partner"));
        assert_eq!(
            metadata_secrets(&collect_surface_reference_keys(&surface).unwrap()),
            vec![("transit-meta".to_string(), true, true)]
        );
    }

    #[test]
    fn a_secret_in_custom_metadata_and_in_target_auth_must_exist_after_deduplication() {
        let mut surface = AgentSurface::default();
        surface.target.auth = Some(static_secret_auth("shared-secret"));
        surface.target.custom_metadata = custom_metadata(serde_json::json!({"key": "$SECRET:shared-secret"}));

        let keys = collect_surface_reference_keys(&surface).unwrap();

        let shared = key(&keys, ResourceKind::Secrets, "shared-secret");
        assert!(shared.same_tenant);
        assert!(!shared.custom_metadata);
    }

    #[test]
    fn a_custom_metadata_secret_is_sent_where_its_metadata_goes() {
        let sent = sent_credentials(&metadata_surface()).unwrap();
        let legs: HashSet<_> = sent
            .iter()
            .filter(|credential| {
                credential
                    .id
                    .ends_with("-meta")
                    || credential
                        .id
                        .ends_with("-response")
            })
            .map(|credential| {
                (
                    credential
                        .variant_id
                        .as_deref(),
                    credential
                        .transit_point_id
                        .as_deref(),
                    destination(credential),
                    credential.id.as_str(),
                )
            })
            .collect();

        let mut expected = HashSet::new();
        for (variant, target_endpoint) in
            [(None, "https://target.example"), (Some("staging-id"), "https://staging.example")]
        {
            expected.extend([
                (variant, None, target_endpoint, "target-meta"),
                (variant, None, "caller", "target-response"),
                (variant, None, "caller", "ap-response"),
                (variant, Some("partner-id"), "https://partner.example", "transit-meta"),
                (variant, Some("peer-id"), "https://peer.example", "transit-meta"),
            ]);
        }
        assert_eq!(legs, expected);
    }

    #[test]
    fn a_stored_custom_metadata_secret_is_kept_only_while_its_leg_keeps_its_endpoint() {
        let stored = metadata_surface();
        let kept_metadata = |saved: &AgentSurface| -> Vec<String> {
            kept(&stored, saved)
                .into_iter()
                .filter(|key| key.ends_with("-meta") || key.ends_with("-response"))
                .collect()
        };
        let all = vec![
            "secrets:ap-response".to_string(),
            "secrets:target-meta".to_string(),
            "secrets:target-response".to_string(),
            "secrets:transit-meta".to_string(),
        ];
        assert_eq!(kept_metadata(&stored), all);

        let mut target = metadata_surface();
        target.target.endpoint = "https://tenant.example".into();
        assert_eq!(
            kept_metadata(&target),
            vec![
                "secrets:ap-response".to_string(),
                "secrets:target-response".to_string(),
                "secrets:transit-meta".to_string(),
            ]
        );

        let mut partner = metadata_surface();
        points(&mut partner)[0].target_endpoint = "https://tenant.example".into();
        assert_eq!(kept_metadata(&partner), all[..3].to_vec());

        let mut moved = metadata_surface();
        moved.target.custom_metadata = custom_metadata(serde_json::json!({"a": "$SECRET:transit-meta"}));
        assert_eq!(
            kept_metadata(&moved),
            vec!["secrets:ap-response".to_string(), "secrets:target-response".to_string()]
        );
    }

    #[test]
    fn a_secret_newly_in_response_metadata_is_not_kept_from_target_auth_or_request_metadata() {
        let stored = metadata_surface();
        let places: [fn(&mut AgentSurface) -> &mut Option<CustomMetadata>; 2] = [
            |surface| {
                &mut surface
                    .target
                    .response_custom_metadata
            },
            |surface| {
                &mut surface
                    .access_point
                    .response_custom_metadata
            },
        ];
        for place in places {
            for id in ["target-secret", "target-meta"] {
                let mut saved = metadata_surface();
                *place(&mut saved) = custom_metadata(serde_json::json!({"k": format!("$SECRET:{id}")}));
                let kept = kept(&stored, &saved);
                assert!(!kept.contains(&format!("secrets:{id}")), "{id} kept: {kept:?}");
                assert!(kept.contains(&"secrets:transit-meta".to_string()), "{kept:?}");
            }
        }
    }

    #[test]
    fn disabled_custom_metadata_is_not_counted_as_sent_but_its_secrets_are_still_checked() {
        let mut stored = metadata_surface();
        stored
            .target
            .response_custom_metadata
            .as_mut()
            .unwrap()
            .enabled = false;

        assert!(!kept(&stored, &metadata_surface()).contains(&"secrets:target-response".to_string()));
        assert!(kept(&metadata_surface(), &metadata_surface()).contains(&"secrets:target-response".to_string()));
        let keys = collect_surface_reference_keys(&stored).unwrap();
        let disabled = key(&keys, ResourceKind::Secrets, "target-response");
        assert!(disabled.same_tenant);
        assert!(disabled.custom_metadata);
    }

    #[test]
    fn disabled_custom_metadata_keeps_a_stored_secret_only_until_it_is_enabled() {
        let disable = |surface: &mut AgentSurface| {
            surface
                .target
                .custom_metadata
                .as_mut()
                .unwrap()
                .enabled = false;
        };
        let target_meta = "secrets:target-meta".to_string();
        let mut stored = metadata_surface();
        disable(&mut stored);

        assert!(kept(&stored, &stored).contains(&target_meta), "{:?}", kept(&stored, &stored));
        let mut disabled = metadata_surface();
        disable(&mut disabled);
        assert!(kept(&metadata_surface(), &disabled).contains(&target_meta));

        let enabled = metadata_surface();
        assert!(!kept(&stored, &enabled).contains(&target_meta));
        assert_eq!(
            reference_rule(
                &grandfathered_references(&sent_credentials(&stored).unwrap(), &sent_credentials(&enabled).unwrap()),
                RuleMode::Warn,
                ResourceKind::Secrets,
                "target-meta"
            ),
            RuleMode::Enforce
        );
        assert_eq!(
            reference_rule(
                &grandfathered_references(&sent_credentials(&stored).unwrap(), &sent_credentials(&stored).unwrap()),
                RuleMode::Warn,
                ResourceKind::Secrets,
                "target-meta"
            ),
            RuleMode::Warn
        );

        let mut redirected = stored.clone();
        redirected.target.endpoint = "https://tenant.example".into();
        assert!(!kept(&stored, &redirected).contains(&target_meta));
    }

    #[test]
    fn endpoint_id_extracts_only_the_authority_segment() {
        assert_eq!(endpoint_id("fabric://gateway-1/surface-1", "fabric://"), Some("gateway-1"));
        assert_eq!(endpoint_id("proxy://proxy-1", "proxy://"), Some("proxy-1"));
        assert_eq!(endpoint_id("https://example.com", "fabric://"), None);
        assert_eq!(endpoint_id("fabric://", "fabric://"), None);
    }

    #[test]
    fn collects_trust_registries_from_both_legs_and_variants() {
        let mut surface = AgentSurface::default();
        surface
            .access_point
            .trust_check_list = vec![trust_check("base-caller", "tr-base-caller")];
        surface
            .target
            .trust_check_list = vec![trust_check("base-target", "tr-base-target")];
        surface
            .access_point
            .trust_recorder = Some(TrustRecorderConfig {
            entries: vec![TrustRecorderEntry {
                trust_registry_id: "tr-base-recorder".into(),
                issuer_did: "did:example:issuer".into(),
                authority_did: "did:example:authority".into(),
                include_owned_agent: true,
                custom_resources: Vec::new(),
            }],
        });
        surface.variants = vec![SurfaceVariant {
            id: "variant-id".into(),
            alias: "variant".into(),
            name: "Variant".into(),
            description: String::new(),
            enabled: true,
            overrides: SurfaceOverrides {
                access_point: Some(AccessPointOverrides {
                    trust_check_list: Some(vec![trust_check("variant-caller", "tr-variant-caller")]),
                    trust_recorder: Some(TrustRecorderConfig {
                        entries: vec![TrustRecorderEntry {
                            trust_registry_id: "tr-variant-recorder".into(),
                            issuer_did: "did:example:variant-issuer".into(),
                            authority_did: "did:example:variant-authority".into(),
                            include_owned_agent: true,
                            custom_resources: Vec::new(),
                        }],
                    }),
                    ..Default::default()
                }),
                target: Some(TargetOverrides {
                    trust_check_list: Some(vec![trust_check("variant-target", "tr-variant-target")]),
                    ..Default::default()
                }),
                transit: Some(TransitOverrides {
                    points: Some(vec![transit_point("variant-tp", "tr-variant-tp")]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        }];
        surface.transit = Some(crate::config::agent_surface::TransitConfig {
            points: vec![transit_point("base-tp", "tr-base-tp")],
            outbound_listen_address: None,
            shared: Default::default(),
        });

        let references = collect_surface_reference_keys(&surface).unwrap();
        let trust_registries: HashSet<_> = references
            .iter()
            .filter(|reference| reference.kind == ResourceKind::TrustRegistries)
            .map(|reference| reference.id.as_str())
            .collect();

        assert_eq!(
            trust_registries,
            HashSet::from([
                "tr-base-caller",
                "tr-base-target",
                "tr-base-recorder",
                "tr-variant-caller",
                "tr-variant-target",
                "tr-variant-recorder",
                "tr-base-tp",
                "tr-variant-tp",
            ])
        );
    }

    /// A Transit Point's own `source_auth` names secrets, JWT strategies, API-key
    /// parents and certificates that are checked like an Access Point's.
    #[test]
    fn collects_transit_point_source_auth_references_from_the_base_and_variants() {
        let point = |alias: &str, source_auth: serde_json::Value| -> crate::config::agent_surface::TransitPoint {
            serde_json::from_value(serde_json::json!({
                "alias": alias, "target_endpoint": "https://partner.example/a2a", "protocol": "a2a",
                "source_auth": source_auth
            }))
            .unwrap()
        };
        let header = serde_json::json!({"source": "http_header", "field": "x-api-key"});
        let transit = Some(crate::config::agent_surface::TransitConfig {
            points: vec![
                point("key", serde_json::json!({"type": "api_key", "extraction": header, "secret_id": "tp-secret"})),
                point(
                    "jwt",
                    serde_json::json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "tp-strategy",
                                       "audiences": ["tp-audience"]}),
                ),
                point(
                    "mtls",
                    serde_json::json!({"type": "mtls", "trust": {"type": "pinned", "certificate_ids": ["tp-cert"]},
                                       "identity_binding": {"type": "fingerprint"}}),
                ),
            ],
            outbound_listen_address: None,
            shared: Default::default(),
        });
        let variants = vec![SurfaceVariant {
            id: "variant-id".into(),
            alias: "variant".into(),
            name: "Variant".into(),
            description: String::new(),
            enabled: true,
            overrides: SurfaceOverrides {
                transit: Some(TransitOverrides {
                    points: Some(vec![point(
                        "provider",
                        serde_json::json!({"type": "api_key_provider", "extraction": header,
                                           "agent_id": "tp-key-parent"}),
                    )]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        }];
        let surface = AgentSurface {
            transit,
            variants,
            ..Default::default()
        };

        let references: HashSet<_> = collect_surface_reference_keys(&surface)
            .unwrap()
            .into_iter()
            .map(|reference| (reference.kind.as_str(), reference.id))
            .collect();
        for (kind, id) in [
            (ResourceKind::Secrets, "tp-secret"),
            (ResourceKind::JwtVerificationStrategies, "tp-strategy"),
            (ResourceKind::Certificates, "tp-cert"),
            (ResourceKind::ApiKeys, "tp-key-parent"),
        ] {
            assert!(references.contains(&(kind.as_str(), id.to_string())), "{kind} {id} missing from {references:?}");
        }
    }

    async fn providers_with(directory: &tempfile::TempDir) -> std::sync::Arc<dyn CredentialProviderStorage> {
        let store = crate::credential_providers::storage::FileSystemCredentialProviderStore::new(
            directory
                .path()
                .join("providers"),
        )
        .await
        .unwrap();
        const VENDOR: Option<&str> = Some("https://203.0.113.30/mcp");
        for (id, tenant, issuer, resource) in [
            ("external-a", Some("tenant-a"), Some("https://203.0.113.30"), VENDOR),
            ("external-b", Some("tenant-b"), Some("https://203.0.113.30"), VENDOR),
            ("external-global", None, Some("https://203.0.113.30"), VENDOR),
            ("external-private", Some("tenant-a"), Some("https://10.0.0.5"), Some("https://10.0.0.5/mcp")),
            ("external-without-resource", Some("tenant-a"), Some("https://203.0.113.30"), None),
            ("external-elsewhere", Some("tenant-a"), Some("https://203.0.113.10"), VENDOR),
            ("legacy-a", Some("tenant-a"), None, None),
        ] {
            store
                .create(
                    serde_json::from_value(serde_json::json!({
                        "id": id, "tenant_id": tenant, "name": id, "provider_id": id, "issuer": issuer,
                        "resource": resource,
                        "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
                    }))
                    .unwrap(),
                )
                .await
                .unwrap();
        }
        std::sync::Arc::new(store)
    }

    fn vendor_point(binding: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"id": "tp-1", "alias": "vendor", "target_endpoint": "https://203.0.113.30/mcp",
            "require_transit_token": true, "transit_credentials": binding})
    }

    fn surface_with_points(
        points: serde_json::Value,
        outbound_credentials: serde_json::Value,
        variant_points: Option<serde_json::Value>,
    ) -> AgentSurface {
        let variants = match variant_points {
            Some(points) => {
                serde_json::json!([{"id": "v-1", "alias": "candidate", "name": "candidate", "enabled": true,
                "overrides": {"transit": {"points": points}}}])
            }
            None => serde_json::json!([]),
        };
        serde_json::from_value(serde_json::json!({
            "surface_id": "surface", "name": "surface", "tenant_id": "tenant-a",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://managed.example/agent"},
            "outbound_credentials": outbound_credentials,
            "transit": {"points": points},
            "variants": variants
        }))
        .unwrap()
    }

    fn surface_binding(
        binding: serde_json::Value,
        outbound_credentials: serde_json::Value,
        variant_binding: Option<serde_json::Value>,
    ) -> AgentSurface {
        surface_with_points(
            serde_json::json!([vendor_point(binding)]),
            outbound_credentials,
            variant_binding.map(|binding| serde_json::json!([vendor_point(binding)])),
        )
    }

    fn external(
        provider: &str,
        subject: Option<&str>,
    ) -> serde_json::Value {
        let mut binding = serde_json::json!({"credential_provider_id": provider, "consent_mode": "external"});
        if let Some(subject) = subject {
            binding["subject"] = serde_json::json!(subject);
        }
        binding
    }

    async fn checked(
        providers: &std::sync::Arc<dyn CredentialProviderStorage>,
        surface: AgentSurface,
        encryption_active: bool,
    ) -> Result<(), String> {
        checked_with(
            providers,
            surface,
            GrantStorage {
                encrypted: encryption_active,
                stable_ids: true,
            },
        )
        .await
    }

    async fn checked_with(
        providers: &std::sync::Arc<dyn CredentialProviderStorage>,
        surface: AgentSurface,
        storage: GrantStorage,
    ) -> Result<(), String> {
        check_external_consent_bindings(Some(providers), &surface, storage, &std::collections::HashMap::new(), None)
            .await
            .map_err(|error| match error {
                SurfaceApiError::BadRequest(message) => message,
                other => panic!("expected a 400, got {other:?}"),
            })
    }

    /// With `external_consent_issuers` set, a binding's provider must name a
    /// listed issuer.
    #[tokio::test]
    async fn a_binding_whose_providers_issuer_the_operator_does_not_list_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let providers = providers_with(&directory).await;
        let surface = surface_binding(external("external-a", Some("owner")), serde_json::json!([]), None);
        let storage = GrantStorage {
            encrypted: true,
            stable_ids: true,
        };
        let check = |issuers: Option<std::collections::HashMap<String, Vec<String>>>| {
            let providers = providers.clone();
            let surface = surface.clone();
            async move {
                check_external_consent_bindings(
                    Some(&providers),
                    &surface,
                    storage,
                    &std::collections::HashMap::new(),
                    issuers.as_ref(),
                )
                .await
            }
        };
        let issuer = providers
            .get("external-a")
            .await
            .unwrap()
            .unwrap()
            .issuer
            .unwrap();
        assert!(check(None).await.is_ok());
        assert!(
            check(Some(std::collections::HashMap::from([(issuer, Vec::new())])))
                .await
                .is_ok()
        );
        match check(Some(std::collections::HashMap::new())).await {
            Err(SurfaceApiError::BadRequest(message)) => assert!(
                message.contains("issuer is not permitted by the gateway's external_consent_issuers"),
                "{message}"
            ),
            other => panic!("expected a 400, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_transit_point_binds_its_own_tenants_provider_with_an_issuer_by_external_consent() {
        let directory = tempfile::tempdir().unwrap();
        let providers = providers_with(&directory).await;
        for subject in ["owner", "caller"] {
            let surface = surface_binding(external("external-a", Some(subject)), serde_json::json!([]), None);
            assert_eq!(checked(&providers, surface, true).await, Ok(()), "{subject}");
        }
        let legacy =
            surface_binding(serde_json::json!({"credential_provider_id": "legacy-a"}), serde_json::json!([]), None);
        assert_eq!(checked(&providers, legacy, false).await, Ok(()), "other bindings are unchanged");
    }

    #[tokio::test]
    async fn external_consent_bindings_that_break_a_rule_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let providers = providers_with(&directory).await;
        let none = serde_json::json!([]);
        let legacy_outbound = serde_json::json!([{"credential_provider_id": "legacy-a"}]);
        for (case, surface, encryption_active, expected) in [
            (
                "without at-rest encryption",
                surface_binding(external("external-a", Some("owner")), none.clone(), None),
                false,
                "transit.points[0].transit_credentials: consent_mode external needs at-rest encryption",
            ),
            (
                "without a subject",
                surface_binding(external("external-a", None), none.clone(), None),
                true,
                "transit.points[0].transit_credentials: consent_mode external needs a subject",
            ),
            (
                "a provider without an issuer",
                surface_binding(external("legacy-a", Some("owner")), none.clone(), None),
                true,
                "transit.points[0].transit_credentials: consent_mode external needs a credential provider with an issuer",
            ),
            (
                "another tenant's provider",
                surface_binding(external("external-b", Some("owner")), none.clone(), None),
                true,
                "transit.points[0].transit_credentials: consent_mode external needs a credential provider of the surface's own tenant",
            ),
            (
                "an untenanted provider on a tenant's surface",
                surface_binding(external("external-global", Some("owner")), none.clone(), None),
                true,
                "transit.points[0].transit_credentials: consent_mode external needs a credential provider of the surface's own tenant",
            ),
            (
                "a surface with outbound_credentials",
                surface_binding(external("external-a", Some("owner")), legacy_outbound.clone(), None),
                true,
                "transit.points[0].transit_credentials: consent_mode external cannot be used on a surface with outbound_credentials",
            ),
            (
                "a subject on another consent mode",
                surface_binding(
                    serde_json::json!({"credential_provider_id": "legacy-a", "subject": "owner"}),
                    none.clone(),
                    None,
                ),
                true,
                "transit.points[0].transit_credentials: subject is set only with consent_mode external",
            ),
            (
                "a provider with an issuer on another consent mode",
                surface_binding(serde_json::json!({"credential_provider_id": "external-a"}), none.clone(), None),
                true,
                "transit.points[0].transit_credentials: a credential provider with an issuer needs consent_mode external",
            ),
            (
                "a provider with an issuer in outbound_credentials",
                surface_binding(
                    serde_json::json!({"credential_provider_id": "legacy-a"}),
                    serde_json::json!([{"credential_provider_id": "external-a"}]),
                    None,
                ),
                true,
                "outbound_credentials[0]: a credential provider with an issuer needs consent_mode external",
            ),
            (
                "a variant without a subject",
                surface_with_points(
                    serde_json::json!([vendor_point(external("external-a", Some("owner")))]),
                    none.clone(),
                    Some(serde_json::json!([{"id": "tp-2", "alias": "vendor",
                        "target_endpoint": "https://203.0.113.30/mcp", "require_transit_token": true,
                        "transit_credentials": external("external-a", None)}])),
                ),
                true,
                "variant 'candidate' transit.points[0].transit_credentials: consent_mode external needs a subject",
            ),
        ] {
            let message = checked(&providers, surface, encryption_active)
                .await
                .expect_err(case);
            assert!(message.starts_with(expected), "{case}: {message}");
        }
    }

    /// A Transit Point's grants go only to its provider's `resource` origin, and
    /// a Transit Point id that carries them names one Transit Point, in one
    /// place: the surface or one variant.
    #[tokio::test]
    async fn an_external_consent_binding_sends_its_grants_only_to_its_providers_resource() {
        let directory = tempfile::tempdir().unwrap();
        let providers = providers_with(&directory).await;
        let none = serde_json::json!([]);
        let owner = external("external-a", Some("owner"));
        let at = |target: &str, binding: &serde_json::Value| {
            let mut point = vendor_point(binding.clone());
            point["target_endpoint"] = serde_json::json!(target);
            point
        };
        let mut second = at("https://203.0.113.66/mcp", &owner);
        second["alias"] = serde_json::json!("vendor-2");
        let mut named_target = vendor_point(owner.clone());
        named_target["id"] = serde_json::json!("target");

        let only_in_variant =
            surface_with_points(none.clone(), none.clone(), Some(serde_json::json!([vendor_point(owner.clone())])));
        assert_eq!(checked(&providers, only_in_variant, true).await, Ok(()), "a variant may hold the binding alone");

        let point = "transit.points[0].transit_credentials: ";
        let elsewhere = "variant 'candidate' transit.points[0]: the id of a Transit Point with consent_mode external is \
                         used in more than one place";
        for (case, surface, expected) in [
            (
                "a target repointed at another host",
                surface_with_points(serde_json::json!([at("https://203.0.113.66/mcp", &owner)]), none.clone(), None),
                format!("{point}consent_mode external needs a target_endpoint with the origin of"),
            ),
            (
                "an http target",
                surface_with_points(serde_json::json!([at("http://203.0.113.30/mcp", &owner)]), none.clone(), None),
                format!("{point}consent_mode external needs a target_endpoint that is a public https URL"),
            ),
            (
                "a private address",
                surface_with_points(
                    serde_json::json!([at("https://10.0.0.5/mcp", &external("external-private", Some("owner")))]),
                    none.clone(),
                    None,
                ),
                format!("{point}consent_mode external needs a target_endpoint that is a public https URL"),
            ),
            (
                "a Fabric route",
                surface_with_points(serde_json::json!([at("fabric://gateway-b/channel", &owner)]), none.clone(), None),
                format!("{point}consent_mode external never forwards over Fabric"),
            ),
            (
                "a provider whose resource is not permitted for its issuer",
                surface_with_points(
                    serde_json::json!([vendor_point(external("external-elsewhere", Some("owner")))]),
                    none.clone(),
                    None,
                ),
                format!("{point}the credential provider's resource is not permitted for its issuer"),
            ),
            (
                "a provider without a resource",
                surface_with_points(
                    serde_json::json!([vendor_point(external("external-without-resource", Some("owner")))]),
                    none.clone(),
                    None,
                ),
                format!("{point}the credential provider names no resource"),
            ),
            (
                "a second point with the same id",
                surface_with_points(serde_json::json!([vendor_point(owner.clone()), second]), none.clone(), None),
                "transit.points[1]: the id of a Transit Point with consent_mode external is used twice".to_string(),
            ),
            (
                "a variant point with an empty id",
                surface_with_points(
                    none.clone(),
                    none.clone(),
                    Some(serde_json::json!([{
                    "id": "", "alias": "vendor", "target_endpoint": "https://203.0.113.30/mcp",
                    "require_transit_token": true, "transit_credentials": owner.clone()}])),
                ),
                "variant 'candidate' transit.points[0]: a Transit Point with consent_mode external needs an id"
                    .to_string(),
            ),
            (
                "a variant keeping the identical point",
                surface_with_points(
                    serde_json::json!([vendor_point(owner.clone())]),
                    none.clone(),
                    Some(serde_json::json!([vendor_point(owner.clone())])),
                ),
                elsewhere.to_string(),
            ),
            (
                "a variant point with the same id and another target",
                surface_with_points(
                    serde_json::json!([vendor_point(owner.clone())]),
                    none.clone(),
                    Some(serde_json::json!([at("https://203.0.113.30/other", &owner)])),
                ),
                elsewhere.to_string(),
            ),
            (
                "a variant point with the same id and another binding",
                surface_with_points(
                    serde_json::json!([vendor_point(owner.clone())]),
                    none.clone(),
                    Some(serde_json::json!([vendor_point(external("external-a", Some("caller")))])),
                ),
                elsewhere.to_string(),
            ),
            (
                "a variant point that takes the id of an external point with no binding",
                surface_with_points(
                    serde_json::json!([vendor_point(owner.clone())]),
                    none.clone(),
                    Some(serde_json::json!([{"id": "tp-1", "alias": "vendor",
                        "target_endpoint": "https://203.0.113.66/mcp", "require_transit_token": true}])),
                ),
                elsewhere.to_string(),
            ),
            (
                "a point that takes the id `target`, which names the Access Point Target's grants",
                surface_with_points(serde_json::json!([named_target.clone()]), none.clone(), None),
                "transit.points[0]: the id `target` is reserved".to_string(),
            ),
        ] {
            let message = checked(&providers, surface, true)
                .await
                .expect_err(case);
            assert!(message.starts_with(&expected), "{case}: {message}");
        }
    }

    #[tokio::test]
    async fn an_external_consent_binding_is_refused_while_the_identity_hash_pepper_is_ephemeral() {
        let directory = tempfile::tempdir().unwrap();
        let providers = providers_with(&directory).await;
        let surface = surface_binding(external("external-a", Some("owner")), serde_json::json!([]), None);
        let ephemeral = GrantStorage {
            encrypted: true,
            stable_ids: false,
        };
        let message = checked_with(&providers, surface, ephemeral)
            .await
            .expect_err("an ephemeral pepper is refused");
        assert!(
            message.starts_with(
                "transit.points[0].transit_credentials: consent_mode external needs a configured identity hash \
                 pepper"
            ),
            "{message}"
        );
        let legacy =
            surface_binding(serde_json::json!({"credential_provider_id": "legacy-a"}), serde_json::json!([]), None);
        assert_eq!(checked_with(&providers, legacy, ephemeral).await, Ok(()), "other bindings are unchanged");
    }

    #[test]
    fn surface_level_outbound_credentials_take_external_consent_with_a_subject() {
        let binding = serde_json::json!({"credential_provider_id": "external-a", "consent_mode": "external",
            "subject": "caller"});
        let parsed = serde_json::from_value::<crate::config::types::OutboundCredentialBinding>(binding).unwrap();
        assert!(parsed.is_external());
        assert_eq!(parsed.subject, Some(crate::config::agent_surface::GrantSubject::Caller));
        let saved = serde_json::to_value(&parsed).unwrap();
        assert_eq!(saved["consent_mode"], "external");
        assert_eq!(saved["subject"], "caller");
        let legacy = serde_json::to_value(
            serde_json::from_value::<crate::config::types::OutboundCredentialBinding>(
                serde_json::json!({"credential_provider_id": "legacy-a"}),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            legacy
                .get("subject")
                .is_none(),
            "{legacy}"
        );
    }

    /// A surface whose Access Point Target is the vendor at the resource of
    /// `external-a`, with `outbound_credentials`, and `extra` set on top.
    fn target_surface(
        outbound_credentials: serde_json::Value,
        extra: serde_json::Value,
    ) -> AgentSurface {
        let mut surface = serde_json::json!({
            "surface_id": "surface", "name": "surface", "tenant_id": "tenant-a",
            "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://203.0.113.30/mcp"},
            "outbound_credentials": outbound_credentials
        });
        for (name, value) in extra.as_object().unwrap() {
            surface[name] = value.clone();
        }
        serde_json::from_value(surface).unwrap()
    }

    fn variant(overrides: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"variants": [{"id": "v-1", "alias": "candidate", "name": "candidate", "enabled": true,
            "overrides": overrides}]})
    }

    #[tokio::test]
    async fn the_access_point_target_binds_its_own_tenants_provider_by_external_consent() {
        let directory = tempfile::tempdir().unwrap();
        let providers = providers_with(&directory).await;
        let none = serde_json::json!({});
        for subject in ["owner", "caller"] {
            let surface = target_surface(serde_json::json!([external("external-a", Some(subject))]), none.clone());
            assert_eq!(checked(&providers, surface, true).await, Ok(()), "{subject}");
        }
        for (case, surface) in [
            (
                "a header of its own",
                target_surface(
                    serde_json::json!([{"credential_provider_id": "external-a", "consent_mode": "external",
                        "subject": "owner", "inject_as": {"type": "custom_header", "name": "X-Vendor-Token",
                        "format": "token {value}"}}]),
                    none.clone(),
                ),
            ),
            (
                "a variant that holds it alone",
                target_surface(
                    serde_json::json!([]),
                    variant(serde_json::json!({"outbound_credentials": [external("external-a", Some("owner"))]})),
                ),
            ),
            (
                "a variant that keeps the surface's",
                target_surface(
                    serde_json::json!([external("external-a", Some("owner"))]),
                    variant(serde_json::json!({"access_point": {"rate_limit": {"requests": 5, "window_secs": 60}}})),
                ),
            ),
            (
                "a variant that drops it",
                target_surface(
                    serde_json::json!([external("external-a", Some("owner"))]),
                    variant(serde_json::json!({"outbound_credentials": [],
                        "target": {"endpoint": "https://managed.example/agent"}})),
                ),
            ),
            (
                "the surface's DID in a header, which the vendor is not sent",
                target_surface(
                    serde_json::json!([external("external-a", Some("owner"))]),
                    serde_json::json!({"access_point": {"listen_address": "https://gateway.example", "route": "/mcp",
                        "protocol": "mcp", "didwebvh_identity": {"injection_mode": "signed_header"}},
                        "target": {"endpoint": "https://203.0.113.30/mcp", "workload_binding": {"enabled": false}}}),
                ),
            ),
            (
                "a payment policy turned off",
                target_surface(
                    serde_json::json!([external("external-a", Some("owner"))]),
                    serde_json::json!({"target": {"endpoint": "https://203.0.113.30/mcp",
                        "payment_policy": {"type": "x402", "enabled": false}}}),
                ),
            ),
        ] {
            assert_eq!(checked(&providers, surface, true).await, Ok(()), "{case}");
        }
    }

    /// The Access Point Target's grant goes only to its provider's resource,
    /// in place of every credential of the caller's and the Target's own, and
    /// is kept under one binding of the surface, in one place.
    #[tokio::test]
    async fn access_point_target_bindings_that_break_a_rule_are_refused() {
        let directory = tempfile::tempdir().unwrap();
        let providers = providers_with(&directory).await;
        let none = serde_json::json!({});
        let owner = external("external-a", Some("owner"));
        let only = serde_json::json!([owner.clone()]);
        let at = |endpoint: &str| serde_json::json!({"target": {"endpoint": endpoint}});
        let binding = "outbound_credentials[0]: ";
        for (case, surface, expected) in [
            (
                "without a subject",
                target_surface(serde_json::json!([external("external-a", None)]), none.clone()),
                format!("{binding}consent_mode external needs a subject"),
            ),
            (
                "a provider without an issuer",
                target_surface(serde_json::json!([external("legacy-a", Some("owner"))]), none.clone()),
                format!("{binding}consent_mode external needs a credential provider with an issuer"),
            ),
            (
                "another tenant's provider",
                target_surface(serde_json::json!([external("external-b", Some("owner"))]), none.clone()),
                format!("{binding}consent_mode external needs a credential provider of the surface's own tenant"),
            ),
            (
                "another binding beside it",
                target_surface(
                    serde_json::json!([owner.clone(), {"credential_provider_id": "legacy-a"}]),
                    none.clone(),
                ),
                format!("{binding}consent_mode external binds the Access Point's Target alone"),
            ),
            (
                "two of them",
                target_surface(
                    serde_json::json!([owner.clone(), external("external-a", Some("caller"))]),
                    none.clone(),
                ),
                format!("{binding}consent_mode external binds the Access Point's Target alone"),
            ),
            (
                "a surface with Transit Points",
                target_surface(
                    only.clone(),
                    serde_json::json!({"transit": {"points": [{"id": "tp-1", "alias": "partner",
                        "target_endpoint": "https://partner.example/mcp", "require_transit_token": true}]}}),
                ),
                format!("{binding}consent_mode external in outbound_credentials binds the Access Point's Target"),
            ),
            (
                "a Target at another host",
                target_surface(only.clone(), at("https://203.0.113.66/mcp")),
                format!("{binding}consent_mode external needs a target_endpoint with the origin of"),
            ),
            (
                "an http Target",
                target_surface(only.clone(), at("http://203.0.113.30/mcp")),
                format!("{binding}consent_mode external needs a target_endpoint that is a public https URL"),
            ),
            (
                "a Fabric Target",
                target_surface(only.clone(), at("fabric://gateway-b/channel")),
                format!("{binding}consent_mode external never forwards over Fabric"),
            ),
            (
                "an MCP proxy Target",
                target_surface(only.clone(), at("proxy://mcp-proxy")),
                format!("{binding}consent_mode external needs a target_endpoint that is a public https URL"),
            ),
            (
                "the grant in the body",
                target_surface(
                    serde_json::json!([{"credential_provider_id": "external-a", "consent_mode": "external",
                        "subject": "owner", "inject_as": {"type": "meta", "field": "vendor/token"}}]),
                    none.clone(),
                ),
                format!("{binding}consent_mode external injects the grant as a header"),
            ),
            (
                "a Target credential of its own",
                target_surface(
                    only.clone(),
                    serde_json::json!({"target": {"endpoint": "https://203.0.113.30/mcp", "auth": {
                        "method": {"static_secret": {"secret_id": "vendor-key", "header_name": "X-Api-Key"}}}}}),
                ),
                format!("{binding}consent_mode external sends the grant in place of the Target's own credential"),
            ),
            (
                "the caller's credential forwarded",
                target_surface(
                    only.clone(),
                    serde_json::json!({"access_point": {"listen_address": "https://gateway.example", "route": "/mcp",
                        "protocol": "mcp", "caller_authentication": {"methods": [{"type": "jwt_bearer",
                        "jwt_verification_strategy_id": "strategy", "audiences": ["https://gateway.example/mcp"],
                        "forward_header": true}]}}}),
                ),
                format!("{binding}consent_mode external sends the grant in place of the caller's credential"),
            ),
            (
                "a provider whose resource is not permitted for its issuer",
                target_surface(serde_json::json!([external("external-elsewhere", Some("owner"))]), none.clone()),
                format!("{binding}the credential provider's resource is not permitted for its issuer"),
            ),
            (
                "an identity VP for the vendor",
                target_surface(
                    only.clone(),
                    serde_json::json!({"target": {"endpoint": "https://203.0.113.30/mcp",
                        "identity_injection": {"inject_vp": true}}}),
                ),
                format!("{binding}consent_mode external sends the vendor no presentation of the agent"),
            ),
            (
                "an inbound identity slot, which injects an identity VP",
                target_surface(
                    only.clone(),
                    serde_json::json!({"identity_slots": {"inbound": {"type": "static", "did": "did:example:agent"}}}),
                ),
                format!("{binding}consent_mode external sends the vendor no presentation of the agent"),
            ),
            (
                "a workload binding for the vendor",
                target_surface(
                    only.clone(),
                    serde_json::json!({"target": {"endpoint": "https://203.0.113.30/mcp",
                        "workload_binding": {"enabled": true}}}),
                ),
                format!("{binding}consent_mode external sends the vendor no presentation of the agent"),
            ),
            (
                "the surface's DID in the body",
                target_surface(
                    only.clone(),
                    serde_json::json!({"access_point": {"listen_address": "https://gateway.example", "route": "/mcp",
                        "protocol": "mcp", "didwebvh_identity": {"injection_mode": "protocol_native"}}}),
                ),
                format!("{binding}consent_mode external sends the vendor no presentation of the agent"),
            ),
            (
                "an x402 payment",
                target_surface(
                    only.clone(),
                    serde_json::json!({"target": {"endpoint": "https://203.0.113.30/mcp",
                        "payment_policy": {"type": "x402", "enabled": true}}}),
                ),
                format!("{binding}consent_mode external charges callers nothing"),
            ),
            (
                "an MPP payment",
                target_surface(
                    only.clone(),
                    serde_json::json!({"target": {"endpoint": "https://203.0.113.30/mcp",
                        "payment_policy": {"type": "mpp", "enabled": true, "realm": "vendor",
                        "secret_key": "$MPP_SECRET_KEY"}}}),
                ),
                format!("{binding}consent_mode external charges callers nothing"),
            ),
            (
                "an agent-pay payment",
                target_surface(
                    only.clone(),
                    serde_json::json!({"target": {"endpoint": "https://203.0.113.30/mcp",
                        "payment_policy": {"type": "agent_pay", "payment_gateway_id": "pay-gw",
                        "payment_surface_id": "pay-1"}}}),
                ),
                format!("{binding}consent_mode external charges callers nothing"),
            ),
            (
                "a variant that keeps it and charges its callers",
                target_surface(
                    only.clone(),
                    variant(serde_json::json!({"target": {"payment_policy": {"type": "x402", "enabled": true}}})),
                ),
                format!("variant 'candidate' {binding}consent_mode external charges callers nothing"),
            ),
            (
                "custom metadata for the vendor",
                target_surface(
                    only.clone(),
                    serde_json::json!({"target": {"endpoint": "https://203.0.113.30/mcp",
                        "custom_metadata": {"enabled": true, "payload": {"tenant": "acme"}}}}),
                ),
                format!("{binding}consent_mode external sends the vendor nothing of the gateway's"),
            ),
            (
                "a variant that keeps it and adds custom metadata",
                target_surface(
                    only.clone(),
                    variant(serde_json::json!({"target": {"custom_metadata": {"enabled": true,
                        "payload": {"tenant": "acme"}}}})),
                ),
                format!("variant 'candidate' {binding}consent_mode external sends the vendor nothing of the gateway's"),
            ),
            (
                "a subject on another consent mode",
                target_surface(
                    serde_json::json!([{"credential_provider_id": "legacy-a", "subject": "owner"}]),
                    none.clone(),
                ),
                format!("{binding}subject is set only with consent_mode external"),
            ),
            (
                "a provider with an issuer on another consent mode",
                target_surface(serde_json::json!([{"credential_provider_id": "external-a"}]), none.clone()),
                format!("{binding}a credential provider with an issuer needs consent_mode external"),
            ),
            (
                "the surface and a variant each holding one",
                target_surface(only.clone(), variant(serde_json::json!({"outbound_credentials": only.clone()}))),
                format!("variant 'candidate' {binding}the Access Point Target's consent_mode external binding is"),
            ),
            (
                "a variant that keeps it and repoints the Target",
                target_surface(
                    only.clone(),
                    variant(serde_json::json!({"target": {"endpoint": "https://203.0.113.66/mcp"}})),
                ),
                format!(
                    "variant 'candidate' {binding}consent_mode external needs a target_endpoint with the origin of"
                ),
            ),
            (
                "a variant that keeps it and adds Transit Points",
                target_surface(
                    only.clone(),
                    variant(serde_json::json!({"transit": {"points": [{"id": "tp-1", "alias": "partner",
                        "target_endpoint": "https://partner.example/mcp", "require_transit_token": true}]}})),
                ),
                format!("variant 'candidate' {binding}consent_mode external in outbound_credentials binds"),
            ),
        ] {
            let message = checked(&providers, surface, true)
                .await
                .expect_err(case);
            assert!(message.starts_with(&expected), "{case}: {message}");
        }

        let without_encryption = checked(&providers, target_surface(only.clone(), none.clone()), false)
            .await
            .expect_err("without at-rest encryption");
        assert!(
            without_encryption.starts_with(&format!("{binding}consent_mode external needs at-rest encryption")),
            "{without_encryption}"
        );
        let ephemeral = checked_with(
            &providers,
            target_surface(only.clone(), none.clone()),
            GrantStorage {
                encrypted: true,
                stable_ids: false,
            },
        )
        .await
        .expect_err("an ephemeral pepper");
        assert!(
            ephemeral.starts_with(&format!("{binding}consent_mode external needs a configured identity hash pepper")),
            "{ephemeral}"
        );
        let unlisted = check_external_consent_bindings(
            Some(&providers),
            &target_surface(only.clone(), none.clone()),
            GrantStorage {
                encrypted: true,
                stable_ids: true,
            },
            &std::collections::HashMap::new(),
            Some(&std::collections::HashMap::new()),
        )
        .await;
        match unlisted {
            Err(SurfaceApiError::BadRequest(message)) => assert!(
                message.starts_with(&format!(
                    "{binding}the credential provider's issuer is not permitted by the gateway's \
                     external_consent_issuers"
                )),
                "{message}"
            ),
            other => panic!("expected a 400, got {other:?}"),
        }
    }

    /// On A2A and AP2 the grant goes at or under the Target's endpoint path,
    /// so a Target at the root of its origin would be sent the grant on every
    /// path of the vendor's: such an endpoint is refused, in the surface or a
    /// variant. An MCP Target, sent the grant at its endpoint path alone, may
    /// be at the root.
    #[tokio::test]
    async fn an_a2a_target_at_the_root_of_its_origin_is_refused_external_consent() {
        let directory = tempfile::tempdir().unwrap();
        let providers = providers_with(&directory).await;
        let owner = serde_json::json!([external("external-a", Some("owner"))]);
        let on = |protocol: &str, endpoint: &str| {
            serde_json::json!({"access_point": {"listen_address": "https://gateway.example", "route": "/agent",
                "protocol": protocol}, "target": {"endpoint": endpoint}})
        };
        for (case, extra) in [
            ("A2A under a path", on("a2a", "https://203.0.113.30/a2a")),
            ("AP2 under a path", on("ap2", "https://203.0.113.30/agents/shop/")),
            ("MCP at the root", on("mcp", "https://203.0.113.30/")),
        ] {
            assert_eq!(checked(&providers, target_surface(owner.clone(), extra), true).await, Ok(()), "{case}");
        }

        let refused = "outbound_credentials[0]: consent_mode external on an A2A or AP2 Access Point sends the grant \
                       at or under the Target's endpoint path";
        let mut at_the_root_in_a_variant = on("a2a", "https://203.0.113.30/a2a");
        at_the_root_in_a_variant["variants"] = variant(serde_json::json!({"target": {"endpoint":
            "https://203.0.113.30"}}))["variants"]
            .clone();
        for (case, extra) in [
            ("A2A at the root", on("a2a", "https://203.0.113.30/")),
            ("A2A at the origin", on("a2a", "https://203.0.113.30")),
            ("AP2 at the root", on("ap2", "https://203.0.113.30//")),
            ("A2A at the root with a query", on("a2a", "https://203.0.113.30/?tenant=a")),
            ("a variant at the root", at_the_root_in_a_variant),
        ] {
            let message = checked(&providers, target_surface(owner.clone(), extra), true)
                .await
                .expect_err(case);
            assert!(message.contains(refused), "{case}: {message}");
        }
    }

    /// An Access Point's caller authentication with `methods`.
    fn access_point_authenticating(methods: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp",
            "caller_authentication": {"methods": methods}})
    }

    /// DID Auth accepting the DIDs in `allowed_dids`, or any DID when empty.
    fn did_auth(allowed_dids: &[&str]) -> serde_json::Value {
        serde_json::json!({"type": "did_auth", "extraction": {"source": "http_header", "field": "X-DID-Auth-Session"},
            "allowed_dids": allowed_dids})
    }

    /// A binding with external consent, on the Target or a Transit Point, in
    /// the surface or a variant, needs callers authenticated by something the
    /// gateway can check: DID Auth without `allowed_dids`, in any view and
    /// among any of the methods, accepts whoever mints a DID, so it is refused
    /// beside an owner's grant or a caller's.
    #[tokio::test]
    async fn external_consent_needs_callers_the_gateway_can_check() {
        let directory = tempfile::tempdir().unwrap();
        let providers = providers_with(&directory).await;
        let api_key = serde_json::json!({"type": "api_key",
            "extraction": {"source": "http_header", "field": "X-API-Key"}, "secret_id": "caller-key"});
        let open = access_point_authenticating(serde_json::json!([api_key.clone(), did_auth(&[])]));
        let listed = access_point_authenticating(serde_json::json!([did_auth(&["did:example:alice"])]));
        let with_access_point = |mut surface: AgentSurface, access_point: &serde_json::Value| {
            surface.access_point = serde_json::from_value(access_point.clone()).unwrap();
            surface
        };
        let target = |subject: &str| {
            target_surface(serde_json::json!([external("external-a", Some(subject))]), serde_json::json!({}))
        };
        let point = |subject: &str| surface_binding(external("external-a", Some(subject)), serde_json::json!([]), None);

        for (case, surface) in [
            ("the Target, with an allow-list", with_access_point(target("owner"), &listed)),
            ("a Transit Point, with an allow-list", with_access_point(point("owner"), &listed)),
            ("open DID Auth without a binding with external consent", {
                with_access_point(
                    target_surface(serde_json::json!([{"credential_provider_id": "legacy-a"}]), serde_json::json!({})),
                    &open,
                )
            }),
        ] {
            assert_eq!(checked(&providers, surface, true).await, Ok(()), "{case}");
        }

        let needs = "consent_mode external needs callers authenticated by something the gateway can check";
        for (case, surface, expected) in [
            (
                "the Target's owner",
                with_access_point(target("owner"), &open),
                format!("outbound_credentials[0]: {needs}"),
            ),
            (
                "the Target's callers",
                with_access_point(target("caller"), &open),
                format!("outbound_credentials[0]: {needs}"),
            ),
            (
                "a Transit Point's owner",
                with_access_point(point("owner"), &open),
                format!("transit.points[0].transit_credentials: {needs}"),
            ),
            (
                "a Transit Point's callers",
                with_access_point(point("caller"), &open),
                format!("transit.points[0].transit_credentials: {needs}"),
            ),
            (
                "a variant that opens the Access Point",
                target_surface(
                    serde_json::json!([external("external-a", Some("owner"))]),
                    variant(serde_json::json!({"access_point": {"caller_authentication": {
                        "methods": [did_auth(&[])]}}})),
                ),
                format!("outbound_credentials[0]: {needs}"),
            ),
        ] {
            let message = checked(&providers, surface, true)
                .await
                .expect_err(case);
            assert!(message.starts_with(&expected), "{case}: {message}");
        }
    }

    /// A binding with external consent, on the Target or a Transit Point, in
    /// the surface or a variant, is refused beside a JWT bearer method without
    /// `audiences` on an Access Point that publishes no protected resource:
    /// it accepts a token its issuer minted for any other service. With an
    /// audience, or a protected resource, which binds one, it is accepted.
    #[tokio::test]
    async fn external_consent_needs_caller_tokens_minted_for_the_access_point() {
        let directory = tempfile::tempdir().unwrap();
        let providers = providers_with(&directory).await;
        let jwt = |audiences: &[&str]| {
            serde_json::json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "strategy-1",
                "audiences": audiences})
        };
        let with_access_point = |mut surface: AgentSurface, access_point: serde_json::Value| {
            surface.access_point = serde_json::from_value(access_point).unwrap();
            surface
        };
        let any_audience = access_point_authenticating(serde_json::json!([jwt(&[])]));
        let audience = access_point_authenticating(serde_json::json!([jwt(&["https://gateway.example/mcp"])]));
        let mut published = any_audience.clone();
        published["caller_authentication"]["protected_resource"] = serde_json::json!({
            "resource": "https://gateway.example/mcp", "authorization_servers": ["https://issuer.example"]});
        let target = |subject: &str| {
            target_surface(serde_json::json!([external("external-a", Some(subject))]), serde_json::json!({}))
        };
        let point = |subject: &str| surface_binding(external("external-a", Some(subject)), serde_json::json!([]), None);

        for (case, surface) in [
            ("the Target, with an audience", with_access_point(target("owner"), audience.clone())),
            ("a Transit Point, with an audience", with_access_point(point("caller"), audience)),
            ("the Target, with a protected resource", with_access_point(target("owner"), published)),
        ] {
            assert_eq!(checked(&providers, surface, true).await, Ok(()), "{case}");
        }

        let needs = "consent_mode external needs callers authenticated by something the gateway can check: the \
                     Access Point's jwt_bearer has no audiences";
        for (case, surface, expected) in [
            ("the Target's owner", with_access_point(target("owner"), any_audience.clone()), "outbound_credentials[0]"),
            (
                "the Target's callers",
                with_access_point(target("caller"), any_audience.clone()),
                "outbound_credentials[0]",
            ),
            (
                "a Transit Point's owner",
                with_access_point(point("owner"), any_audience.clone()),
                "transit.points[0].transit_credentials",
            ),
            (
                "a variant without audiences",
                target_surface(
                    serde_json::json!([external("external-a", Some("caller"))]),
                    variant(serde_json::json!({"access_point": {"caller_authentication": {
                        "methods": [jwt(&[])]}}})),
                ),
                "outbound_credentials[0]",
            ),
        ] {
            let message = checked(&providers, surface, true)
                .await
                .expect_err(case);
            assert!(message.starts_with(&format!("{expected}: {needs}")), "{case}: {message}");
        }
    }

    /// A Transit Point with external consent sends its vendor no presentation
    /// of the agent, as the Access Point Target does not: an identity VP, from
    /// `identity_injection.inject_vp` or a `managed_identity` of its own, or an
    /// enabled workload binding, is refused, on the surface's Transit Point or
    /// a variant's. One without them, or with the workload binding off, is
    /// accepted, and so is a Transit Point with them that takes no grant by
    /// external consent.
    #[tokio::test]
    async fn a_transit_point_with_external_consent_sends_no_presentation_of_the_agent() {
        let directory = tempfile::tempdir().unwrap();
        let providers = providers_with(&directory).await;
        let presenting = |field: &str, value: serde_json::Value, binding: serde_json::Value| {
            let mut point = vendor_point(binding);
            point[field] = value;
            serde_json::json!([point])
        };
        let owner = external("external-a", Some("owner"));
        let vp = ("an identity VP", "identity_injection", serde_json::json!({"inject_vp": true}));
        let own_identity = (
            "a managed identity of its own",
            "managed_identity",
            serde_json::json!({"type": "static", "did": "did:example:agent"}),
        );
        let workload = ("a workload binding", "workload_binding", serde_json::json!({"enabled": true}));

        for (case, surface) in [
            (
                "a workload binding turned off",
                surface_with_points(
                    presenting("workload_binding", serde_json::json!({"enabled": false}), owner.clone()),
                    serde_json::json!([]),
                    None,
                ),
            ),
            (
                "an identity VP without external consent",
                surface_with_points(
                    presenting(vp.1, vp.2.clone(), serde_json::json!({"credential_provider_id": "legacy-a"})),
                    serde_json::json!([]),
                    None,
                ),
            ),
        ] {
            assert_eq!(checked(&providers, surface, true).await, Ok(()), "{case}");
        }

        let refused = "transit.points[0].transit_credentials: consent_mode external sends the vendor no \
                       presentation of the agent";
        for (case, field, value) in [vp, own_identity, workload] {
            let on_the_surface =
                surface_with_points(presenting(field, value.clone(), owner.clone()), serde_json::json!([]), None);
            let message = checked(&providers, on_the_surface, true)
                .await
                .expect_err(case);
            assert!(message.starts_with(refused), "{case}: {message}");
            let in_a_variant = surface_with_points(
                serde_json::json!([]),
                serde_json::json!([]),
                Some(presenting(field, value, owner.clone())),
            );
            let message = checked(&providers, in_a_variant, true)
                .await
                .expect_err(case);
            assert!(message.starts_with(&format!("variant 'candidate' {refused}")), "{case}, a variant: {message}");
        }
    }

    /// A caller's grant is kept by the caller's identity hash, which needs the
    /// issuer that named the caller. The gateway's own resource access tokens
    /// (`mcp_http.authorization`) name a caller by its subject under the
    /// gateway's issuer, so two identity providers' callers with the same
    /// subject would share a grant: a `caller` binding, on the Target or a
    /// Transit Point, is refused beside them. An `owner` binding is not.
    #[tokio::test]
    async fn a_callers_grant_needs_callers_named_with_their_issuer() {
        let directory = tempfile::tempdir().unwrap();
        let providers = providers_with(&directory).await;
        let with_resource_tokens = |surface: AgentSurface| {
            let mut surface = serde_json::to_value(surface).unwrap();
            surface["mcp_http"] =
                serde_json::json!({"authorization": {"resource": "https://gateway.example/mcp", "scopes": ["read"]}});
            serde_json::from_value::<AgentSurface>(surface).unwrap()
        };
        let target = |subject: &str| {
            with_resource_tokens(target_surface(
                serde_json::json!([external("external-a", Some(subject))]),
                serde_json::json!({}),
            ))
        };
        let point = |subject: &str| {
            with_resource_tokens(surface_binding(external("external-a", Some(subject)), serde_json::json!([]), None))
        };
        for (case, surface) in [("the Target's owner", target("owner")), ("a Transit Point's owner", point("owner"))] {
            assert_eq!(checked(&providers, surface, true).await, Ok(()), "{case}");
        }
        let needs = "consent_mode external with subject caller needs callers named with the issuer that named them";
        for (case, surface, expected) in [
            ("the Target's callers", target("caller"), format!("outbound_credentials[0]: {needs}")),
            ("a Transit Point's callers", point("caller"), format!("transit.points[0].transit_credentials: {needs}")),
        ] {
            let message = checked(&providers, surface, true)
                .await
                .expect_err(case);
            assert!(message.starts_with(&expected), "{case}: {message}");
        }
    }

    /// Every caller of an owner binding acts as the owner, so a variant that
    /// keeps the surface's owner binding for the Access Point Target keeps the
    /// surface's caller authentication: one of its own, which could admit
    /// callers the surface's would not, is refused, enabled or not, and so is
    /// one that a complete override clears. A variant that holds no such
    /// binding, or keeps a caller binding, may have its own.
    #[tokio::test]
    async fn a_variant_that_keeps_the_owners_grant_keeps_the_surfaces_caller_authentication() {
        let directory = tempfile::tempdir().unwrap();
        let providers = providers_with(&directory).await;
        let key = |secret_id: &str| {
            serde_json::json!({"type": "api_key", "extraction": {"source": "http_header", "field": "X-API-Key"},
                "secret_id": secret_id})
        };
        let base =
            serde_json::json!({"access_point": access_point_authenticating(serde_json::json!([key("owner-key")]))});
        let with_variant = |subject: &str, enabled: bool, overrides: serde_json::Value| {
            let mut extra = base.clone();
            extra["variants"] = serde_json::json!([{"id": "v-1", "alias": "candidate", "name": "candidate",
                "enabled": enabled, "overrides": overrides}]);
            target_surface(serde_json::json!([external("external-a", Some(subject))]), extra)
        };
        let own_keys = serde_json::json!({"access_point": {"caller_authentication": {"methods": [key("team-keys")]}}});

        for (case, surface) in [
            (
                "a variant that names the same caller authentication",
                with_variant(
                    "owner",
                    true,
                    serde_json::json!({"access_point": {"caller_authentication": {"methods": [key("owner-key")]}}}),
                ),
            ),
            (
                "a variant with other Access Point settings",
                with_variant(
                    "owner",
                    true,
                    serde_json::json!({"access_point": {"rate_limit": {"requests": 5, "window_secs": 60}}}),
                ),
            ),
            ("a variant that drops the binding", {
                let mut overrides = own_keys.clone();
                overrides["outbound_credentials"] = serde_json::json!([]);
                with_variant("owner", true, overrides)
            }),
            ("a variant that keeps a caller binding", with_variant("caller", true, own_keys.clone())),
        ] {
            assert_eq!(checked(&providers, surface, true).await, Ok(()), "{case}");
        }

        let refused = "variant 'candidate' overrides.access_point.caller_authentication: a variant that keeps the \
                       Access Point Target's owner binding keeps the surface's caller authentication";
        for (case, surface) in [
            ("a variant with its own caller authentication", with_variant("owner", true, own_keys.clone())),
            ("a disabled variant with its own caller authentication", with_variant("owner", false, own_keys.clone())),
            (
                "a complete variant that clears it",
                with_variant(
                    "owner",
                    true,
                    serde_json::json!({"complete": true, "access_point": {"rate_limit": {"requests": 5,
                        "window_secs": 60}}}),
                ),
            ),
        ] {
            let message = checked(&providers, surface, true)
                .await
                .expect_err(case);
            assert!(message.starts_with(refused), "{case}: {message}");
        }
    }

    /// The policies and trust checks that narrow which callers reach the
    /// Target, the Access Point's `inbound_policy` and `trust_check_list` and
    /// the Target's `policy`, choose who acts as the owner too: a variant that
    /// keeps the surface's owner binding keeps the surface's, as it keeps its
    /// caller authentication. One of its own, or one a complete override
    /// clears, is refused, enabled or not. A variant that holds no such
    /// binding, or keeps a caller binding, may have its own.
    #[tokio::test]
    async fn a_variant_that_keeps_the_owners_grant_keeps_the_surfaces_policies_and_trust_checks() {
        let directory = tempfile::tempdir().unwrap();
        let providers = providers_with(&directory).await;
        let policy = |id: &str| serde_json::json!({"policy_definition_id": id});
        let trust_check = |id: &str| {
            serde_json::json!([{"id": id, "trust_registry_id": "tr-1", "query_type": "authorization",
                "query": {"authority_id": "did:web:authority.example", "entity_id": "{{ caller.did }}",
                    "action": "invoke"}}])
        };
        let mut access_point = access_point_authenticating(serde_json::json!([{"type": "api_key",
            "extraction": {"source": "http_header", "field": "X-API-Key"}, "secret_id": "team-keys"}]));
        access_point["inbound_policy"] = policy("only-the-owner");
        access_point["trust_check_list"] = trust_check("owner-is-recognised");
        let base = serde_json::json!({"access_point": access_point,
            "target": {"endpoint": "https://203.0.113.30/mcp", "policy": policy("owner-tools")}});
        let with_variant = |subject: &str, enabled: bool, overrides: serde_json::Value| {
            let mut extra = base.clone();
            extra["variants"] = serde_json::json!([{"id": "v-1", "alias": "candidate", "name": "candidate",
                "enabled": enabled, "overrides": overrides}]);
            target_surface(serde_json::json!([external("external-a", Some(subject))]), extra)
        };
        let loosening = [
            (
                "access_point.inbound_policy",
                "inbound policy",
                serde_json::json!({"access_point": {"inbound_policy": policy("everyone")}}),
            ),
            ("target.policy", "Target policy", serde_json::json!({"target": {"policy": policy("every-tool")}})),
            (
                "access_point.trust_check_list",
                "caller trust checks",
                serde_json::json!({"access_point": {"trust_check_list": trust_check("anyone")}}),
            ),
        ];

        let mut accepted = vec![(
            "a variant naming the same policies",
            with_variant(
                "owner",
                true,
                serde_json::json!({"access_point": {"inbound_policy": policy("only-the-owner")},
                    "target": {"policy": policy("owner-tools")}}),
            ),
        )];
        for (_, _, overrides) in &loosening {
            let mut dropping = overrides.clone();
            dropping["outbound_credentials"] = serde_json::json!([]);
            accepted.push(("a variant that drops the binding", with_variant("owner", true, dropping)));
            accepted.push(("a variant that keeps a caller binding", with_variant("caller", true, overrides.clone())));
        }
        for (case, surface) in accepted {
            assert_eq!(checked(&providers, surface, true).await, Ok(()), "{case}");
        }

        for (field, name, overrides) in loosening {
            for enabled in [true, false] {
                let message = checked(&providers, with_variant("owner", enabled, overrides.clone()), true)
                    .await
                    .expect_err(field);
                let refused = format!(
                    "variant 'candidate' overrides.{field}: a variant that keeps the Access Point Target's owner \
                     binding keeps the surface's {name}"
                );
                assert!(message.starts_with(&refused), "{field}, enabled {enabled}: {message}");
            }
        }
        let message = checked(
            &providers,
            with_variant(
                "owner",
                true,
                serde_json::json!({"complete": true, "target": {"endpoint": "https://203.0.113.30/mcp"}}),
            ),
            true,
        )
        .await
        .expect_err("a complete variant that clears the Target policy");
        assert!(message.starts_with("variant 'candidate' overrides.target.policy: "), "{message}");
    }
}
