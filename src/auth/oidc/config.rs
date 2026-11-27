//! `oidc.json`: the one OpenID provider the dashboard signs in with, the client registered there,
//! and how the provider's claims become a user and a role. Read and checked once at startup; any
//! problem stops startup.

use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

use jsonwebtoken::Algorithm;
use serde::Deserialize;
use serde_json::Value;
use tracing::{info, warn};
use url::Url;
use zeroize::Zeroizing;

use crate::auth::types::UserRole;

/// Where a client secret may come from. A secret written into the file itself (`string://` or no
/// prefix) is refused, so `oidc.json` never holds one.
const SECRET_REFERENCE_PREFIXES: &[&str] = &["env://", "file://", "aws_secrets://", "aws_parameter_store://"];

/// ID token signing algorithms that may be allowed. `none` and the `HS*` family are never among
/// them: an `HS*` token is signed with the client secret, which proves nothing about the provider.
const ALLOWED_SIGNING_ALGS: &[Algorithm] = &[
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::EdDSA,
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OidcFile {
    #[serde(default = "default_label")]
    label: String,
    issuer: String,
    client_id: String,
    client_secret: String,
    #[serde(default)]
    token_endpoint_auth_method: TokenEndpointAuthMethod,
    redirect_uri: String,
    #[serde(default = "default_scopes")]
    scopes: Vec<String>,
    #[serde(default = "default_signing_algs")]
    id_token_signing_algs: Vec<String>,
    #[serde(default)]
    claims: ClaimNames,
    #[serde(default)]
    required_claims: BTreeMap<String, Vec<RawClaimValue>>,
    #[serde(default)]
    allow_any_account: bool,
    role_mapping: RoleMappingFile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoleMappingFile {
    claim: String,
    values: BTreeMap<String, UserRole>,
    #[serde(default = "default_unmapped")]
    unmapped: String,
}

fn default_label() -> String {
    "SSO".to_string()
}

fn default_scopes() -> Vec<String> {
    ["openid", "profile", "email"]
        .map(String::from)
        .to_vec()
}

fn default_signing_algs() -> Vec<String> {
    vec!["ES256".to_string()]
}

fn default_unmapped() -> String {
    "deny".to_string()
}

/// How the client authenticates at the provider's token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    #[default]
    ClientSecretBasic,
    ClientSecretPost,
}

impl TokenEndpointAuthMethod {
    /// The method's name in `oidc.json` and in the provider's discovery document.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
        }
    }
}

/// Which ID token claim fills each profile field. Profile fields are display data only: none of
/// them identifies the person.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ClaimNames {
    pub username: String,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
}

impl Default for ClaimNames {
    fn default() -> Self {
        Self {
            username: "preferred_username".to_string(),
            email: "email".to_string(),
            first_name: "given_name".to_string(),
            last_name: "family_name".to_string(),
        }
    }
}

/// How `oidc.json` marks a value as a regular expression: `regex:<pattern>`. An explicit marker,
/// because ordinary values such as email addresses are full of characters (`.`, `+`) that mean
/// something in a pattern.
const REGEX_PREFIX: &str = "regex:";

/// The longest compiled pattern accepted, in bytes of compiled program.
const MAX_PATTERN_SIZE: usize = 1 << 20;

/// A claim value as `oidc.json` writes it in `required_claims`.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawClaimValue {
    String(String),
    Bool(bool),
}

/// A value from `oidc.json` that a claim value is compared with: a string or a boolean, each
/// matching only its own type exactly (so `true` does not match the string `"true"`), or a
/// `regex:` pattern that must match the whole of a string value.
#[derive(Debug, Clone)]
pub enum ValueMatcher {
    Exact(String),
    Bool(bool),
    Regex(regex::Regex),
}

impl PartialEq for ValueMatcher {
    fn eq(
        &self,
        other: &Self,
    ) -> bool {
        match (self, other) {
            (Self::Exact(a), Self::Exact(b)) => a == b,
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Regex(a), Self::Regex(b)) => a.as_str() == b.as_str(),
            _ => false,
        }
    }
}

impl ValueMatcher {
    /// A string from `oidc.json`: a pattern when it starts with `regex:`, otherwise an exact
    /// value. The pattern is anchored to the whole value.
    pub(crate) fn from_text(
        field: &str,
        text: &str,
    ) -> Result<Self, String> {
        let Some(pattern) = text.strip_prefix(REGEX_PREFIX) else {
            return Ok(Self::Exact(text.to_string()));
        };
        let build = |pattern: &str| {
            regex::RegexBuilder::new(pattern)
                .size_limit(MAX_PATTERN_SIZE)
                .build()
                .map_err(|e| format!("{field}: {text} is not a usable regular expression: {e}"))
        };
        // Compiled alone first: a pattern such as `a)|(b` would otherwise close the anchoring
        // group and match part of a value.
        build(pattern)?;
        build(&format!("^(?:{pattern})$")).map(Self::Regex)
    }

    /// Whether a claim value from a token matches.
    pub fn matches(
        &self,
        value: &Value,
    ) -> bool {
        match (self, value) {
            (Self::Bool(expected), Value::Bool(actual)) => expected == actual,
            (_, Value::String(actual)) => self.matches_str(actual),
            _ => false,
        }
    }

    /// Whether a string claim value matches.
    pub fn matches_str(
        &self,
        value: &str,
    ) -> bool {
        match self {
            Self::Exact(expected) => expected == value,
            Self::Regex(pattern) => pattern.is_match(value),
            Self::Bool(_) => false,
        }
    }
}

/// Which values of one claim grant which role, and what an account with no mapped value gets: a
/// role, or no access (`None`).
#[derive(Debug)]
pub struct RoleMapping {
    pub claim: String,
    pub values: Vec<(ValueMatcher, UserRole)>,
    pub unmapped: Option<UserRole>,
}

/// The resolved client secret, zeroed when dropped. Its `Debug` output never shows the value.
pub struct ClientSecret(pub(super) Zeroizing<String>);

impl ClientSecret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ClientSecret {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.write_str("ClientSecret(<redacted>)")
    }
}

/// A checked `oidc.json`, with its client secret resolved.
#[derive(Debug)]
pub struct OidcConfig {
    pub label: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: ClientSecret,
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    pub redirect_uri: Url,
    pub scopes: Vec<String>,
    pub id_token_signing_algs: Vec<Algorithm>,
    pub claims: ClaimNames,
    pub required_claims: BTreeMap<String, Vec<ValueMatcher>>,
    pub role_mapping: RoleMapping,
}

impl OidcConfig {
    /// Read, check and resolve `oidc.json`.
    pub async fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| format!("Failed to read OIDC config file: {}", e))?;
        Self::from_json(&content).await
    }

    pub(crate) async fn from_json(content: &str) -> Result<Self, String> {
        let file: OidcFile =
            serde_json::from_str(content).map_err(|e| format!("Failed to parse OIDC config JSON: {}", e))?;
        let checked = check(file)?;
        let client_id = resolve_client_id(&checked.client_id).await?;
        let client_secret = resolve_client_secret(&checked.client_secret_reference).await?;
        Ok(Self {
            label: checked.label,
            issuer: checked.issuer,
            client_id,
            client_secret,
            token_endpoint_auth_method: checked.token_endpoint_auth_method,
            redirect_uri: checked.redirect_uri,
            scopes: checked.scopes,
            id_token_signing_algs: checked.id_token_signing_algs,
            claims: checked.claims,
            required_claims: checked.required_claims,
            role_mapping: checked.role_mapping,
        })
    }

    /// The provider's discovery document address (OpenID Connect Discovery 1.0 section 4: one
    /// trailing `/` of the issuer is dropped first).
    pub fn discovery_url(&self) -> String {
        format!(
            "{}/.well-known/openid-configuration",
            self.issuer
                .strip_suffix('/')
                .unwrap_or(&self.issuer)
        )
    }
}

/// Everything in the file but the secret, checked.
struct CheckedFile {
    label: String,
    issuer: String,
    client_id: String,
    client_secret_reference: String,
    token_endpoint_auth_method: TokenEndpointAuthMethod,
    redirect_uri: Url,
    scopes: Vec<String>,
    id_token_signing_algs: Vec<Algorithm>,
    claims: ClaimNames,
    required_claims: BTreeMap<String, Vec<ValueMatcher>>,
    role_mapping: RoleMapping,
}

fn check(file: OidcFile) -> Result<CheckedFile, String> {
    let label = non_empty("label", file.label)?;
    let issuer_url = provider_url("issuer", &file.issuer)?;
    if issuer_url.query().is_some() {
        return Err("issuer must not have a query".to_string());
    }
    let client_id = non_empty("client_id", file.client_id)?;
    if !SECRET_REFERENCE_PREFIXES
        .iter()
        .any(|prefix| {
            file.client_secret
                .starts_with(prefix)
        })
    {
        return Err(format!(
            "client_secret must be a secret reference starting with {}",
            SECRET_REFERENCE_PREFIXES.join(", ")
        ));
    }
    let redirect_uri = provider_url("redirect_uri", &file.redirect_uri)?;
    if !file
        .scopes
        .iter()
        .any(|scope| scope == "openid")
    {
        return Err("scopes must include openid".to_string());
    }
    let id_token_signing_algs = signing_algs(&file.id_token_signing_algs)?;
    for (field, claim) in [
        ("claims.username", &file.claims.username),
        ("claims.email", &file.claims.email),
        ("claims.first_name", &file.claims.first_name),
        ("claims.last_name", &file.claims.last_name),
    ] {
        if claim.trim().is_empty() {
            return Err(format!("{field} must not be empty"));
        }
    }
    let required_claims = required_claims(file.required_claims)?;
    let role_mapping = role_mapping(file.role_mapping)?;
    check_tenant_binding(&file.issuer, &required_claims, &role_mapping, file.allow_any_account)?;
    Ok(CheckedFile {
        label,
        issuer: file.issuer,
        client_id,
        client_secret_reference: file.client_secret,
        token_endpoint_auth_method: file.token_endpoint_auth_method,
        redirect_uri,
        scopes: file.scopes,
        id_token_signing_algs,
        claims: file.claims,
        required_claims,
        role_mapping,
    })
}

/// Refuse a file that does not tie sign-in to one tenant at the provider, unless it opts out
/// with `allow_any_account` and refuses unmapped accounts; and refuse an `unmapped` role that a
/// weak binding (only booleans or patterns) would give to every tenant's accounts. Log how far
/// the binding goes.
fn check_tenant_binding(
    issuer: &str,
    required_claims: &BTreeMap<String, Vec<ValueMatcher>>,
    role_mapping: &RoleMapping,
    allow_any_account: bool,
) -> Result<(), String> {
    if !binds_anything(required_claims) {
        if !allow_any_account {
            return Err("required_claims must name at least one claim that binds sign-in to your tenant at the \
                 provider (iss, aud and azp are tied to the issuer and client_id and cannot name a tenant), or set \
                 allow_any_account to true to let every account at the provider sign in"
                .to_string());
        }
        if role_mapping
            .unmapped
            .is_some()
        {
            return Err("allow_any_account requires role_mapping.unmapped to be deny: with no tenant binding, an \
                 unmapped role would go to every account at the provider"
                .to_string());
        }
        warn!(
            event = "oidc_tenant_binding_disabled",
            issuer = %issuer,
            unmapped = "deny",
            "oidc.json sets allow_any_account without a tenant binding: every account at the OpenID provider that \
             role_mapping maps can sign in"
        );
        return Ok(());
    }
    let bound = exact_value_claims(required_claims);
    if !bound.is_empty() {
        info!(issuer = %issuer, claims = %bound.join(", "), "required_claims ties sign-in to the tenant");
    } else if role_mapping
        .unmapped
        .is_some()
    {
        let judged = bindable_entries(required_claims)
            .map(|(claim, _)| claim.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "role_mapping.unmapped must be deny unless a required_claims entry lists only exact values of a claim \
             that names your tenant: the entries other than iss, aud and azp ({judged}) allow booleans or patterns, \
             which match accounts of every tenant, so an unmapped role would go to all of them. List an exact tenant \
             value such as org_id, or set role_mapping.unmapped to deny"
        ));
    } else if holds_exact_value(required_claims) {
        info!(
            issuer = %issuer,
            "every required_claims entry mixes exact values with patterns or booleans: check that each allowed \
             value belongs to your tenant"
        );
    } else {
        warn!(
            issuer = %issuer,
            "every required_claims entry is a boolean or a pattern, so it may not tie sign-in to your tenant: \
             either can match accounts of every tenant at the OpenID provider"
        );
    }
    Ok(())
}

fn required_claims(file: BTreeMap<String, Vec<RawClaimValue>>) -> Result<BTreeMap<String, Vec<ValueMatcher>>, String> {
    file.into_iter()
        .map(|(claim, allowed)| {
            if claim.trim().is_empty() {
                return Err("required_claims has an empty claim name".to_string());
            }
            if allowed.is_empty() {
                return Err(format!("required_claims.{claim} must list at least one allowed value"));
            }
            let field = format!("required_claims.{claim}");
            let allowed = allowed
                .into_iter()
                .map(|value| match value {
                    RawClaimValue::String(text) if text.trim().is_empty() => {
                        Err(format!("{field} must not list a blank value"))
                    }
                    RawClaimValue::String(text) => ValueMatcher::from_text(&field, &text),
                    RawClaimValue::Bool(value) => Ok(ValueMatcher::Bool(value)),
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((claim, allowed))
        })
        .collect()
}

/// Claims tied to the issuer and to this client, not to a tenant: `iss` is the configured issuer,
/// and `aud` and `azp` name `client_id`. An entry on one of them cannot tell one tenant's accounts
/// from another's, so it binds nothing.
const NON_TENANT_CLAIMS: &[&str] = &["iss", "aud", "azp"];

/// The `required_claims` entries that can name a tenant: every entry but those on
/// [`NON_TENANT_CLAIMS`].
fn bindable_entries(
    required: &BTreeMap<String, Vec<ValueMatcher>>
) -> impl Iterator<Item = (&String, &Vec<ValueMatcher>)> {
    required
        .iter()
        .filter(|(claim, _)| !NON_TENANT_CLAIMS.contains(&claim.as_str()))
}

/// Whether some `required_claims` entry is on a claim that can name a tenant.
fn binds_anything(required: &BTreeMap<String, Vec<ValueMatcher>>) -> bool {
    bindable_entries(required)
        .next()
        .is_some()
}

/// A boolean, or the string `"true"` or `"false"` in any case that a provider may send in its
/// place.
fn is_boolean_like(value: &ValueMatcher) -> bool {
    match value {
        ValueMatcher::Bool(_) => true,
        ValueMatcher::Exact(text) => text.eq_ignore_ascii_case("true") || text.eq_ignore_ascii_case("false"),
        ValueMatcher::Regex(_) => false,
    }
}

/// Whether a value can name one tenant: an exact string. A boolean-like value or a `regex:`
/// pattern can match accounts of any tenant.
fn is_exact_tenant_value(value: &ValueMatcher) -> bool {
    matches!(value, ValueMatcher::Exact(_)) && !is_boolean_like(value)
}

/// The `required_claims` entries that allow only exact string values, the shape that can name
/// one tenant.
fn exact_value_claims(required: &BTreeMap<String, Vec<ValueMatcher>>) -> Vec<&str> {
    bindable_entries(required)
        .filter(|(_, allowed)| {
            allowed
                .iter()
                .all(is_exact_tenant_value)
        })
        .map(|(claim, _)| claim.as_str())
        .collect()
}

/// Whether any `required_claims` entry allows at least one exact string value.
fn holds_exact_value(required: &BTreeMap<String, Vec<ValueMatcher>>) -> bool {
    bindable_entries(required)
        .flat_map(|(_, allowed)| allowed)
        .any(is_exact_tenant_value)
}

fn non_empty(
    field: &str,
    value: String,
) -> Result<String, String> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(value)
}

/// Parse an address the provider or the browser is sent to, and refuse one that is not `https`
/// (see [`transport_problem`]), has a fragment, or carries user information.
fn provider_url(
    field: &str,
    raw: &str,
) -> Result<Url, String> {
    let url = Url::parse(raw).map_err(|_| format!("{field} is not an absolute URL"))?;
    if let Some(problem) = transport_problem(&url) {
        return Err(format!("{field} {problem}"));
    }
    if url.fragment().is_some() {
        return Err(format!("{field} must not have a fragment"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{field} must not contain user information"));
    }
    Ok(url)
}

/// Why a provider address cannot be used, if it cannot. Tokens are trusted partly because they
/// arrive over TLS, so every address is `https`. A debug build also accepts `http` to a loopback
/// host, for a provider running on the same machine during development; a release build never
/// does.
pub(crate) fn transport_problem(url: &Url) -> Option<&'static str> {
    match url.scheme() {
        "https" => None,
        "http" if cfg!(debug_assertions) && is_loopback(url) => None,
        _ => Some("must start with https://"),
    }
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn signing_algs(names: &[String]) -> Result<Vec<Algorithm>, String> {
    if names.is_empty() {
        return Err("id_token_signing_algs must list at least one algorithm".to_string());
    }
    names
        .iter()
        .map(|name| {
            Algorithm::from_str(name)
                .ok()
                .filter(|algorithm| ALLOWED_SIGNING_ALGS.contains(algorithm))
                .ok_or_else(|| format!("id_token_signing_algs: {name} is not an allowed ID token signing algorithm"))
        })
        .collect()
}

fn role_mapping(file: RoleMappingFile) -> Result<RoleMapping, String> {
    if file.claim.trim().is_empty() {
        return Err("role_mapping.claim must not be empty".to_string());
    }
    if file.values.is_empty() {
        return Err("role_mapping.values must map at least one value to a role".to_string());
    }
    let unmapped = match file.unmapped.as_str() {
        "deny" => None,
        other => Some(UserRole::from_config_name(other).ok_or_else(|| {
            format!("role_mapping.unmapped must be deny, administrator, poweruser or user, not {other}")
        })?),
    };
    let values = file
        .values
        .into_iter()
        .map(|(text, role)| Ok((ValueMatcher::from_text("role_mapping.values", &text)?, role)))
        .collect::<Result<Vec<_>, String>>()?;
    Ok(RoleMapping {
        claim: file.claim,
        values,
        unmapped,
    })
}

/// Resolve a secret reference to its trimmed, non-empty value. The `file://` loader keeps a
/// file's trailing newline, which no client credential has.
async fn resolve_reference(
    field: &str,
    reference: &str,
) -> Result<Zeroizing<String>, String> {
    let value = Zeroizing::new(
        crate::config::loaders::load(reference)
            .await
            .map_err(|e| format!("{field} could not be resolved: {}", e))?,
    );
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} resolved to an empty value"));
    }
    Ok(Zeroizing::new(trimmed.to_string()))
}

/// The client id is not secret (the provider shows it in every sign-in address), so it may be
/// written in the file, or given as a secret reference to keep it beside the client secret.
async fn resolve_client_id(client_id: &str) -> Result<String, String> {
    if SECRET_REFERENCE_PREFIXES
        .iter()
        .any(|prefix| client_id.starts_with(prefix))
    {
        resolve_reference("client_id", client_id)
            .await
            .map(|value| value.to_string())
    } else {
        Ok(client_id.to_string())
    }
}

async fn resolve_client_secret(reference: &str) -> Result<ClientSecret, String> {
    resolve_reference("client_secret", reference)
        .await
        .map(ClientSecret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component_tests::helpers::formatted_logs::FormattedLogs;
    use serde_json::{Value, json};

    fn valid_file() -> Value {
        json!({
            "label": "Example Directory",
            "issuer": "https://idp.example.com",
            "client_id": "agent-gateway",
            "client_secret": "file://SECRET_FILE",
            "redirect_uri": "https://gateway.example.com/api/oidc/callback",
            "required_claims": { "org_id": ["org_123"] },
            "role_mapping": {
                "claim": "roles",
                "values": { "admin": "administrator", "member": "user" }
            }
        })
    }

    fn with(
        mut file: Value,
        path: &[&str],
        value: Value,
    ) -> Value {
        let (last, parents) = path.split_last().unwrap();
        let mut target = &mut file;
        for key in parents {
            target = target.get_mut(*key).unwrap();
        }
        target[*last] = value;
        file
    }

    fn without(
        mut file: Value,
        key: &str,
    ) -> Value {
        file.as_object_mut()
            .unwrap()
            .remove(key);
        file
    }

    /// Load `file` with its `file://SECRET_FILE` reference pointing at a file holding `secret`.
    async fn load_with_secret(
        file: Value,
        secret: &str,
    ) -> Result<OidcConfig, String> {
        let secret_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(secret_file.path(), secret).unwrap();
        let json = file.to_string().replace(
            "SECRET_FILE",
            secret_file
                .path()
                .to_str()
                .unwrap(),
        );
        OidcConfig::from_json(&json).await
    }

    async fn load(file: Value) -> Result<OidcConfig, String> {
        load_with_secret(file, " s3cret\n").await
    }

    /// Load `file`, returning what it logged.
    async fn logs_of(file: Value) -> (String, Result<OidcConfig, String>) {
        let logs = FormattedLogs::capture();
        let loaded = load(file).await;
        (logs.text(), loaded)
    }

    #[tokio::test]
    async fn a_valid_file_loads_with_its_defaults() {
        let config = load(valid_file())
            .await
            .unwrap();

        assert_eq!(config.label, "Example Directory");
        assert_eq!(config.client_secret.expose(), "s3cret", "the resolved secret is trimmed");
        assert_eq!(config.token_endpoint_auth_method, TokenEndpointAuthMethod::ClientSecretBasic);
        assert_eq!(config.scopes, ["openid", "profile", "email"]);
        assert_eq!(config.id_token_signing_algs, [Algorithm::ES256]);
        assert_eq!(config.claims.username, "preferred_username");
        assert_eq!(config.role_mapping.unmapped, None, "an unmapped account is refused by default");
        assert!(
            config
                .role_mapping
                .values
                .contains(&(ValueMatcher::Exact("admin".to_string()), UserRole::Administrator))
        );
        assert!(!format!("{config:?}").contains("s3cret"), "the secret never reaches Debug output");
    }

    #[test]
    fn the_example_file_passes_every_check_but_the_secret() {
        let file: OidcFile = serde_json::from_str(include_str!("../../../config/examples/oidc.example.json")).unwrap();

        let checked = check(file).unwrap();

        assert_eq!(checked.client_secret_reference, "env://AG_OIDC_CLIENT_SECRET");
        assert_eq!(checked.role_mapping.unmapped, None);
        assert_eq!(exact_value_claims(&checked.required_claims), ["org_id"]);
    }

    #[tokio::test]
    async fn the_client_id_may_be_written_in_the_file_or_referenced() {
        let config = load(valid_file())
            .await
            .unwrap();
        assert_eq!(config.client_id, "agent-gateway", "a plain value is used as written");

        let config = load(with(valid_file(), &["client_id"], json!("file://SECRET_FILE")))
            .await
            .unwrap();
        assert_eq!(config.client_id, "s3cret", "a reference is resolved and trimmed, never sent as written");

        let refused = load(with(valid_file(), &["client_id"], json!("env://AG_TEST_OIDC_UNSET_CLIENT_ID")))
            .await
            .unwrap_err();
        assert!(refused.contains("client_id could not be resolved"), "{refused}");
    }

    #[tokio::test]
    async fn a_secret_written_into_the_file_is_refused() {
        for secret in ["string://s3cret", "s3cret"] {
            let refused = load(with(valid_file(), &["client_secret"], json!(secret)))
                .await
                .unwrap_err();
            assert!(refused.contains("secret reference"), "{secret}: {refused}");
        }
    }

    #[tokio::test]
    async fn a_secret_that_resolves_to_nothing_is_refused() {
        let refused = load(with(valid_file(), &["client_secret"], json!("env://AG_TEST_OIDC_UNSET_SECRET")))
            .await
            .unwrap_err();
        assert!(refused.contains("client_secret could not be resolved"), "{refused}");

        let refused = load_with_secret(valid_file(), " \n")
            .await
            .unwrap_err();
        assert!(refused.contains("empty"), "{refused}");
    }

    #[tokio::test]
    async fn only_asymmetric_signing_algorithms_are_allowed() {
        for alg in ["none", "HS256", "HS512", "XX1"] {
            let refused = load(with(valid_file(), &["id_token_signing_algs"], json!(["ES256", alg])))
                .await
                .unwrap_err();
            assert!(refused.contains(alg), "{alg}: {refused}");
        }
        let refused = load(with(valid_file(), &["id_token_signing_algs"], json!([])))
            .await
            .unwrap_err();
        assert!(refused.contains("at least one"), "{refused}");

        let config = load(with(valid_file(), &["id_token_signing_algs"], json!(["RS256", "PS256", "EdDSA"])))
            .await
            .unwrap();
        assert_eq!(config.id_token_signing_algs, [Algorithm::RS256, Algorithm::PS256, Algorithm::EdDSA]);
    }

    #[tokio::test]
    async fn the_role_mapping_must_name_known_roles() {
        let refused = load(with(valid_file(), &["role_mapping", "values"], json!({ "admin": "owner" })))
            .await
            .unwrap_err();
        assert!(refused.contains("owner"), "{refused}");

        let refused = load(with(valid_file(), &["role_mapping", "values"], json!({ "admin": "Administrator" })))
            .await
            .unwrap_err();
        assert!(refused.contains("Administrator"), "role names are exact: {refused}");

        let refused = load(with(valid_file(), &["role_mapping", "values"], json!({})))
            .await
            .unwrap_err();
        assert!(refused.contains("at least one value"), "{refused}");

        let refused = load(with(valid_file(), &["role_mapping", "unmapped"], json!("guest")))
            .await
            .unwrap_err();
        assert!(refused.contains("guest"), "{refused}");

        let refused = load(with(valid_file(), &["role_mapping", "claim"], json!(" ")))
            .await
            .unwrap_err();
        assert!(refused.contains("role_mapping.claim"), "{refused}");

        let config = load(with(valid_file(), &["role_mapping", "unmapped"], json!("user")))
            .await
            .unwrap();
        assert_eq!(config.role_mapping.unmapped, Some(UserRole::User));
    }

    #[tokio::test]
    async fn a_misspelt_field_stops_startup_rather_than_being_ignored() {
        let binding = valid_file()["required_claims"].clone();
        let file = with(without(valid_file(), "required_claims"), &["required_claim"], binding);

        let refused = load(file).await.unwrap_err();
        assert!(refused.contains("unknown field"), "{refused}");

        for (path, value) in
            [(&["role_mapping", "unmaped"][..], json!("user")), (&["claims"][..], json!({ "user_name": "name" }))]
        {
            let refused = load(with(valid_file(), path, value))
                .await
                .unwrap_err();
            assert!(refused.contains("unknown field"), "{path:?}: {refused}");
        }
    }

    #[tokio::test]
    async fn the_issuer_and_redirect_uri_must_be_https() {
        for (field, value, expected) in [
            ("issuer", "http://idp.example.com", "must start with https://"),
            ("issuer", "https://idp.example.com?tenant=1", "must not have a query"),
            ("issuer", "https://idp.example.com#top", "must not have a fragment"),
            ("issuer", "idp.example.com", "not an absolute URL"),
            ("redirect_uri", "http://gateway.example.com/api/oidc/callback", "must start with https://"),
            ("redirect_uri", "https://user:pw@gateway.example.com/api/oidc/callback", "user information"),
        ] {
            let refused = load(with(valid_file(), &[field], json!(value)))
                .await
                .unwrap_err();
            assert!(refused.contains(expected), "{field}={value}: {refused}");
        }
    }

    #[test]
    fn plain_http_is_accepted_only_to_this_machine_in_a_debug_build() {
        let local = Url::parse("http://127.0.0.1:8080").unwrap();
        let remote = Url::parse("http://idp.example.com").unwrap();

        assert_eq!(transport_problem(&local).is_none(), cfg!(debug_assertions));
        assert!(transport_problem(&remote).is_some());
        assert!(transport_problem(&Url::parse("ftp://127.0.0.1").unwrap()).is_some());
    }

    #[tokio::test]
    async fn scopes_must_include_openid_and_lists_must_not_be_empty() {
        let refused = load(with(valid_file(), &["scopes"], json!(["profile", "email"])))
            .await
            .unwrap_err();
        assert!(refused.contains("openid"), "{refused}");

        let refused = load(with(valid_file(), &["required_claims"], json!({ "org_id": [] })))
            .await
            .unwrap_err();
        assert!(refused.contains("required_claims.org_id"), "{refused}");

        let refused = load(with(valid_file(), &["claims"], json!({ "username": "" })))
            .await
            .unwrap_err();
        assert!(refused.contains("claims.username"), "{refused}");
    }

    #[tokio::test]
    async fn a_required_claim_may_allow_strings_and_booleans_but_nothing_else() {
        let config = load(with(
            valid_file(),
            &["required_claims"],
            json!({ "org_id": ["org_123"], "email_verified": [true, "true"] }),
        ))
        .await
        .unwrap();
        assert_eq!(
            config.required_claims["email_verified"],
            [ValueMatcher::Bool(true), ValueMatcher::Exact("true".to_string())]
        );
        assert_eq!(config.required_claims["org_id"], [ValueMatcher::Exact("org_123".to_string())]);

        for value in [json!([123]), json!([null]), json!([{"org": "org_123"}]), json!("org_123")] {
            let refused = load(with(valid_file(), &["required_claims"], json!({ "org_id": value })))
                .await
                .unwrap_err();
            assert!(refused.contains("Failed to parse OIDC config JSON"), "{value}: {refused}");
        }
    }

    #[tokio::test]
    async fn a_regex_value_is_compiled_at_startup_and_anything_else_is_exact() {
        let config = load(with(
            valid_file(),
            &["role_mapping", "values"],
            json!({ "regex:.*@example\\.com": "poweruser", "jo.doe@example.com": "administrator" }),
        ))
        .await
        .unwrap();
        let (pattern, role) = config
            .role_mapping
            .values
            .iter()
            .find(|(matcher, _)| matches!(matcher, ValueMatcher::Regex(_)))
            .unwrap();
        assert_eq!(role, &UserRole::PowerUser);
        assert!(pattern.matches_str("someone@example.com"));
        assert!(
            config
                .role_mapping
                .values
                .contains(&(ValueMatcher::Exact("jo.doe@example.com".to_string()), UserRole::Administrator)),
            "a value with dots is still exact"
        );

        let config = load(with(valid_file(), &["role_mapping", "values"], json!({ "regex:a|b": "user" })))
            .await
            .unwrap();
        let (alternation, _) = &config.role_mapping.values[0];
        assert!(alternation.matches_str("b"));
        assert!(!alternation.matches_str("ab"), "an alternation stays anchored");

        for (path, value) in [
            (&["role_mapping", "values"][..], json!({ "regex:(unclosed": "user" })),
            (&["required_claims"][..], json!({ "org_id": ["org_123"], "email": ["regex:[a-"] })),
            (&["required_claims"][..], json!({ "org_id": ["org_123"], "email": ["regex:x)|(.*"] })),
        ] {
            let refused = load(with(valid_file(), path, value))
                .await
                .unwrap_err();
            assert!(refused.contains("is not a usable regular expression"), "{refused}");
        }
    }

    #[tokio::test]
    async fn the_discovery_address_drops_one_trailing_slash_of_the_issuer() {
        let config = load(with(valid_file(), &["issuer"], json!("https://tenant.auth.example/")))
            .await
            .unwrap();
        assert_eq!(config.issuer, "https://tenant.auth.example/", "the issuer is kept exactly as written");
        assert_eq!(config.discovery_url(), "https://tenant.auth.example/.well-known/openid-configuration");

        let config = load(with(valid_file(), &["issuer"], json!("https://id.example/realms/example")))
            .await
            .unwrap();
        assert_eq!(config.discovery_url(), "https://id.example/realms/example/.well-known/openid-configuration");
    }

    #[tokio::test]
    async fn the_client_authentication_method_is_basic_or_post() {
        let config = load(with(valid_file(), &["token_endpoint_auth_method"], json!("client_secret_post")))
            .await
            .unwrap();
        assert_eq!(config.token_endpoint_auth_method, TokenEndpointAuthMethod::ClientSecretPost);

        let refused = load(with(valid_file(), &["token_endpoint_auth_method"], json!("private_key_jwt")))
            .await
            .unwrap_err();
        assert!(refused.contains("private_key_jwt"), "{refused}");
    }

    #[tokio::test]
    async fn a_file_without_a_tenant_binding_is_refused_unless_it_opts_out() {
        let unbound = without(valid_file(), "required_claims");

        for file in [unbound.clone(), with(valid_file(), &["required_claims"], json!({}))] {
            let refused = load(file).await.unwrap_err();
            assert!(refused.contains("required_claims"), "{refused}");
            assert!(refused.contains("allow_any_account"), "{refused}");
        }

        let config = load(with(unbound, &["allow_any_account"], json!(true)))
            .await
            .unwrap();
        assert!(
            config
                .required_claims
                .is_empty()
        );
    }

    #[test]
    fn only_an_entry_of_exact_values_can_name_a_tenant() {
        let exact = |text: &str| ValueMatcher::Exact(text.to_string());
        let pattern = |text: &str| ValueMatcher::from_text("required_claims.x", text).unwrap();
        let claims = |entries: &[(&str, Vec<ValueMatcher>)]| {
            entries
                .iter()
                .cloned()
                .map(|(claim, allowed)| (claim.to_string(), allowed))
                .collect::<BTreeMap<_, _>>()
        };

        assert_eq!(exact_value_claims(&claims(&[("org_id", vec![exact("org_123")])])), ["org_id"]);
        assert_eq!(
            exact_value_claims(&claims(&[
                ("email_verified", vec![ValueMatcher::Bool(true)]),
                ("org_id", vec![exact("org_1"), exact("org_2")]),
            ])),
            ["org_id"]
        );
        for unbound in [
            claims(&[("email_verified", vec![ValueMatcher::Bool(true)])]),
            claims(&[("email_verified", vec![exact("true")])]),
            claims(&[("email_verified", vec![exact("False")])]),
            claims(&[("org_id", vec![pattern("regex:.*")])]),
            claims(&[("org_id", vec![exact("org_123"), pattern("regex:.*")])]),
        ] {
            assert!(exact_value_claims(&unbound).is_empty(), "{unbound:?}");
        }
    }

    #[test]
    fn a_mixed_entry_holds_an_exact_value_but_a_boolean_or_pattern_alone_does_not() {
        let exact = |text: &str| ValueMatcher::Exact(text.to_string());
        let pattern = |text: &str| ValueMatcher::from_text("required_claims.x", text).unwrap();
        let claims = |allowed: Vec<ValueMatcher>| BTreeMap::from([("org_id".to_string(), allowed)]);

        assert!(holds_exact_value(&claims(vec![exact("org_1"), pattern("regex:org_1_.*")])));
        assert!(!holds_exact_value(&claims(vec![pattern("regex:.*")])));
        assert!(!holds_exact_value(&claims(vec![ValueMatcher::Bool(true)])));
        assert!(!holds_exact_value(&claims(vec![exact("TRUE")])));
    }

    #[tokio::test]
    async fn a_blank_required_claim_value_is_refused() {
        for blank in ["", "  "] {
            let refused = load(with(valid_file(), &["required_claims"], json!({ "org_id": [blank] })))
                .await
                .unwrap_err();
            assert!(refused.contains("required_claims.org_id"), "{refused}");
            assert!(refused.contains("blank"), "{refused}");
        }
    }

    #[tokio::test]
    async fn a_claim_tied_to_the_issuer_or_client_is_no_tenant_binding() {
        let issuer_and_client_claims =
            json!({ "iss": ["https://idp.example.com"], "aud": ["agent-gateway"], "azp": ["agent-gateway"] });
        for claims in [json!({ "iss": ["https://idp.example.com"] }), issuer_and_client_claims] {
            let refused = load(with(valid_file(), &["required_claims"], claims))
                .await
                .unwrap_err();
            assert!(refused.contains("iss, aud and azp"), "{refused}");
            assert!(refused.contains("allow_any_account"), "{refused}");
        }

        let config = load(with(
            valid_file(),
            &["required_claims"],
            json!({ "iss": ["https://idp.example.com"], "org_id": ["org_123"] }),
        ))
        .await
        .unwrap();
        assert_eq!(config.required_claims.len(), 2, "an entry that binds keeps its neighbours");

        let opted_out = with(valid_file(), &["required_claims"], json!({ "iss": ["https://idp.example.com"] }));
        assert!(
            load(with(opted_out, &["allow_any_account"], json!(true)))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn the_opt_out_is_logged_as_a_warning_event_and_a_bound_file_is_not() {
        let unbound = with(without(valid_file(), "required_claims"), &["allow_any_account"], json!(true));

        let (logs, config) = logs_of(unbound).await;
        config.unwrap();
        assert!(logs.contains("oidc_tenant_binding_disabled"), "{logs}");
        assert!(logs.contains("idp.example.com"), "{logs}");

        let (logs, config) = logs_of(valid_file()).await;
        config.unwrap();
        assert!(!logs.contains("oidc_tenant_binding_disabled"), "{logs}");
    }

    #[tokio::test]
    async fn startup_says_how_far_required_claims_ties_sign_in_to_a_tenant() {
        let logs_for = |claims: Value| async move {
            let (logs, config) = logs_of(with(valid_file(), &["required_claims"], claims)).await;
            config.unwrap();
            logs
        };

        let exact = logs_for(json!({ "org_id": ["org_123"], "email_verified": [true] })).await;
        assert!(exact.contains("ties sign-in to the tenant"), "{exact}");
        assert!(exact.contains("org_id"), "{exact}");
        assert!(!exact.contains("WARN"), "{exact}");

        let mixed = logs_for(json!({ "org_id": ["org_1", "regex:org_1_.*"] })).await;
        assert!(mixed.contains("mixes exact values"), "{mixed}");
        assert!(!mixed.contains("WARN"), "{mixed}");

        for weak in
            [json!({ "email_verified": [true] }), json!({ "org_id": ["regex:.*"] }), json!({ "org_id": ["true"] })]
        {
            let weak = logs_for(weak).await;
            assert!(weak.contains("WARN"), "{weak}");
            assert!(weak.contains("boolean or a pattern"), "{weak}");
        }
    }

    #[tokio::test]
    async fn opting_out_of_the_tenant_binding_needs_unmapped_accounts_denied() {
        let unbound = with(without(valid_file(), "required_claims"), &["allow_any_account"], json!(true));

        for role in ["administrator", "poweruser", "user"] {
            let refused = load(with(unbound.clone(), &["role_mapping", "unmapped"], json!(role)))
                .await
                .unwrap_err();
            assert!(refused.contains("allow_any_account"), "{refused}");
            assert!(refused.contains("role_mapping.unmapped"), "{refused}");
        }

        let bound = with(valid_file(), &["allow_any_account"], json!(true));
        let config = load(with(bound, &["role_mapping", "unmapped"], json!("user")))
            .await
            .unwrap();
        assert_eq!(config.role_mapping.unmapped, Some(UserRole::User), "a bound file may still grant a role");
        assert_eq!(config.required_claims["org_id"], [ValueMatcher::Exact("org_123".to_string())]);
    }

    #[tokio::test]
    async fn a_binding_with_no_exact_tenant_entry_is_refused_when_unmapped_accounts_get_a_role() {
        let file = |claims: Value, unmapped: &str| {
            with(with(valid_file(), &["required_claims"], claims), &["role_mapping", "unmapped"], json!(unmapped))
        };

        for claims in [
            json!({ "email_verified": [true] }),
            json!({ "email_verified": ["True", "TRUE"], "mfa": ["False"] }),
            json!({ "iss": ["https://idp.example.com"], "email_verified": [true] }),
            json!({ "email": ["regex:.*@example\\.com"] }),
            json!({ "org_id": ["org_1", "regex:.*"] }),
        ] {
            for role in ["administrator", "poweruser", "user"] {
                let refused = load(file(claims.clone(), role))
                    .await
                    .unwrap_err();
                assert!(refused.contains("role_mapping.unmapped must be deny"), "{refused}");
                assert!(refused.contains("iss, aud and azp"), "{refused}");
            }
            let config = load(file(claims, "deny"))
                .await
                .unwrap();
            assert_eq!(config.role_mapping.unmapped, None);
        }

        let config = load(file(json!({ "org_id": ["org_1"], "email_verified": ["True"] }), "user"))
            .await
            .unwrap();
        assert_eq!(config.role_mapping.unmapped, Some(UserRole::User), "an exact entry may grant a role");
    }
}
