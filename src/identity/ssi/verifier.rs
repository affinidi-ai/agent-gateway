use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use anyhow::{Context as AnyhowContext, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use did_peer::resolve_did_peer;
use serde_json::Value;
use ssi::claims::data_integrity::{AnyDataIntegrity, AnySuite, Proof, Proofs};
use ssi::claims::vc::v2::syntax::{JsonCredential, JsonPresentation};
use ssi::claims::{ProofValidationError, Verification, VerificationParameters};
use ssi::dids::document::{self, representation::MediaType};
use ssi::dids::resolution::{self, Options};
use ssi::dids::{AnyDidMethod, DID, DIDResolver, DIDURL, VerificationMethodDIDResolver};
use ssi::verification_methods::{AnyMethod, ControllerProvider, ProofPurpose};

use super::context::create_signature_environment;
use super::vp_issuer::VP_LIFETIME_MINUTES;

/// The one cryptosuite `ssi` cannot parse, and the one the Verifiable Trust
/// Agent produces. Its presence on a proof is what routes that proof to
/// `affinidi-data-integrity` instead.
const JCS_CRYPTOSUITE: &str = "eddsa-jcs-2022";

#[allow(dead_code)]
pub struct VcVerificationResult {
    pub issuer_did: String,
    pub subject_did: String,
    pub identity_fields: HashMap<String, Value>,
}

pub struct VpVerificationResult {
    pub holder_did: String,
    pub credentials: Vec<VcVerificationResult>,
    /// Raw `verifiableCredential` entries from the verified VP, preserved so
    /// downstream gateways can flatten this hop's VCs into a chained-provenance
    /// VP they re-issue. Order matches the inbound VP.
    pub raw_credentials: Vec<Value>,
    /// The audiences the presentation's proof names in `domain` (a string or an
    /// array of strings), empty when it names none.
    pub domains: Vec<String>,
    pub challenge: Option<String>,
}

#[async_trait]
pub trait Verifier: Send + Sync {
    async fn verify_vp(
        &self,
        presentation: &Value,
    ) -> Result<VpVerificationResult>;
}

pub struct LocalVerifier {
    did_cache: Arc<DIDCacheClient>,
}

impl LocalVerifier {
    pub fn new(did_cache: Arc<DIDCacheClient>) -> Self {
        Self { did_cache }
    }
}

#[derive(Default)]
struct ResolvedDocuments {
    documents: HashMap<String, resolution::Output<Vec<u8>>>,
    from_cache: HashSet<String>,
}

/// Resolves DIDs for one verification. A DID resolved through the DID cache is resolved once and
/// its document reused, so the signature and proof purpose checks of a presentation read the same
/// document.
struct CompositeResolver {
    ssi_resolver: AnyDidMethod,
    did_cache: Arc<DIDCacheClient>,
    resolved: Arc<std::sync::Mutex<ResolvedDocuments>>,
}

/// The DIDs a [`CompositeResolver`] answered from the DID cache rather than a fresh resolution.
struct CachedDocuments(Arc<std::sync::Mutex<ResolvedDocuments>>);

impl CachedDocuments {
    fn contains(
        &self,
        did: &str,
    ) -> bool {
        self.0
            .lock()
            .is_ok_and(|resolved| {
                resolved
                    .from_cache
                    .contains(did)
            })
    }
}

impl CompositeResolver {
    fn new(did_cache: Arc<DIDCacheClient>) -> Self {
        Self {
            ssi_resolver: AnyDidMethod::default(),
            did_cache,
            resolved: Arc::default(),
        }
    }

    fn cached_documents(&self) -> CachedDocuments {
        CachedDocuments(self.resolved.clone())
    }

    async fn resolve_peer_did(
        &self,
        did_str: &str,
    ) -> Result<Vec<u8>, resolution::Error> {
        let doc_json = resolve_did_peer(did_str)
            .await
            .map_err(|e| resolution::Error::Internal(format!("Failed to resolve did:peer: {:?}", e)))?;

        let mut doc: serde_json::Value = serde_json::from_str(&doc_json)
            .map_err(|e| resolution::Error::Internal(format!("Failed to parse did:peer document: {}", e)))?;
        // ssi lib expects did/v1
        doc["@context"] = serde_json::json!(["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"]);

        serde_json::to_vec(&doc).map_err(|e| resolution::Error::Internal(e.to_string()))
    }

    async fn resolve_through_did_cache(
        &self,
        did: &DID,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        if let Some(output) = self
            .resolved
            .lock()
            .ok()
            .and_then(|resolved| {
                resolved
                    .documents
                    .get(did.as_str())
                    .cloned()
            })
        {
            return Ok(output);
        }
        let resolve_result = self
            .did_cache
            .resolve(did.as_str())
            .await
            .map_err(|e| resolution::Error::Internal(e.to_string()))?;
        let doc_bytes =
            serde_json::to_vec(&resolve_result.doc).map_err(|e| resolution::Error::Internal(e.to_string()))?;
        let output = resolution::Output::new(
            doc_bytes,
            document::Metadata::default(),
            resolution::Metadata::from_content_type(Some(MediaType::JsonLd.to_string())),
        );
        if let Ok(mut resolved) = self.resolved.lock() {
            resolved
                .documents
                .insert(did.as_str().to_string(), output.clone());
            if resolve_result.cache_hit {
                resolved
                    .from_cache
                    .insert(did.as_str().to_string());
            }
        }
        Ok(output)
    }
}

impl DIDResolver for CompositeResolver {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        match did.method_name() {
            "peer" => {
                let doc_bytes = self
                    .resolve_peer_did(did.as_str())
                    .await?;
                Ok(resolution::Output::new(
                    doc_bytes,
                    document::Metadata::default(),
                    resolution::Metadata::from_content_type(Some(MediaType::JsonLd.to_string())),
                ))
            }
            "key" | "jwk" | "pkh" | "ethr" | "ion" | "tz" => {
                self.ssi_resolver
                    .resolve_representation(did, options)
                    .await
            }
            _ => {
                self.resolve_through_did_cache(did)
                    .await
            }
        }
    }
}

fn verify_vc_lifetime(vc: &Value) -> Result<()> {
    let now = Utc::now();

    if let Some(valid_from) = vc
        .get("validFrom")
        .and_then(|v| v.as_str())
    {
        let valid_from_dt: DateTime<Utc> = valid_from
            .parse()
            .context("Invalid validFrom date format")?;
        if now < valid_from_dt {
            anyhow::bail!("VC is not yet valid (validFrom: {})", valid_from);
        }
    }

    if let Some(valid_until) = vc
        .get("validUntil")
        .and_then(|v| v.as_str())
    {
        let valid_until_dt: DateTime<Utc> = valid_until
            .parse()
            .context("Invalid validUntil date format")?;
        if now > valid_until_dt {
            anyhow::bail!("VC has expired (validUntil: {})", valid_until);
        }
    }

    if let Some(expiration_date) = vc
        .get("expirationDate")
        .and_then(|v| v.as_str())
    {
        let expiration_dt: DateTime<Utc> = expiration_date
            .parse()
            .context("Invalid expirationDate format")?;
        if now > expiration_dt {
            anyhow::bail!("VC has expired (expirationDate: {})", expiration_date);
        }
    }

    if let Some(issuance_date) = vc
        .get("issuanceDate")
        .and_then(|v| v.as_str())
    {
        let issuance_dt: DateTime<Utc> = issuance_date
            .parse()
            .context("Invalid issuanceDate format")?;
        if now < issuance_dt {
            anyhow::bail!("VC is not yet valid (issuanceDate: {})", issuance_date);
        }
    }

    Ok(())
}

const VP_CLOCK_SKEW_SECONDS: i64 = 120;

fn proof_domains(proof: &Value) -> Result<Vec<String>> {
    match proof.get("domain") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(domain)) => Ok(vec![domain.clone()]),
        Some(Value::Array(domains)) => domains
            .iter()
            .map(|domain| {
                domain
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("VP proof domain entries must be strings"))
            })
            .collect(),
        Some(_) => anyhow::bail!("VP proof domain must be a string or an array of strings"),
    }
}

fn verify_vp_proof_lifetime(proof: &Value) -> Result<()> {
    let now = Utc::now();
    let skew = Duration::seconds(VP_CLOCK_SKEW_SECONDS);

    if let Some(expires) = proof
        .get("expires")
        .and_then(|v| v.as_str())
    {
        let expires_dt: DateTime<Utc> = expires
            .parse()
            .context("Invalid proof expires date format")?;
        if now > expires_dt {
            anyhow::bail!("VP proof has expired (expires: {})", expires);
        }
        if expires_dt > now + Duration::minutes(VP_LIFETIME_MINUTES) + skew {
            anyhow::bail!(
                "VP proof expires too far ahead (expires: {}, at most {} minutes allowed)",
                expires,
                VP_LIFETIME_MINUTES
            );
        }
        // A signed created bounds the whole window, so a long-lived proof
        // does not become acceptable once enough of it has elapsed.
        if let Some(created) = proof
            .get("created")
            .and_then(|v| v.as_str())
        {
            let created_dt: DateTime<Utc> = created
                .parse()
                .context("Invalid proof created date format")?;
            if created_dt > now + skew {
                anyhow::bail!("VP proof is created in the future (created: {})", created);
            }
            if expires_dt - created_dt > Duration::minutes(VP_LIFETIME_MINUTES) + skew {
                anyhow::bail!(
                    "VP proof lifetime is too long (created: {}, expires: {}, at most {} minutes allowed)",
                    created,
                    expires,
                    VP_LIFETIME_MINUTES
                );
            }
        }
        return Ok(());
    }

    // Proofs without expires are bounded by their signed created timestamp instead.
    let created = proof
        .get("created")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("VP proof has neither expires nor created"))?;
    let created_dt: DateTime<Utc> = created
        .parse()
        .context("Invalid proof created date format")?;
    if created_dt > now + skew {
        anyhow::bail!("VP proof is created in the future (created: {})", created);
    }
    if now > created_dt + Duration::minutes(VP_LIFETIME_MINUTES) {
        anyhow::bail!("VP proof has expired (created: {}, no expires)", created);
    }

    Ok(())
}

/// Notes a credential that names a status list. The gateway does not resolve
/// status lists yet, so the status is logged and not checked.
fn check_revocation_status(vc: &Value) -> Result<()> {
    if let Some(status) = vc.get("credentialStatus") {
        let status_type = status
            .get("type")
            .and_then(|t| t.as_str());
        match status_type {
            Some("BitstringStatusListEntry") | Some("StatusList2021Entry") => {
                tracing::warn!(
                    "VC has credentialStatus of type {:?}, revocation check not yet implemented",
                    status_type
                );
            }
            Some(other) => {
                tracing::warn!("Unknown credentialStatus type: {}", other);
            }
            None => {}
        }
    }
    Ok(())
}

/// The proofs on a document, as raw JSON.
///
/// `proof` may be a single object or an array; both are normalised here so
/// every caller sees the same shape. An absent or empty `proof` is an error:
/// an unsigned document must never reach a verification decision.
fn proofs_of(
    document: &Value,
    what: &str,
) -> Result<Vec<Value>> {
    let proofs = match document.get("proof") {
        Some(Value::Array(items)) => items.clone(),
        Some(Value::Object(_)) => vec![document["proof"].clone()],
        Some(_) => anyhow::bail!("{} proof must be an object or an array", what),
        None => anyhow::bail!("{} has no proof", what),
    };
    if proofs.is_empty() {
        anyhow::bail!("{} has no proof", what);
    }
    Ok(proofs)
}

/// The DID that controls a proof, taken from its `verificationMethod`.
fn proof_controller(proof: &Value) -> Result<String> {
    let vm = proof
        .get("verificationMethod")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("proof has no verificationMethod"))?;
    let did = DIDURL::new(vm.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid proof verificationMethod {}", vm))?
        .did()
        .to_string();
    Ok(did)
}

/// `document` with its `proof` member removed.
///
/// Both cryptosuites hash the document *without* its proof, so this is what
/// either verifier must be handed.
fn without_proof(document: &Value) -> Value {
    let mut unsigned = document.clone();
    if let Some(obj) = unsigned.as_object_mut() {
        obj.remove("proof");
    }
    unsigned
}

/// Check every proof on `document` against `expected_controller`, and verify
/// any `eddsa-jcs-2022` proofs. Returns whether the document carried one.
///
/// This is the **only** place the binding decision is made, for every
/// cryptosuite. That the proof's `verificationMethod` must be a method of the
/// DID the document claims is the gateway's own invariant — `ssi` does not
/// enforce it — so keeping it here, on raw JSON, means it holds identically
/// whichever library checks the signature.
///
/// Signature checking is the only thing that dispatches by suite:
/// - `eddsa-jcs-2022` → `affinidi-data-integrity`, here, because `ssi`
///   implements no JCS cryptosuite at any released version.
/// - everything else → `ssi` at the call site, which owns `eddsa-rdfc-2022` and
///   the legacy suites and whose JSON-LD loader carries this gateway's own
///   contexts.
///
/// Returning `true` tells the caller to **skip** the `ssi` pass: `ssi` cannot
/// parse the JCS suite and would reject the document for the wrong reason. The
/// signature has already been checked here, and the bindings for every proof
/// on the document were checked above regardless.
///
/// A document that mixes `eddsa-jcs-2022` with any other suite is refused:
/// skipping the `ssi` pass would leave its other proofs with only their binding
/// checked, so an unsigned proof could carry a forged `challenge` or `domain`.
async fn check_bindings_and_jcs_proofs(
    document: &Value,
    expected_controller: &str,
    role: &str,
    allowed: &[ProofPurpose],
    what: &str,
    did_cache: &Arc<DIDCacheClient>,
) -> Result<bool> {
    let proofs = proofs_of(document, what)?;
    let unsigned = without_proof(document);
    let is_jcs = |proof: &Value| {
        proof
            .get("cryptosuite")
            .and_then(|c| c.as_str())
            == Some(JCS_CRYPTOSUITE)
    };
    let jcs_proofs = proofs
        .iter()
        .filter(|proof| is_jcs(proof))
        .count();
    if jcs_proofs > 0 && jcs_proofs != proofs.len() {
        anyhow::bail!("{what} mixes {JCS_CRYPTOSUITE} proofs with other cryptosuites");
    }
    let mut any_jcs = false;

    for proof in &proofs {
        let controller = proof_controller(proof).with_context(|| format!("{} proof binding failed", what))?;
        if controller != expected_controller {
            anyhow::bail!(
                "{}: proof verificationMethod {} does not belong to {} {}",
                what,
                proof
                    .get("verificationMethod")
                    .and_then(|v| v.as_str())
                    .unwrap_or("<none>"),
                role,
                expected_controller
            );
        }

        if is_jcs(proof) {
            any_jcs = true;
            ensure_jcs_proof_purpose(proof, allowed, role, what)?;
            super::di_jcs::verify_jcs_proof(&unsigned, proof, did_cache.clone())
                .await
                .with_context(|| format!("{} verification failed", what))?;
        }
    }

    Ok(any_jcs)
}

/// Refuses, and counts, an `eddsa-jcs-2022` proof that declares a purpose outside `allowed`; that
/// its key is listed under the purpose it declares is checked when the proof is verified.
fn ensure_jcs_proof_purpose(
    proof: &Value,
    allowed: &[ProofPurpose],
    role: &str,
    what: &str,
) -> Result<()> {
    let Some(declared) = proof
        .get("proofPurpose")
        .and_then(|p| p.as_str())
    else {
        return Ok(());
    };
    if allowed
        .iter()
        .any(|purpose| purpose_term(*purpose) == declared)
    {
        return Ok(());
    }
    let allowed = allowed
        .iter()
        .map(|purpose| purpose_term(*purpose))
        .collect::<Vec<_>>()
        .join(" or ");
    let reason = PurposeReason::PurposeNotAllowed.as_str();
    tracing::warn!(reason, "Refused a presentation: {what} proof declares purpose {declared} instead of {allowed}");
    crate::metrics::backends::prometheus::track_proof_purpose_mismatch(
        if role == "holder" {
            "vp"
        } else {
            "vc"
        },
        reason,
    );
    anyhow::bail!("{what} proof declares purpose {declared} instead of {allowed}")
}

fn purpose_term(purpose: ProofPurpose) -> String {
    match serde_json::to_value(purpose) {
        Ok(Value::String(term)) => term,
        _ => purpose.to_string(),
    }
}

const VC_PROOF_PURPOSES: &[ProofPurpose] = &[ProofPurpose::Assertion];
const VP_PROOF_PURPOSES: &[ProofPurpose] = &[ProofPurpose::Assertion, ProofPurpose::Authentication];

/// How long a signer DID whose cached document did not list a key waits before its document may be
/// fetched again for that reason.
const SIGNER_DOCUMENT_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PurposeReason {
    PurposeNotAllowed,
    NotListed,
    Unresolvable,
}

impl PurposeReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::PurposeNotAllowed => "purpose_not_allowed",
            Self::NotListed => "not_listed",
            Self::Unresolvable => "unresolvable",
        }
    }
}

struct PurposeProblem {
    reason: PurposeReason,
    message: String,
}

/// A refused proof's key was missing from a cached DID document; the signer may have listed it
/// since, so the presentation is verified again against the document as now published.
#[derive(Debug)]
struct StaleSignerDocument {
    did: String,
    role: &'static str,
}

impl std::fmt::Display for StaleSignerDocument {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        write!(f, "the cached DID document of {} does not list the proof key", self.did)
    }
}

impl std::error::Error for StaleSignerDocument {}

/// Whether `did`'s document may be fetched again now, at most once per
/// [`SIGNER_DOCUMENT_REFRESH_INTERVAL`], so a signer that keeps failing does not cost a fetch on
/// every presentation.
fn may_refresh_signer_document(did: &str) -> bool {
    static REFRESHED: std::sync::LazyLock<std::sync::Mutex<HashMap<String, std::time::Instant>>> =
        std::sync::LazyLock::new(Default::default);
    let Ok(mut refreshed) = REFRESHED.lock() else {
        return false;
    };
    let now = std::time::Instant::now();
    refreshed.retain(|_, at| now.duration_since(*at) < SIGNER_DOCUMENT_REFRESH_INTERVAL);
    if refreshed.contains_key(did) {
        return false;
    }
    refreshed.insert(did.to_string(), now);
    true
}

/// Why `proof` may not be used, if it may not: it declares a purpose outside `allowed`, the
/// signer's DID document does not list its key under the purpose it declares, or the document
/// could not be read to check.
async fn proof_purpose_problem(
    proof: &Proof<AnySuite>,
    allowed: &[ProofPurpose],
    controllers: &impl ControllerProvider,
) -> Option<PurposeProblem> {
    let vm = proof.verification_method.id();
    let declared = proof.proof_purpose;
    if !allowed.contains(&declared) {
        let allowed = allowed
            .iter()
            .map(|purpose| purpose_term(*purpose))
            .collect::<Vec<_>>()
            .join(" or ");
        return Some(PurposeProblem {
            reason: PurposeReason::PurposeNotAllowed,
            message: format!("proof by {vm} declares purpose {} instead of {allowed}", purpose_term(declared)),
        });
    }
    let unresolvable = |detail: String| {
        tracing::warn!("Could not check the proof purpose of {vm}: {detail}");
        Some(PurposeProblem {
            reason: PurposeReason::Unresolvable,
            message: format!("proof key {vm} could not be checked against its DID document"),
        })
    };
    let did = match DIDURL::new(vm.as_str()) {
        Ok(url) => url.did(),
        Err(e) => return unresolvable(format!("not a DID URL: {e}")),
    };
    match controllers
        .ensure_allows_verification_method(did.as_iri(), vm, declared)
        .await
    {
        Ok(()) => None,
        Err(ProofValidationError::InvalidKeyUse) => Some(PurposeProblem {
            reason: PurposeReason::NotListed,
            message: format!("proof key {vm} is not listed under {} in {did}", purpose_term(declared)),
        }),
        Err(e) => unresolvable(e.to_string()),
    }
}

/// Refuses, and counts, a proof in `proofs` that breaks `allowed`. A key missing from a document
/// read from the DID cache fails with [`StaleSignerDocument`] instead, unless its signer is in
/// `refreshed`, so the caller verifies the whole presentation again against the document as now
/// published.
async fn ensure_proof_purpose(
    proofs: &Proofs<AnySuite>,
    allowed: &[ProofPurpose],
    controllers: &impl ControllerProvider,
    cached: &CachedDocuments,
    refreshed: &HashSet<String>,
    what: &str,
    role: &'static str,
) -> Result<()> {
    for proof in proofs.iter() {
        let Some(problem) = proof_purpose_problem(proof, allowed, controllers).await else {
            continue;
        };
        if problem.reason == PurposeReason::NotListed
            && let Ok(url) = DIDURL::new(
                proof
                    .verification_method
                    .id()
                    .as_str(),
            )
            && !refreshed.contains(url.did().as_str())
            && cached.contains(url.did().as_str())
            && may_refresh_signer_document(url.did().as_str())
        {
            return Err(StaleSignerDocument {
                did: url.did().as_str().to_string(),
                role,
            }
            .into());
        }
        tracing::warn!(reason = problem.reason.as_str(), "Refused a presentation: {what} {}", problem.message);
        crate::metrics::backends::prometheus::track_proof_purpose_mismatch(role, problem.reason.as_str());
        anyhow::bail!("{what} {}", problem.message);
    }
    Ok(())
}

fn ensure_verified(
    outcome: Result<Verification, ProofValidationError>,
    what: &str,
) -> Result<()> {
    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(invalid)) => anyhow::bail!("{} proof verification failed: {}", what, invalid),
        Err(e) => Err(e).with_context(|| format!("{} verification failed", what)),
    }
}

fn verify_vc_fields(
    vc: &Value,
    holder_did: &str,
) -> Result<VcVerificationResult> {
    verify_vc_lifetime(vc)?;
    check_revocation_status(vc)?;

    let subject_did = vc
        .get("credentialSubject")
        .and_then(|cs| cs.get("id"))
        .and_then(|id| id.as_str())
        .ok_or_else(|| anyhow::anyhow!("VC missing credentialSubject.id"))?
        .to_string();

    if subject_did != holder_did {
        anyhow::bail!("VP holder ({:?}) does not match VC subject ({:?})", holder_did, subject_did);
    }

    let issuer_did = vc
        .get("issuer")
        .and_then(|i| i.as_str())
        .ok_or_else(|| anyhow::anyhow!("VC missing issuer field"))?
        .to_string();

    let mut identity_fields = vc
        .get("credentialSubject")
        .and_then(|cs| cs.get("identityFields"))
        .and_then(|fields| fields.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<HashMap<String, Value>>()
        })
        .unwrap_or_default();

    // Carry the Workload Binding object through so the identity-binding consumer
    // (`IdentityBindingContext::from_verified_parts`) can parse the nested
    // caller / delegated / target / agentIdentity shape. The Workload Binding
    // feature stores it under `credentialSubject.workloadBinding` (not the flat
    // `identityFields`), so without this the binding degrades to a flat identity
    // with `caller` absent.
    if let Some(workload_binding) = vc
        .get("credentialSubject")
        .and_then(|cs| cs.get("workloadBinding"))
    {
        identity_fields.insert("workloadBinding".to_string(), workload_binding.clone());
    }

    Ok(VcVerificationResult {
        issuer_did,
        subject_did,
        identity_fields,
    })
}

#[async_trait]
impl Verifier for LocalVerifier {
    async fn verify_vp(
        &self,
        presentation: &Value,
    ) -> Result<VpVerificationResult> {
        let mut refreshed = HashSet::new();
        loop {
            let result = self
                .verify_vp_with(presentation, &refreshed)
                .await;
            match result
                .as_ref()
                .err()
                .and_then(|e| e.downcast_ref::<StaleSignerDocument>())
            {
                Some(stale) if refreshed.insert(stale.did.clone()) => {
                    self.fetch_again(stale)
                        .await?;
                }
                _ => return result,
            }
        }
    }
}

impl LocalVerifier {
    /// Replaces `stale`'s cached document with the one now published. A document that cannot be
    /// fetched again refuses the presentation, counted as `unresolvable`, and is not cached again.
    async fn fetch_again(
        &self,
        stale: &StaleSignerDocument,
    ) -> Result<()> {
        self.did_cache
            .remove(&stale.did)
            .await;
        if let Err(e) = self
            .did_cache
            .resolve(&stale.did)
            .await
        {
            let reason = PurposeReason::Unresolvable.as_str();
            tracing::warn!(
                reason,
                "Refused a presentation: the DID document of {} could not be fetched again: {e}",
                stale.did
            );
            crate::metrics::backends::prometheus::track_proof_purpose_mismatch(stale.role, reason);
            anyhow::bail!(
                "{} proof key could not be checked against the DID document of {}",
                stale.role.to_uppercase(),
                stale.did
            );
        }
        Ok(())
    }

    async fn verify_vp_with(
        &self,
        presentation: &Value,
        refreshed: &HashSet<String>,
    ) -> Result<VpVerificationResult> {
        let holder_did = presentation
            .get("holder")
            .and_then(|h| h.as_str())
            .ok_or_else(|| anyhow::anyhow!("VP missing holder field"))?
            .to_string();

        let vc_field = presentation
            .get("verifiableCredential")
            .ok_or_else(|| anyhow::anyhow!("VP missing verifiableCredential field"))?;

        let vcs: Vec<&Value> = if let Some(arr) = vc_field.as_array() {
            if arr.is_empty() {
                anyhow::bail!("VP has no credentials");
            }
            arr.iter().collect()
        } else if vc_field.is_object() {
            vec![vc_field]
        } else {
            anyhow::bail!("VP verifiableCredential must be an object or array");
        };

        // Reject a stale presentation before doing any signature work: the
        // proof's own `expires`, falling back to its signed `created` time.
        //
        // Normalised through `proofs_of` so the three unsigned shapes are one
        // case: absent, `"proof": []`, and a `proof` that is neither object nor
        // array. An empty array in particular would otherwise pass a bare
        // `get("proof")` and carry an unsigned presentation into verification.
        // Every proof is bounded, so adding a second, stale proof cannot buy a
        // presentation more life than its shortest one allows.
        let proofs = proofs_of(presentation, "VP")?;
        for proof in &proofs {
            verify_vp_proof_lifetime(proof)?;
        }

        let resolver = CompositeResolver::new(self.did_cache.clone());
        let cached = resolver.cached_documents();
        let vm_resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(resolver);

        let env = create_signature_environment(None).await?;
        let params = VerificationParameters::from_resolver(vm_resolver).with_json_ld_loader(env.json_ld_loader);

        // The VP's bindings are checked on raw JSON, and a JCS holder proof is
        // verified there too. Only when it carries none is the `ssi` pass run —
        // and the typed parse that pass needs is deferred until then, because
        // `ssi` cannot deserialize a JCS proof and would fail on the shape
        // rather than on the signature.
        let vp_has_jcs = check_bindings_and_jcs_proofs(
            presentation,
            &holder_did,
            "holder",
            VP_PROOF_PURPOSES,
            "VP",
            &self.did_cache,
        )
        .await?;

        if !vp_has_jcs {
            // Credentials are parsed as raw values, not as `AnyDataIntegrity`.
            // During the migration a presentation legitimately mixes suites —
            // VTA-signed JCS credentials inside a gateway-signed RDFC
            // presentation — and typing them here would reject the whole VP
            // because of one credential `ssi` has no suite for.
            let vp: AnyDataIntegrity<JsonPresentation<Value>> = serde_json::from_value(presentation.clone())
                .context("Failed to parse VP as Data Integrity presentation")?;
            anyhow::ensure!(
                vp.claims
                    .verifiable_credentials
                    .len()
                    == vcs.len(),
                "VP credential count mismatch: {} parsed vs {} raw",
                vp.claims
                    .verifiable_credentials
                    .len(),
                vcs.len()
            );
            ensure_verified(vp.verify(&params).await, "VP")?;
            ensure_proof_purpose(&vp.proofs, VP_PROOF_PURPOSES, &params.resolver, &cached, refreshed, "VP", "vp")
                .await?;
        }

        let mut credentials = Vec::with_capacity(vcs.len());
        for (i, vc_json) in vcs.iter().enumerate() {
            let what = format!("VC[{}]", i);
            let vc_result =
                verify_vc_fields(vc_json, &holder_did).with_context(|| format!("{} validation failed", what))?;

            let vc_has_jcs = check_bindings_and_jcs_proofs(
                vc_json,
                &vc_result.issuer_did,
                "issuer",
                VC_PROOF_PURPOSES,
                &what,
                &self.did_cache,
            )
            .await?;

            if !vc_has_jcs {
                let vc: AnyDataIntegrity<JsonCredential> = serde_json::from_value((*vc_json).clone())
                    .with_context(|| format!("{} is not a Data Integrity credential", what))?;
                ensure_verified(vc.verify(&params).await, &what)?;
                ensure_proof_purpose(&vc.proofs, VC_PROOF_PURPOSES, &params.resolver, &cached, refreshed, &what, "vc")
                    .await?;
            }

            credentials.push(vc_result);
        }

        // Replay bindings come from the holder's proof. `proofs_of` guarantees
        // at least one, every proof's signature was verified above (one suite
        // per document), and the first is the holder proof in every shape the
        // gateway produces or accepts; the caller compares these against what
        // it challenged with, so a presentation whose binding does not match is
        // refused there.
        let proof = &proofs[0];
        let domains = proof_domains(proof)?;
        let challenge = proof
            .get("challenge")
            .and_then(|c| c.as_str())
            .map(String::from);

        Ok(VpVerificationResult {
            holder_did,
            credentials,
            raw_credentials: vcs
                .iter()
                .map(|v| (*v).clone())
                .collect(),
            domains,
            challenge,
        })
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_credential_naming_a_status_list_still_verifies() {
        for status_type in ["BitstringStatusListEntry", "StatusList2021Entry", "SomethingElse"] {
            let vc = json!({ "credentialStatus": { "type": status_type, "statusListIndex": "7" } });
            check_revocation_status(&vc).expect("a status list is logged, not checked");
        }
    }

    #[test]
    fn a_credential_without_a_status_passes_the_status_check() {
        check_revocation_status(&json!({ "credentialSubject": { "id": "did:key:z6Mk" } })).expect("nothing to check");
    }
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::sync::Arc;

    use serde_json::{Value, json};
    use ssi::jwk::JWK;
    use tokio::sync::RwLock;

    use super::*;
    use crate::identity::VCIssuerConfig;
    use crate::identity::ssi::did_utils::create_signing_did_peer;
    use crate::identity::ssi::did_utils::jwk_to_multibase_ed25519;
    use crate::identity::ssi::vc_issuer::{
        AgentIdentity, IssueVcPayload, LocalVcIssuer, LocalVcSigner, VcIssuer, VcSigner,
    };
    use crate::identity::ssi::vp_issuer::{
        Credentials, LocalVpIssuer, LocalVpSigner, VpIssuer, VpIssuerPayload, VpSigner,
    };
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

    struct Fixture {
        issuer_did: String,
        holder_key: JWK,
        holder_did: String,
        verifier: LocalVerifier,
        issuer_config: Arc<RwLock<VCIssuerConfig>>,
    }

    fn signer_config(
        did: &str,
        key: &JWK,
    ) -> Arc<RwLock<VCIssuerConfig>> {
        Arc::new(RwLock::new(VCIssuerConfig {
            storage_path: Default::default(),
            proxy_did: did.to_string(),
            signing_key: key.clone(),
            is_vp_challenge_required: false,
        }))
    }

    async fn fixture() -> Fixture {
        crate::gateways::did_cache::init_shared_resolver()
            .await
            .expect("init_shared_resolver failed");
        let issuer_key = JWK::generate_ed25519().unwrap();
        let issuer_did = create_signing_did_peer(&issuer_key).unwrap();
        let holder_key = JWK::generate_ed25519().unwrap();
        let holder_did = create_signing_did_peer(&holder_key).unwrap();
        Fixture {
            issuer_config: signer_config(&issuer_did, &issuer_key),
            issuer_did,
            holder_key,
            holder_did,
            verifier: LocalVerifier::new(crate::gateways::did_cache::shared_resolver().clone()),
        }
    }

    async fn issue_vc(
        f: &Fixture,
        subject_did: &str,
    ) -> Value {
        let signer = Arc::new(LocalVcSigner::new(f.issuer_config.clone()));
        let mut identity_fields = HashMap::new();
        identity_fields.insert("region".to_string(), json!("eu"));
        LocalVcIssuer::new(f.issuer_config.clone(), signer)
            .issue(IssueVcPayload::AgentIdentity(AgentIdentity {
                did: Cow::Borrowed(subject_did),
                identity_fields: Cow::Owned(identity_fields),
                workload_binding: None,
                display_name: None,
            }))
            .await
            .expect("VC issuance should succeed")
    }

    async fn present(
        holder_key: &JWK,
        holder_did: &str,
        vcs: Vec<Value>,
    ) -> Value {
        present_for(holder_key, holder_did, vcs, ssi::verification_methods::ProofPurpose::Assertion).await
    }

    async fn present_for(
        holder_key: &JWK,
        holder_did: &str,
        vcs: Vec<Value>,
        proof_purpose: ssi::verification_methods::ProofPurpose,
    ) -> Value {
        LocalVpIssuer::new(Arc::new(LocalVpSigner::new()))
            .issue(VpIssuerPayload::Credentials(Credentials {
                holder_key: Some(Cow::Borrowed(holder_key)),
                holder_did: Cow::Borrowed(holder_did),
                verifiable_credentials: Cow::Owned(vcs),
                challenge: None,
                domain: None,
                proof_purpose,
            }))
            .await
            .expect("VP issuance should succeed")
    }

    async fn verify(
        f: &Fixture,
        vp: &Value,
    ) -> Result<VpVerificationResult, String> {
        f.verifier
            .verify_vp(vp)
            .await
            .map_err(|e| format!("{:#}", e))
    }

    #[tokio::test]
    async fn verifies_vp_over_vc_with_display_name() {
        let f = fixture().await;
        let signer = Arc::new(LocalVcSigner::new(f.issuer_config.clone()));
        let vc = LocalVcIssuer::new(f.issuer_config.clone(), signer)
            .issue(IssueVcPayload::AgentIdentity(AgentIdentity {
                did: Cow::Borrowed(&f.holder_did),
                identity_fields: Cow::Owned(HashMap::new()),
                workload_binding: None,
                display_name: Some(Cow::Borrowed("OXYGEN")),
            }))
            .await
            .expect("VC issuance with a display name should succeed");
        assert_eq!(vc["credentialSubject"]["name"], json!("OXYGEN"));
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let result = verify(&f, &vp)
            .await
            .expect("VP over a named VC verifies");

        assert_eq!(result.credentials.len(), 1);
        assert_eq!(result.credentials[0].subject_did, f.holder_did);
        assert_eq!(result.raw_credentials[0]["credentialSubject"]["name"], json!("OXYGEN"));
    }

    #[tokio::test]
    async fn rejects_vc_whose_display_name_was_altered_after_signing() {
        let f = fixture().await;
        let signer = Arc::new(LocalVcSigner::new(f.issuer_config.clone()));
        let mut vc = LocalVcIssuer::new(f.issuer_config.clone(), signer)
            .issue(IssueVcPayload::AgentIdentity(AgentIdentity {
                did: Cow::Borrowed(&f.holder_did),
                identity_fields: Cow::Owned(HashMap::new()),
                workload_binding: None,
                display_name: Some(Cow::Borrowed("OXYGEN")),
            }))
            .await
            .unwrap();
        vc["credentialSubject"]["name"] = json!("HELIUM");
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        assert!(verify(&f, &vp).await.is_err(), "a tampered display name must fail verification");
    }

    #[tokio::test]
    async fn verifies_vp_signed_by_holder_over_issuer_signed_vc() {
        let f = fixture().await;
        let vc = issue_vc(&f, &f.holder_did).await;
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let result = verify(&f, &vp)
            .await
            .expect("holder-signed VP over issuer-signed VC verifies");

        assert_eq!(result.holder_did, f.holder_did);
        assert_eq!(result.credentials.len(), 1);
        assert_eq!(result.credentials[0].issuer_did, f.issuer_did);
        assert_eq!(result.credentials[0].subject_did, f.holder_did);
        assert_eq!(result.credentials[0].identity_fields["region"], json!("eu"));
        assert_eq!(result.raw_credentials.len(), 1);
        assert!(result.challenge.is_none());
    }

    #[tokio::test]
    async fn rejects_vc_subject_other_than_holder() {
        let f = fixture().await;
        let vc = issue_vc(&f, &f.issuer_did).await;
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("VC subject must equal the VP holder");

        assert!(err.contains("does not match VC subject"), "{err}");
    }

    #[tokio::test]
    async fn rejects_vc_without_proof() {
        let f = fixture().await;
        let mut vc = issue_vc(&f, &f.holder_did).await;
        vc.as_object_mut()
            .unwrap()
            .remove("proof");
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a VC without a proof must be rejected");

        assert!(err.contains("VC[0]") && err.contains("has no proof"), "{err}");
    }

    #[tokio::test]
    async fn rejects_vc_mutated_after_issuance() {
        let f = fixture().await;
        let mut vc = issue_vc(&f, &f.holder_did).await;
        vc["credentialSubject"]["identityFields"]["region"] = json!("evil");
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a VC changed after the issuer signed it must be rejected");

        assert!(err.contains("VC[0]") && err.contains("proof verification failed"), "{err}");
    }

    #[tokio::test]
    async fn rejects_vc_whose_proof_key_is_not_the_issuer() {
        let f = fixture().await;
        let mut vc = issue_vc(&f, &f.holder_did).await;
        vc.as_object_mut()
            .unwrap()
            .remove("proof");
        assert_eq!(vc["issuer"], json!(f.issuer_did));
        let forged = LocalVcSigner::new(signer_config(&f.holder_did, &f.holder_key))
            .sign(vc)
            .await
            .expect("holder can sign a credential with its own key");
        let vp = present(&f.holder_key, &f.holder_did, vec![forged]).await;

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a VC signed by a key the issuer does not control must be rejected");

        assert!(err.contains("does not belong to issuer"), "{err}");
    }

    #[tokio::test]
    async fn rejects_vp_signed_by_key_of_another_did() {
        let f = fixture().await;
        let attacker_key = JWK::generate_ed25519().unwrap();
        let attacker_did = create_signing_did_peer(&attacker_key).unwrap();
        let vc = issue_vc(&f, &f.holder_did).await;
        let unsigned_vp = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": f.holder_did,
            "verifiableCredential": [vc],
            "id": "urn:uuid:5d5d5d5d-0000-4000-8000-000000000001",
        });
        let vp = LocalVpSigner::new()
            .sign(
                unsigned_vp,
                &attacker_key,
                &attacker_did,
                None,
                None,
                ssi::verification_methods::ProofPurpose::Assertion,
            )
            .await
            .expect("attacker can sign a presentation with its own key");

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a VP whose proof key is not the holder's must be rejected");

        assert!(err.contains("does not belong to holder"), "{err}");
    }

    fn two_key_peer_did(key: &JWK) -> String {
        let public_key = jwk_to_multibase_ed25519(key).unwrap();
        let keys = (0..2)
            .map(|_| did_peer::DIDPeerCreateKeys {
                purpose: did_peer::DIDPeerKeys::Verification,
                type_: None,
                public_key_multibase: Some(public_key.clone()),
            })
            .collect::<Vec<_>>();
        did_peer::DIDPeer::create_peer_did(&keys, None)
            .unwrap()
            .0
    }

    async fn mint_vp() -> (Value, String) {
        let signing_key = JWK::generate_ed25519().unwrap();
        let issuer_did = two_key_peer_did(&signing_key);
        let holder_key = JWK::generate_ed25519().unwrap();
        let holder_did = two_key_peer_did(&holder_key);
        let config = Arc::new(RwLock::new(VCIssuerConfig {
            storage_path: Default::default(),
            proxy_did: issuer_did,
            signing_key,
            is_vp_challenge_required: false,
        }));
        let vc = LocalVcIssuer::new(config.clone(), Arc::new(LocalVcSigner::new(config)))
            .issue(IssueVcPayload::AgentIdentity(AgentIdentity {
                did: Cow::Borrowed(&holder_did),
                identity_fields: Cow::Owned(HashMap::new()),
                workload_binding: None,
                display_name: None,
            }))
            .await
            .unwrap();
        let vp = LocalVpIssuer::new(Arc::new(LocalVpSigner::new()))
            .issue(VpIssuerPayload::Credentials(Credentials {
                holder_key: Some(Cow::Owned(holder_key)),
                holder_did: Cow::Borrowed(&holder_did),
                verifiable_credentials: Cow::Owned(vec![vc]),
                challenge: None,
                domain: None,
                proof_purpose: ssi::verification_methods::ProofPurpose::Assertion,
            }))
            .await
            .unwrap();
        (vp, holder_did)
    }

    async fn did_web_resolution_error(
        host_policy: affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy
    ) -> String {
        let client = DIDCacheClient::new(
            DIDCacheConfigBuilder::default()
                .with_host_policy(host_policy)
                .build(),
        )
        .await
        .expect("Failed to create DID cache client");
        let resolver = CompositeResolver::new(Arc::new(client));
        match resolver
            .resolve_representation(DID::new("did:web:localhost%3A1").unwrap(), Options::default())
            .await
        {
            Ok(_) => panic!("resolving an unreachable did:web must fail"),
            Err(error) => error.to_string(),
        }
    }

    #[tokio::test]
    async fn did_web_on_a_private_host_is_refused_under_the_default_policy() {
        let error =
            did_web_resolution_error(affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy::PublicOnly).await;
        assert!(error.contains("SSRF-prone host"), "expected a blocked-host refusal, got: {error}");
    }

    #[tokio::test]
    async fn did_web_on_a_private_host_is_fetched_when_private_hosts_are_allowed() {
        let error =
            did_web_resolution_error(affinidi_did_resolver_cache_sdk::network_resolvers::HostPolicy::AllowPrivate)
                .await;
        assert!(!error.contains("SSRF-prone host"), "AllowPrivate must not refuse localhost, got: {error}");
    }

    async fn local_verifier() -> LocalVerifier {
        let config = DIDCacheConfigBuilder::default()
            .with_cache_capacity(100)
            .with_cache_ttl(300)
            .build();
        let client = DIDCacheClient::new(config)
            .await
            .expect("Failed to create DID cache client");
        LocalVerifier::new(Arc::new(client))
    }

    #[test]
    fn proof_lifetime_rejects_past_expires() {
        let err = verify_vp_proof_lifetime(&json!({
            "created": "2000-01-01T00:00:00Z",
            "expires": "2000-01-01T00:05:00Z"
        }))
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("expired"),
            "{err}"
        );
    }

    #[test]
    fn proof_lifetime_accepts_expires_within_lifetime() {
        let expires = (Utc::now() + Duration::minutes(VP_LIFETIME_MINUTES)).to_rfc3339();
        verify_vp_proof_lifetime(&json!({ "expires": expires })).unwrap();
    }

    #[test]
    fn proof_lifetime_accepts_expires_within_clock_skew() {
        let expires =
            (Utc::now() + Duration::minutes(VP_LIFETIME_MINUTES) + Duration::seconds(VP_CLOCK_SKEW_SECONDS - 5))
                .to_rfc3339();
        verify_vp_proof_lifetime(&json!({ "expires": expires })).unwrap();
    }

    #[test]
    fn proof_lifetime_rejects_expires_beyond_lifetime() {
        let expires =
            (Utc::now() + Duration::minutes(VP_LIFETIME_MINUTES) + Duration::seconds(VP_CLOCK_SKEW_SECONDS + 5))
                .to_rfc3339();
        let err = verify_vp_proof_lifetime(&json!({ "expires": expires })).unwrap_err();
        assert!(
            err.to_string()
                .contains("too far ahead"),
            "{err}"
        );
    }

    #[test]
    fn proof_lifetime_rejects_far_future_expires() {
        let err = verify_vp_proof_lifetime(&json!({
            "created": "2000-01-01T00:00:00Z",
            "expires": "2999-01-01T00:00:00Z"
        }))
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("too far ahead"),
            "{err}"
        );
    }

    #[test]
    fn proof_lifetime_rejects_long_window_once_mostly_elapsed() {
        let created = (Utc::now() - Duration::minutes(25)).to_rfc3339();
        let expires = (Utc::now() + Duration::minutes(5)).to_rfc3339();
        let err = verify_vp_proof_lifetime(&json!({ "created": created, "expires": expires })).unwrap_err();
        assert!(
            err.to_string()
                .contains("lifetime is too long"),
            "{err}"
        );
    }

    #[test]
    fn proof_lifetime_accepts_created_and_expires_within_lifetime() {
        let created = Utc::now().to_rfc3339();
        let expires = (Utc::now() + Duration::minutes(VP_LIFETIME_MINUTES)).to_rfc3339();
        verify_vp_proof_lifetime(&json!({ "created": created, "expires": expires })).unwrap();
    }

    #[test]
    fn proof_lifetime_rejects_created_in_the_future_with_expires() {
        let created = (Utc::now() + Duration::minutes(10)).to_rfc3339();
        let expires = (Utc::now() + Duration::minutes(VP_LIFETIME_MINUTES)).to_rfc3339();
        let err = verify_vp_proof_lifetime(&json!({ "created": created, "expires": expires })).unwrap_err();
        assert!(
            err.to_string()
                .contains("in the future"),
            "{err}"
        );
    }

    #[test]
    fn proof_lifetime_rejects_created_in_the_future() {
        let created = (Utc::now() + Duration::seconds(VP_CLOCK_SKEW_SECONDS + 5)).to_rfc3339();
        let err = verify_vp_proof_lifetime(&json!({ "created": created })).unwrap_err();
        assert!(
            err.to_string()
                .contains("in the future"),
            "{err}"
        );
    }

    #[test]
    fn proof_lifetime_accepts_created_within_clock_skew() {
        let created = (Utc::now() + Duration::seconds(VP_CLOCK_SKEW_SECONDS - 5)).to_rfc3339();
        verify_vp_proof_lifetime(&json!({ "created": created })).unwrap();
    }

    #[test]
    fn proof_lifetime_rejects_malformed_expires() {
        assert!(verify_vp_proof_lifetime(&json!({ "expires": "not-a-date" })).is_err());
    }

    #[test]
    fn proof_lifetime_without_expires_is_bounded_by_created() {
        let fresh = (Utc::now() - Duration::minutes(1)).to_rfc3339();
        verify_vp_proof_lifetime(&json!({ "created": fresh })).unwrap();

        let stale = (Utc::now() - Duration::minutes(VP_LIFETIME_MINUTES + 1)).to_rfc3339();
        let err = verify_vp_proof_lifetime(&json!({ "created": stale })).unwrap_err();
        assert!(
            err.to_string()
                .contains("expired"),
            "{err}"
        );
    }

    #[test]
    fn proof_domains_reads_a_string_an_array_or_nothing() {
        assert_eq!(proof_domains(&json!({})).unwrap(), Vec::<String>::new());
        assert_eq!(proof_domains(&json!({ "domain": "did:example:gw2" })).unwrap(), vec!["did:example:gw2"]);
        assert_eq!(
            proof_domains(&json!({ "domain": ["did:example:a", "https://b.example"] })).unwrap(),
            vec!["did:example:a", "https://b.example"]
        );
    }

    #[test]
    fn proof_domains_rejects_a_domain_that_is_not_text() {
        assert!(proof_domains(&json!({ "domain": 7 })).is_err());
        assert!(proof_domains(&json!({ "domain": ["did:example:a", 7] })).is_err());
    }

    #[test]
    fn proof_lifetime_rejects_proof_without_timestamps() {
        assert!(verify_vp_proof_lifetime(&json!({ "type": "DataIntegrityProof" })).is_err());
    }

    #[tokio::test]
    async fn verify_vp_accepts_fresh_presentation_within_lifetime() {
        let (vp, holder_did) = mint_vp().await;

        let result = local_verifier()
            .await
            .verify_vp(&vp)
            .await
            .expect("fresh VP must verify");

        assert_eq!(result.holder_did, holder_did);
        assert_eq!(result.credentials.len(), 1);
        let expires: DateTime<Utc> = vp["proof"]["expires"]
            .as_str()
            .expect("minted VP proof must carry expires")
            .parse()
            .unwrap();
        assert!(expires > Utc::now());
        assert!(expires <= Utc::now() + Duration::minutes(VP_LIFETIME_MINUTES));
    }

    #[tokio::test]
    async fn verify_vp_rejects_expired_proof() {
        let (mut vp, _) = mint_vp().await;
        vp["proof"]["expires"] = json!("2000-01-01T00:00:00Z");

        let err = local_verifier()
            .await
            .verify_vp(&vp)
            .await
            .err()
            .expect("expired VP proof must be rejected");
        assert!(format!("{err:#}").contains("VP proof has expired"), "{err:#}");
    }

    #[tokio::test]
    async fn verify_vp_rejects_tampered_issuer() {
        let (mut vp, _) = mint_vp().await;
        first_vc_mut(&mut vp)["issuer"] = json!("did:web:did.dev.example.io:fake-issuer");

        assert!(
            local_verifier()
                .await
                .verify_vp(&vp)
                .await
                .is_err()
        );
    }

    // ─── `eddsa-jcs-2022` (the suite the Verifiable Trust Agent produces) ───
    //
    // `ssi` implements no JCS cryptosuite, so these credentials are signed with
    // `affinidi-data-integrity` — the same crate the VTA signs with — and must
    // be verified through the dispatch in `check_bindings_and_jcs_proofs`.

    /// Sign `credential` with an `eddsa-jcs-2022` proof as `did:key` holder of
    /// `key`, the way the VTA's context-scoped issue task does.
    async fn sign_jcs(
        mut credential: Value,
        key: &ed25519_dalek::SigningKey,
        issuer_did: &str,
        verification_method: &str,
        proof_purpose: &str,
    ) -> Value {
        credential
            .as_object_mut()
            .expect("credential is an object")
            .insert("issuer".into(), json!(issuer_did));

        let proof = sign_jcs_proof(&credential, key, verification_method, proof_purpose).await;
        credential
            .as_object_mut()
            .unwrap()
            .insert("proof".into(), proof);
        credential
    }

    /// An `eddsa-jcs-2022` proof over `document` exactly as it stands.
    async fn sign_jcs_proof(
        document: &Value,
        key: &ed25519_dalek::SigningKey,
        verification_method: &str,
        proof_purpose: &str,
    ) -> Value {
        use affinidi_data_integrity::crypto_suites::CryptoSuite;
        use affinidi_data_integrity::{DataIntegrityProof, SignOptions};
        use affinidi_secrets_resolver::secrets::Secret;

        let mut private = vec![0x80, 0x26];
        private.extend_from_slice(&key.to_bytes());
        let mut secret = Secret::from_multibase(&multibase::encode(multibase::Base::Base58Btc, &private), None)
            .expect("secret from multibase");
        secret.id = verification_method.to_string();

        let proof = DataIntegrityProof::sign(
            document,
            &secret,
            SignOptions::new()
                .with_proof_purpose(proof_purpose)
                .with_cryptosuite(CryptoSuite::EddsaJcs2022),
        )
        .await
        .expect("JCS signing should succeed");
        serde_json::to_value(&proof).expect("proof serialises")
    }

    /// A `did:key` identity: the signing key, the DID, and its verification
    /// method — which for `did:key` is `<did>#<multibase>`.
    fn did_key_identity() -> (ed25519_dalek::SigningKey, String, String) {
        // Seeded from UUIDs rather than an RNG: two `rand` majors are in the
        // tree and `ed25519-dalek` accepts only one of them. Test keys need to
        // differ between calls, not to be cryptographically sourced.
        let mut seed = [0u8; 32];
        seed[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        seed[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(key.verifying_key().as_bytes());
        let multibase = multibase::encode(multibase::Base::Base58Btc, &multicodec);
        let did = format!("did:key:{multibase}");
        let vm = format!("{did}#{multibase}");
        (key, did, vm)
    }

    fn unsigned_agent_vc(
        subject_did: &str,
        issuer_did: &str,
    ) -> Value {
        json!({
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                crate::identity::ssi::context::CTX_AGENT_IDENTITY_V1_URL,
            ],
            "type": ["VerifiableCredential", "AgentIdentityCredential"],
            "issuer": issuer_did,
            "validFrom": chrono::Utc::now().to_rfc3339(),
            "validUntil": (chrono::Utc::now() + chrono::Duration::days(1)).to_rfc3339(),
            "credentialSubject": { "id": subject_did, "identityFields": { "region": "eu" } },
            "id": "urn:uuid:1c5d0000-0000-4000-8000-00000000f00d",
        })
    }

    /// The shape trust agent signing produces: a VTA-signed `eddsa-jcs-2022` credential
    /// inside a gateway-signed `eddsa-rdfc-2022` presentation. Both suites must
    /// verify in one pass.
    #[tokio::test]
    async fn verifies_a_jcs_credential_inside_an_rdfc_presentation() {
        let f = fixture().await;
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();

        let vc = sign_jcs(
            unsigned_agent_vc(&f.holder_did, &issuer_did),
            &issuer_key,
            &issuer_did,
            &issuer_vm,
            "assertionMethod",
        )
        .await;
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let result = verify(&f, &vp)
            .await
            .expect("a JCS credential in an RDFC presentation must verify");

        assert_eq!(result.credentials.len(), 1);
        assert_eq!(result.credentials[0].issuer_did, issuer_did);
        assert_eq!(result.credentials[0].subject_did, f.holder_did);
        assert_eq!(result.credentials[0].identity_fields["region"], json!("eu"));
    }

    /// A JCS credential proof must declare `assertionMethod`, as a credential proof of any other
    /// suite must, even when its key is listed under the purpose it declares.
    #[tokio::test]
    async fn rejects_a_jcs_credential_whose_proof_declares_authentication() {
        let f = fixture().await;
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();
        let vc = sign_jcs(
            unsigned_agent_vc(&f.holder_did, &issuer_did),
            &issuer_key,
            &issuer_did,
            &issuer_vm,
            "authentication",
        )
        .await;
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a credential proof for authentication must be refused");

        assert!(
            err.contains("declares purpose authentication instead of assertionMethod"),
            "refused for the wrong reason: {err}"
        );
    }

    /// A JCS presentation proof may declare `assertionMethod` as well as `authentication`.
    #[tokio::test]
    async fn verifies_a_jcs_presentation_whose_proof_declares_assertion_method() {
        let f = fixture().await;
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();
        let (holder_key, holder_did, holder_vm) = did_key_identity();
        let vc = sign_jcs(
            unsigned_agent_vc(&holder_did, &issuer_did),
            &issuer_key,
            &issuer_did,
            &issuer_vm,
            "assertionMethod",
        )
        .await;
        let unsigned_vp = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": holder_did,
            "verifiableCredential": [vc],
            "id": "urn:uuid:7a7a0000-0000-4000-8000-00000000000a",
        });
        let vp = sign_jcs(unsigned_vp, &holder_key, &holder_did, &holder_vm, "assertionMethod").await;

        let result = verify(&f, &vp)
            .await
            .expect("assertionMethod is allowed on a presentation");

        assert_eq!(result.holder_did, holder_did);
    }

    /// The custom `AgentIdentityCredential` context is exactly what
    /// `affinidi-data-integrity`'s RDFC path cannot expand. JCS does no
    /// expansion, so it must verify regardless — this pins that.
    #[tokio::test]
    async fn a_jcs_credential_verifies_despite_the_custom_jsonld_context() {
        let f = fixture().await;
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();
        let vc = unsigned_agent_vc(&f.holder_did, &issuer_did);
        assert_eq!(
            vc["@context"][1],
            json!(crate::identity::ssi::context::CTX_AGENT_IDENTITY_V1_URL),
            "this test is meaningless unless the custom context is present"
        );

        let vc = sign_jcs(vc, &issuer_key, &issuer_did, &issuer_vm, "assertionMethod").await;
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        verify(&f, &vp)
            .await
            .expect("JCS needs no JSON-LD expansion, so the custom context is irrelevant");
    }

    /// The gateway's own invariant — a proof key must belong to the issuer —
    /// is enforced for JCS exactly as it is for RDFC. This is the check that
    /// must never differ between the two paths.
    #[tokio::test]
    async fn rejects_a_jcs_credential_whose_proof_key_is_not_the_issuer() {
        let f = fixture().await;
        let (attacker_key, _attacker_did, attacker_vm) = did_key_identity();
        let (_, claimed_issuer, _) = did_key_identity();

        // Signed by the attacker's key, but claiming someone else as issuer.
        let vc = sign_jcs(
            unsigned_agent_vc(&f.holder_did, &claimed_issuer),
            &attacker_key,
            &claimed_issuer,
            &attacker_vm,
            "assertionMethod",
        )
        .await;
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a JCS proof key that is not the issuer's must be rejected");
        assert!(err.contains("does not belong to issuer"), "{err}");
    }

    /// A tampered JCS credential must fail the signature check, not slip
    /// through because the binding check passed.
    #[tokio::test]
    async fn rejects_a_jcs_credential_mutated_after_issuance() {
        let f = fixture().await;
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();
        let mut vc = sign_jcs(
            unsigned_agent_vc(&f.holder_did, &issuer_did),
            &issuer_key,
            &issuer_did,
            &issuer_vm,
            "assertionMethod",
        )
        .await;

        vc["credentialSubject"]["identityFields"]["region"] = json!("us");
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a mutated JCS credential must fail verification");
        assert!(err.contains("verification failed") || err.contains("InvalidSignature"), "{err}");
    }

    /// A JCS presentation is what an agent whose key lives in a VTA makes — the holder proof moves to the
    /// VTA too. The dispatch must handle it at the VP level, not just for
    /// embedded credentials.
    #[tokio::test]
    async fn verifies_a_jcs_presentation() {
        let f = fixture().await;
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();
        let (holder_key, holder_did, holder_vm) = did_key_identity();

        let vc = sign_jcs(
            unsigned_agent_vc(&holder_did, &issuer_did),
            &issuer_key,
            &issuer_did,
            &issuer_vm,
            "assertionMethod",
        )
        .await;

        let unsigned_vp = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": holder_did,
            "verifiableCredential": [vc],
            "id": "urn:uuid:7a7a0000-0000-4000-8000-000000000002",
        });
        let vp = sign_jcs(unsigned_vp, &holder_key, &holder_did, &holder_vm, "authentication").await;

        let result = verify(&f, &vp)
            .await
            .expect("an all-JCS presentation must verify");
        assert_eq!(result.holder_did, holder_did);
        assert_eq!(result.credentials[0].issuer_did, issuer_did);
    }

    /// The presentation a trust agent signs for an agent: it names its holder
    /// with `holder` and, so the agent can find its signer, with `controller`
    /// as well. The verifier reads `holder`, so the extra member changes
    /// nothing — and the credential inside still has to be about that holder.
    #[tokio::test]
    async fn verifies_a_trust_agent_presentation_that_also_names_a_controller() {
        let f = fixture().await;
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();
        let (holder_key, holder_did, holder_vm) = did_key_identity();

        let vc = sign_jcs(
            unsigned_agent_vc(&holder_did, &issuer_did),
            &issuer_key,
            &issuer_did,
            &issuer_vm,
            "assertionMethod",
        )
        .await;
        let mut vp = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": holder_did,
            "controller": holder_did,
            "verifiableCredential": [vc],
            "id": "urn:uuid:7a7a0000-0000-4000-8000-000000000003",
        });
        let proof = sign_jcs_proof(&vp, &holder_key, &holder_vm, "authentication").await;
        vp["proof"] = proof;

        let result = verify(&f, &vp)
            .await
            .expect("a presentation that also names a controller must verify");
        assert_eq!(result.holder_did, holder_did);
        assert_eq!(result.credentials[0].subject_did, holder_did);
    }

    /// The `controller` is not a way to present as someone else: a proof made by
    /// a key that is not the holder's is rejected however the document names its
    /// signer.
    #[tokio::test]
    async fn rejects_a_presentation_signed_by_someone_other_than_its_holder() {
        let f = fixture().await;
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();
        let (_holder_key, holder_did, _holder_vm) = did_key_identity();
        let (other_key, other_did, other_vm) = did_key_identity();

        let vc = sign_jcs(
            unsigned_agent_vc(&holder_did, &issuer_did),
            &issuer_key,
            &issuer_did,
            &issuer_vm,
            "assertionMethod",
        )
        .await;
        let mut vp = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": holder_did,
            "controller": other_did,
            "verifiableCredential": [vc],
            "id": "urn:uuid:7a7a0000-0000-4000-8000-000000000004",
        });
        let proof = sign_jcs_proof(&vp, &other_key, &other_vm, "authentication").await;
        vp["proof"] = proof;

        assert!(
            verify(&f, &vp).await.is_err(),
            "a proof from a key that is not the holder's must not verify as the holder"
        );
    }

    /// An `eddsa-jcs-2022` proof built the way the trust agent builds one: the
    /// proof options carry the verification method, the purpose and any
    /// challenge or domain, and the signature covers
    /// `SHA-256(JCS(options)) || SHA-256(JCS(document))`.
    fn trust_agent_proof(
        document: &Value,
        key: &ed25519_dalek::SigningKey,
        verification_method: &str,
        challenge: Option<&str>,
        domain: Option<&str>,
    ) -> Value {
        use sha2::{Digest, Sha256};

        let mut options = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "verificationMethod": verification_method,
            "proofPurpose": "authentication",
        });
        if let Some(context) = document.get("@context") {
            options["@context"] = context.clone();
        }
        if let Some(challenge) = challenge {
            options["challenge"] = json!(challenge);
        }
        if let Some(domain) = domain {
            options["domain"] = json!(domain);
        }
        let jcs = |v: &Value| serde_json_canonicalizer::to_string(v).expect("canonicalise");
        let mut hash_data = Vec::new();
        hash_data.extend_from_slice(&Sha256::digest(jcs(&options).as_bytes()));
        hash_data.extend_from_slice(&Sha256::digest(jcs(document).as_bytes()));
        let signature = ed25519_dalek::Signer::sign(key, &hash_data);
        options["proofValue"] = json!(multibase::encode(multibase::Base::Base58Btc, signature.to_bytes()));
        options
    }

    async fn bound_presentation(
        challenge: Option<&str>,
        domain: Option<&str>,
    ) -> (Value, String) {
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();
        let (holder_key, holder_did, holder_vm) = did_key_identity();
        let vc = sign_jcs(
            unsigned_agent_vc(&holder_did, &issuer_did),
            &issuer_key,
            &issuer_did,
            &issuer_vm,
            "assertionMethod",
        )
        .await;
        let mut vp = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": holder_did,
            "controller": holder_did,
            "verifiableCredential": [vc],
            "id": "urn:uuid:7a7a0000-0000-4000-8000-000000000005",
        });
        vp["proof"] = trust_agent_proof(&vp, &holder_key, &holder_vm, challenge, domain);
        (vp, holder_did)
    }

    /// A proof bound to a challenge and a domain verifies: both are part of what
    /// was signed, so the verifier has to reconstruct them to check anything.
    /// (The library this once used drops them, and every such proof failed.)
    #[tokio::test]
    async fn verifies_a_jcs_presentation_bound_to_a_challenge_and_domain() {
        let f = fixture().await;
        let (vp, holder_did) = bound_presentation(Some("nonce-1"), Some("verifier.example")).await;

        let result = verify(&f, &vp)
            .await
            .expect("a proof bound to a challenge and a domain must verify");
        assert_eq!(result.holder_did, holder_did);
        assert_eq!(vp["proof"]["challenge"], json!("nonce-1"));
    }

    /// The binding is part of the signature: changing the challenge or the
    /// domain afterwards — which is what replaying a proof somewhere else would
    /// need — breaks it.
    #[tokio::test]
    async fn rejects_a_jcs_proof_whose_challenge_or_domain_was_changed_after_signing() {
        let f = fixture().await;
        for member in ["challenge", "domain"] {
            let (mut vp, _) = bound_presentation(Some("nonce-1"), Some("verifier.example")).await;
            vp["proof"][member] = json!("someone-else");
            let err = verify(&f, &vp)
                .await
                .err()
                .unwrap_or_else(|| panic!("a changed {member} must not verify"));
            assert!(err.contains("verification failed"), "{member}: refused for the wrong reason: {err}");
        }
        let (mut vp, _) = bound_presentation(Some("nonce-1"), None).await;
        vp["proof"]["domain"] = json!("added-afterwards");
        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a domain added after signing must not verify");
        assert!(err.contains("verification failed"), "refused for the wrong reason: {err}");
    }

    /// An unsigned document must never reach a verification decision, whichever
    /// suite is in play.
    #[tokio::test]
    async fn rejects_a_presentation_with_no_proof() {
        let f = fixture().await;
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();
        let vc = sign_jcs(
            unsigned_agent_vc(&f.holder_did, &issuer_did),
            &issuer_key,
            &issuer_did,
            &issuer_vm,
            "assertionMethod",
        )
        .await;
        let vp = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": f.holder_did,
            "verifiableCredential": [vc],
        });

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("an unsigned presentation must be rejected");
        assert!(err.contains("has no proof"), "{err}");
    }

    /// A captured trust-agent presentation replayed with an unsigned proof of
    /// another suite placed first, naming the holder and carrying a fresh
    /// challenge, is refused: that proof's signature would go unchecked, and its
    /// challenge is the one the caller compares.
    #[tokio::test]
    async fn rejects_a_jcs_presentation_with_an_unsigned_proof_of_another_suite() {
        let f = fixture().await;
        let (mut vp, _) = bound_presentation(Some("nonce-1"), None).await;
        let real = vp["proof"].clone();
        let forged = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
            "created": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "verificationMethod": real["verificationMethod"],
            "proofPurpose": "authentication",
            "challenge": "fresh-challenge",
            "proofValue": "z1111111111111111111111111111111111111111111111111111111111111111",
        });
        vp["proof"] = json!([forged, real]);

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("an unverifiable proof must not ride along with a verified one");
        assert!(err.contains("mixes eddsa-jcs-2022"), "refused for the wrong reason: {err}");
    }

    /// Every proof on a JCS document is verified, so a second JCS proof whose
    /// signature does not hold is refused even when the first one verifies.
    #[tokio::test]
    async fn rejects_a_jcs_presentation_whose_second_proof_does_not_verify() {
        let f = fixture().await;
        let (mut vp, _) = bound_presentation(Some("nonce-1"), None).await;
        let real = vp["proof"].clone();
        let mut forged = real.clone();
        forged["challenge"] = json!("fresh-challenge");
        vp["proof"] = json!([forged, real]);

        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a proof whose challenge was changed must not verify");
        assert!(err.contains("verification failed"), "refused for the wrong reason: {err}");
    }

    /// A JCS proof is checked against the verification relationship it names,
    /// as `ssi` does for the other suites: a purpose no proof can use, or none
    /// at all, is refused.
    #[tokio::test]
    async fn rejects_a_jcs_proof_whose_purpose_is_not_a_proof_relationship() {
        let f = fixture().await;
        let (issuer_key, issuer_did, issuer_vm) = did_key_identity();
        let (holder_key, holder_did, holder_vm) = did_key_identity();
        let vc = sign_jcs(
            unsigned_agent_vc(&holder_did, &issuer_did),
            &issuer_key,
            &issuer_did,
            &issuer_vm,
            "assertionMethod",
        )
        .await;
        let unsigned_vp = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "holder": holder_did,
            "verifiableCredential": [vc],
            "id": "urn:uuid:7a7a0000-0000-4000-8000-000000000009",
        });
        let vp = sign_jcs(unsigned_vp.clone(), &holder_key, &holder_did, &holder_vm, "keyAgreement").await;
        let err = verify(&f, &vp)
            .await
            .err()
            .expect("keyAgreement is not a relationship a proof can use");
        assert!(err.contains("keyAgreement"), "refused for the wrong reason: {err}");

        let mut vp = sign_jcs(unsigned_vp, &holder_key, &holder_did, &holder_vm, "authentication").await;
        vp["proof"]
            .as_object_mut()
            .unwrap()
            .remove("proofPurpose");
        let err = verify(&f, &vp)
            .await
            .err()
            .expect("a proof with no purpose must be refused");
        assert!(err.contains("proofPurpose"), "refused for the wrong reason: {err}");
    }

    fn did_web_signer(
        key: &JWK,
        relationships: &[&str],
    ) -> (String, affinidi_did_common::Document) {
        let did = format!("did:web:localhost%3A1:{}", uuid::Uuid::new_v4());
        let vm = format!("{did}#key-2");
        let mut document = json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
            "id": did,
            "verificationMethod": [{
                "id": vm,
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": jwk_to_multibase_ed25519(key).unwrap(),
            }],
        });
        for relationship in relationships {
            document[*relationship] = json!([vm]);
        }
        (did, serde_json::from_value(document).unwrap())
    }

    /// A DID cache holding `documents`, each also published unchanged, so fetching one again
    /// returns the same document.
    async fn verifier_with(documents: &[(String, affinidi_did_common::Document)]) -> Arc<DIDCacheClient> {
        let mut client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("Failed to create DID cache client");
        if !documents.is_empty() {
            client.set_resolver(
                affinidi_did_resolver_cache_sdk::MethodName::Web,
                Box::new(PublishedDocuments(
                    documents
                        .iter()
                        .cloned()
                        .collect(),
                )),
            );
        }
        cache(&client, documents).await;
        Arc::new(client)
    }

    /// A DID cache holding `documents`, none of which can be fetched again.
    async fn cached_only(documents: &[(String, affinidi_did_common::Document)]) -> Arc<DIDCacheClient> {
        let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("Failed to create DID cache client");
        cache(&client, documents).await;
        Arc::new(client)
    }

    async fn cache(
        client: &DIDCacheClient,
        documents: &[(String, affinidi_did_common::Document)],
    ) {
        for (did, document) in documents {
            client
                .get_cache()
                .insert(DIDCacheClient::hash_did(did), document.clone())
                .await;
        }
    }

    async fn verify_under(
        client: &Arc<DIDCacheClient>,
        vp: &Value,
    ) -> Result<VpVerificationResult, String> {
        LocalVerifier::new(client.clone())
            .verify_vp(vp)
            .await
            .map_err(|e| format!("{e:#}"))
    }

    struct PurposeCase {
        client: Arc<DIDCacheClient>,
        vp: Value,
        vc: Value,
    }

    async fn did_web_issuer_case(relationships: &[&str]) -> PurposeCase {
        let issuer_key = JWK::generate_ed25519().unwrap();
        let issuer = did_web_signer(&issuer_key, relationships);
        let holder_key = JWK::generate_ed25519().unwrap();
        let holder_did = two_key_peer_did(&holder_key);
        let f = Fixture {
            issuer_config: signer_config(&issuer.0, &issuer_key),
            issuer_did: issuer.0.clone(),
            holder_key,
            holder_did,
            verifier: LocalVerifier::new(verifier_with(&[]).await),
        };
        let vc = issue_vc(&f, &f.holder_did).await;
        let vp = present(&f.holder_key, &f.holder_did, vec![vc.clone()]).await;
        PurposeCase {
            client: verifier_with(&[issuer]).await,
            vp,
            vc,
        }
    }

    fn mismatch_count(role: &str) -> u64 {
        mismatches(role, PurposeReason::NotListed)
    }

    fn mismatches(
        role: &str,
        reason: PurposeReason,
    ) -> u64 {
        crate::metrics::backends::prometheus::PROOF_PURPOSE_MISMATCH
            .with_label_values(&[role, reason.as_str()])
            .get()
    }

    #[tokio::test]
    async fn vc_key_missing_from_assertion_method_is_refused() {
        let case = did_web_issuer_case(&[]).await;
        let before = mismatch_count("vc");

        let err = verify_under(&case.client, &case.vp)
            .await
            .err()
            .expect("a VC key listed under no relationship must be refused");

        assert!(err.contains("VC[0] proof key") && err.contains("is not listed under assertionMethod"), "{err}");
        assert!(mismatch_count("vc") > before);
    }

    #[tokio::test]
    async fn signer_document_that_cannot_be_fetched_again_is_not_cached_again() {
        let case = did_web_issuer_case(&[]).await;
        let (issuer, cached) = cached_issuer_document(&case).await;
        let client = cached_only(&[(issuer.clone(), cached)]).await;
        let before = mismatches("vc", PurposeReason::Unresolvable);

        verify_under(&client, &case.vp)
            .await
            .err()
            .expect("a VC key the cached document does not list must be refused");

        assert!(mismatches("vc", PurposeReason::Unresolvable) > before);

        assert!(
            client
                .get_cache()
                .get(&DIDCacheClient::hash_did(&issuer))
                .await
                .is_none(),
            "the out-of-date document must not be cached again"
        );
    }

    #[test]
    fn a_signer_document_is_refreshed_at_most_once_per_interval() {
        let did = format!("did:web:example.com:{}", uuid::Uuid::new_v4());
        let other = format!("did:web:example.com:{}", uuid::Uuid::new_v4());

        assert!(may_refresh_signer_document(&did));
        assert!(!may_refresh_signer_document(&did));
        assert!(may_refresh_signer_document(&other));
    }

    fn first_vc_mut(vp: &mut Value) -> &mut Value {
        if vp["verifiableCredential"].is_array() {
            &mut vp["verifiableCredential"][0]
        } else {
            &mut vp["verifiableCredential"]
        }
    }

    fn embedded_method(
        issuer: &str,
        key: &JWK,
    ) -> Value {
        json!({
            "id": format!("{issuer}#key-2"),
            "type": "Multikey",
            "controller": issuer,
            "publicKeyMultibase": jwk_to_multibase_ed25519(key).unwrap(),
        })
    }

    #[tokio::test]
    async fn relative_verification_method_is_refused() {
        let mut case = did_web_issuer_case(&["assertionMethod"]).await;
        first_vc_mut(&mut case.vp)["proof"]["verificationMethod"] = json!("#key-2");

        verify_under(&case.client, &case.vp)
            .await
            .err()
            .expect("a relative verification method must be refused");
    }

    #[tokio::test]
    async fn embedded_verification_method_is_checked_by_its_id() {
        for (relationships, listed) in [(&["assertionMethod"][..], true), (&[][..], false)] {
            let case = did_web_issuer_case(relationships).await;
            let (issuer, cached) = cached_issuer_document(&case).await;
            let mut vc = case.vc.clone();
            vc["proof"]["verificationMethod"] = embedded_method(&issuer, &JWK::generate_ed25519().unwrap());
            let vc: AnyDataIntegrity<JsonCredential> = serde_json::from_value(vc).unwrap();
            let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(CompositeResolver::new(
                verifier_with(&[(issuer, cached)]).await,
            ));

            let problem = proof_purpose_problem(vc.proofs.first().unwrap(), VC_PROOF_PURPOSES, &resolver).await;

            assert_eq!(problem.map(|p| p.reason), (!listed).then_some(PurposeReason::NotListed));
        }
    }

    #[tokio::test]
    async fn vc_key_under_assertion_method_verifies() {
        let case = did_web_issuer_case(&["assertionMethod"]).await;

        let result = verify_under(&case.client, &case.vp)
            .await
            .expect("a VC key listed under assertionMethod verifies");

        assert_eq!(result.credentials.len(), 1);
    }

    #[tokio::test]
    async fn did_peer_presentation_verifies() {
        let (vp, holder_did) = mint_vp().await;

        let result = verify_under(&verifier_with(&[]).await, &vp)
            .await
            .expect("did:peer keys are listed under assertionMethod");

        assert_eq!(result.holder_did, holder_did);
    }

    #[tokio::test]
    async fn vp_key_missing_from_assertion_method_is_refused() {
        let issuer_key = JWK::generate_ed25519().unwrap();
        let issuer_did = two_key_peer_did(&issuer_key);
        let holder_key = JWK::generate_ed25519().unwrap();
        let holder = did_web_signer(&holder_key, &[]);
        let f = Fixture {
            issuer_config: signer_config(&issuer_did, &issuer_key),
            issuer_did,
            holder_key,
            holder_did: holder.0.clone(),
            verifier: LocalVerifier::new(verifier_with(&[]).await),
        };
        let vc = issue_vc(&f, &f.holder_did).await;
        let vp = present(&f.holder_key, &f.holder_did, vec![vc]).await;

        let err = verify_under(&verifier_with(&[holder]).await, &vp)
            .await
            .err()
            .expect("a VP key listed under no relationship must be refused");

        assert!(err.contains("VP proof key") && err.contains("is not listed under assertionMethod"), "{err}");
    }

    /// ssi alone never checks the proof purpose: it accepts a presentation that declares
    /// `authentication` although the holder lists its key under `assertionMethod` only. The
    /// purpose check refuses it.
    #[tokio::test]
    async fn only_the_purpose_check_refuses_authentication_by_a_key_listed_for_assertion() {
        let issuer_key = JWK::generate_ed25519().unwrap();
        let issuer_did = two_key_peer_did(&issuer_key);
        let holder_key = JWK::generate_ed25519().unwrap();
        let holder = did_web_signer(&holder_key, &["assertionMethod"]);
        let f = Fixture {
            issuer_config: signer_config(&issuer_did, &issuer_key),
            issuer_did,
            holder_key,
            holder_did: holder.0.clone(),
            verifier: LocalVerifier::new(verifier_with(&[]).await),
        };
        let vc = issue_vc(&f, &f.holder_did).await;
        let vp = present_for(&f.holder_key, &f.holder_did, vec![vc], ProofPurpose::Authentication).await;
        let client = verifier_with(&[holder]).await;
        let env = create_signature_environment(None)
            .await
            .unwrap();
        let params = VerificationParameters::from_resolver(VerificationMethodDIDResolver::<_, AnyMethod>::new(
            CompositeResolver::new(client.clone()),
        ))
        .with_json_ld_loader(env.json_ld_loader);
        let typed: AnyDataIntegrity<JsonPresentation<AnyDataIntegrity<JsonCredential>>> =
            serde_json::from_value(vp.clone()).unwrap();

        ensure_verified(typed.verify(&params).await, "VP").expect("ssi alone accepts the declared purpose");
        let err = verify_under(&client, &vp)
            .await
            .err()
            .expect("the purpose check refuses a key not listed under authentication");
        assert!(err.contains("is not listed under authentication"), "{err}");
    }

    #[tokio::test]
    async fn tampered_vc_fails_its_signature_before_its_purpose() {
        let mut case = did_web_issuer_case(&["authentication"]).await;
        first_vc_mut(&mut case.vp)["credentialSubject"]["identityFields"]["region"] = json!("evil");

        let err = verify_under(&case.client, &case.vp)
            .await
            .err()
            .expect("a tampered VC must be refused");

        assert!(err.contains("proof verification failed") && !err.contains("is not listed"), "{err}");
    }

    #[tokio::test]
    async fn proof_purpose_must_be_allowed_and_list_the_key() {
        let case = did_web_issuer_case(&["authentication"]).await;
        let vc: AnyDataIntegrity<JsonCredential> = serde_json::from_value(case.vc.clone()).unwrap();
        let mut declares_authentication = case.vc.clone();
        declares_authentication["proof"]["proofPurpose"] = json!("authentication");
        let declares_authentication: AnyDataIntegrity<JsonCredential> =
            serde_json::from_value(declares_authentication).unwrap();
        let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(CompositeResolver::new(case.client));
        let declares_authentication = declares_authentication
            .proofs
            .first()
            .unwrap();
        let declares_assertion = vc.proofs.first().unwrap();

        let outside = proof_purpose_problem(declares_authentication, VC_PROOF_PURPOSES, &resolver)
            .await
            .expect("a credential proof may not declare authentication");
        assert_eq!(outside.reason, PurposeReason::PurposeNotAllowed);
        let outside = outside.message;
        assert!(outside.contains("declares purpose authentication instead of assertionMethod"), "{outside}");

        assert!(
            proof_purpose_problem(declares_authentication, VP_PROOF_PURPOSES, &resolver)
                .await
                .is_none(),
            "a presentation proof may declare authentication with a key listed under it"
        );

        let unlisted = proof_purpose_problem(declares_assertion, VP_PROOF_PURPOSES, &resolver)
            .await
            .expect("an assertionMethod proof needs its key under assertionMethod");
        assert_eq!(unlisted.reason, PurposeReason::NotListed);
        let unlisted = unlisted.message;
        assert!(unlisted.contains("is not listed under assertionMethod"), "{unlisted}");
    }

    #[tokio::test]
    async fn a_verification_resolves_each_did_once() {
        let key = JWK::generate_ed25519().unwrap();
        let (did, document) = did_web_signer(&key, &["assertionMethod"]);
        let client = verifier_with(&[(did.clone(), document)]).await;
        let resolver = CompositeResolver::new(client.clone());
        let did = DID::new(did.as_str()).unwrap();
        let first = resolver
            .resolve_representation(did, Options::default())
            .await
            .expect("the cached document resolves");
        client
            .remove(did.as_str())
            .await;

        let again = resolver
            .resolve_representation(did, Options::default())
            .await
            .expect("the second resolution reuses the first document");

        assert_eq!(again.document, first.document);
    }

    #[tokio::test]
    async fn presentation_declaring_authentication_needs_its_key_under_authentication() {
        let case = did_web_issuer_case(&["assertionMethod"]).await;
        let mut declares_authentication = case.vc.clone();
        declares_authentication["proof"]["proofPurpose"] = json!("authentication");
        let declares_authentication: AnyDataIntegrity<JsonCredential> =
            serde_json::from_value(declares_authentication).unwrap();
        let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(CompositeResolver::new(case.client));

        let problem = proof_purpose_problem(
            declares_authentication
                .proofs
                .first()
                .unwrap(),
            VP_PROOF_PURPOSES,
            &resolver,
        )
        .await
        .expect("a key listed only under assertionMethod may not sign for authentication");

        assert_eq!(problem.reason, PurposeReason::NotListed);
        assert!(
            problem
                .message
                .contains("is not listed under authentication"),
            "{}",
            problem.message
        );
    }

    #[tokio::test]
    async fn an_unresolvable_signer_is_reported_without_the_resolver_error() {
        let case = did_web_issuer_case(&["assertionMethod"]).await;
        let vc: AnyDataIntegrity<JsonCredential> = serde_json::from_value(case.vc.clone()).unwrap();
        let resolver =
            VerificationMethodDIDResolver::<_, AnyMethod>::new(CompositeResolver::new(verifier_with(&[]).await));

        let problem = proof_purpose_problem(vc.proofs.first().unwrap(), VC_PROOF_PURPOSES, &resolver)
            .await
            .expect("a document that cannot be read cannot list the key");

        assert_eq!(problem.reason, PurposeReason::Unresolvable);
        assert!(
            problem
                .message
                .ends_with("could not be checked against its DID document"),
            "{}",
            problem.message
        );
        assert!(
            !problem
                .message
                .contains("SSRF"),
            "{}",
            problem.message
        );
    }

    struct PublishedDocuments(HashMap<String, affinidi_did_common::Document>);

    impl affinidi_did_resolver_cache_sdk::Resolver for PublishedDocuments {
        fn name(&self) -> &str {
            "PublishedDocuments"
        }

        fn resolve(
            &self,
            did: &affinidi_did_common::DID,
        ) -> affinidi_did_resolver_cache_sdk::Resolution {
            self.0
                .get(&did.to_string())
                .cloned()
                .map(Ok)
        }
    }

    async fn cached_issuer_document(case: &PurposeCase) -> (String, affinidi_did_common::Document) {
        let issuer = case.vc["issuer"]
            .as_str()
            .unwrap()
            .to_string();
        let cached = case
            .client
            .get_cache()
            .get(&DIDCacheClient::hash_did(&issuer))
            .await
            .unwrap();
        (issuer, cached)
    }

    /// A DID cache holding each signer's `cached` document while its DID publishes `published`.
    async fn client_with_published(
        signers: Vec<(String, affinidi_did_common::Document, affinidi_did_common::Document)>
    ) -> Arc<DIDCacheClient> {
        let mut client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let (cached, published): (Vec<_>, HashMap<_, _>) = signers
            .into_iter()
            .map(|(did, cached, published)| ((did.clone(), cached), (did, published)))
            .unzip();
        client.set_resolver(affinidi_did_resolver_cache_sdk::MethodName::Web, Box::new(PublishedDocuments(published)));
        cache(&client, &cached).await;
        Arc::new(client)
    }

    #[tokio::test]
    async fn issuer_that_has_since_listed_its_key_is_accepted() {
        let case = did_web_issuer_case(&[]).await;
        let (issuer, cached) = cached_issuer_document(&case).await;
        let published = listing_key_under_assertion_method(&issuer, &cached);
        let client = client_with_published(vec![(issuer, cached, published)]).await;

        let result = verify_under(&client, &case.vp)
            .await
            .expect("the document as now published lists the key");

        assert_eq!(result.credentials.len(), 1);
    }

    fn listing_key_under_assertion_method(
        did: &str,
        cached: &affinidi_did_common::Document,
    ) -> affinidi_did_common::Document {
        let mut published = serde_json::to_value(cached).unwrap();
        published["assertionMethod"] = json!([format!("{did}#key-2")]);
        serde_json::from_value(published).unwrap()
    }

    #[tokio::test]
    async fn holder_and_issuer_that_have_both_since_listed_their_keys_are_accepted() {
        let issuer_key = JWK::generate_ed25519().unwrap();
        let (issuer_did, issuer_cached) = did_web_signer(&issuer_key, &[]);
        let holder_key = JWK::generate_ed25519().unwrap();
        let (holder_did, holder_cached) = did_web_signer(&holder_key, &[]);
        let f = Fixture {
            issuer_config: signer_config(&issuer_did, &issuer_key),
            issuer_did: issuer_did.clone(),
            holder_key,
            holder_did: holder_did.clone(),
            verifier: LocalVerifier::new(verifier_with(&[]).await),
        };
        let vc = issue_vc(&f, &holder_did).await;
        let vp = present(&f.holder_key, &holder_did, vec![vc]).await;
        let client = client_with_published(
            [(&issuer_did, issuer_cached), (&holder_did, holder_cached)]
                .into_iter()
                .map(|(did, cached)| {
                    let published = listing_key_under_assertion_method(did, &cached);
                    (did.clone(), cached, published)
                })
                .collect(),
        )
        .await;

        let result = verify_under(&client, &vp)
            .await
            .expect("both documents as now published list their keys");

        assert_eq!(result.holder_did, holder_did);
        assert_eq!(result.credentials[0].issuer_did, issuer_did);
    }

    #[tokio::test]
    async fn key_replaced_since_it_was_cached_is_refused() {
        let case = did_web_issuer_case(&[]).await;
        let (issuer, cached) = cached_issuer_document(&case).await;
        let (_, published) = did_web_signer(&JWK::generate_ed25519().unwrap(), &["assertionMethod"]);
        let mut published = serde_json::to_value(&published).unwrap();
        let vm = format!("{issuer}#key-2");
        published["id"] = json!(issuer);
        published["verificationMethod"][0]["id"] = json!(vm);
        published["verificationMethod"][0]["controller"] = json!(issuer);
        published["assertionMethod"] = json!([vm]);
        let client = client_with_published(vec![(issuer, cached, serde_json::from_value(published).unwrap())]).await;

        let err = verify_under(&client, &case.vp)
            .await
            .err()
            .expect("a signature by a key the published document no longer holds must be refused");

        assert!(err.contains("VC[0]") && !err.contains("is not listed"), "{err}");
    }
}
