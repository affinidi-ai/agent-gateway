use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use openssl::pkey::PKey;
use openssl::x509::X509;
use samael::schema::{Assertion, Conditions, Response};
use std::collections::HashMap;
use std::fs;
use tracing::{info, warn};

use super::pending_requests::PendingRequests;
use super::relay_state::ReturnTargetStore;
use crate::auth::auth_config::SamlConfig;

/// How long an SP-initiated AuthnRequest, and the return target kept for it,
/// stays outstanding, waiting for a matching response's InResponseTo.
pub(super) const AUTHN_REQUEST_TTL: Duration = Duration::minutes(5);

/// Clock skew tolerance applied to assertion NotBefore/NotOnOrAfter checks.
const CLOCK_SKEW: Duration = Duration::seconds(180);

/// Too many AuthnRequests are outstanding to start another sign-in.
#[derive(Debug)]
pub struct TooManyPendingAuthnRequests;

impl std::fmt::Display for TooManyPendingAuthnRequests {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.write_str("too many SAML sign-ins are in progress")
    }
}

impl std::error::Error for TooManyPendingAuthnRequests {}

/// SAML Service Provider implementation
pub struct SamlService {
    /// SAML configuration
    config: SamlConfig,

    /// SHA-256 thumbprints of the trusted IdP signing cert(s), used to pin
    /// the certificate embedded in the response signature. `idp_cert_path`
    /// may hold more than one concatenated PEM certificate — IdPs such as
    /// Azure AD keep multiple signing certs valid at once during a rotation
    /// window, so pinning to exactly one would break login mid-rotation.
    idp_cert_thumbprints: Vec<String>,

    /// SP private key for signing requests (if sign_requests = true)
    sp_key: Option<PKey<openssl::pkey::Private>>,

    /// SP certificate (if sign_requests = true)
    sp_cert: Option<X509>,

    /// Outstanding SP-initiated AuthnRequests, matched once against a response's InResponseTo.
    pending_requests: PendingRequests,

    /// Post-login return targets, keyed by the one-time `RelayState` sent with the request.
    return_targets: ReturnTargetStore,
}

impl SamlService {
    /// Create a new SAML service
    pub fn new(config: SamlConfig) -> Result<Self> {
        // Load IdP certificate(s) - idp_cert_path may hold one or more
        // concatenated PEM certificates (see idp_cert_thumbprints doc).
        let idp_cert_pem = fs::read_to_string(&config.idp_cert_path)
            .with_context(|| format!("Failed to read IdP certificate from {}", config.idp_cert_path))?;

        let idp_certs = X509::stack_from_pem(idp_cert_pem.as_bytes()).context("Failed to parse IdP certificate(s)")?;
        if idp_certs.is_empty() {
            anyhow::bail!("No IdP certificates found in {}", config.idp_cert_path);
        }
        let idp_cert_thumbprints: Vec<String> = idp_certs
            .iter()
            .map(|cert| {
                cert_sha256_thumbprint(cert)
                    .context("Could not compute a SHA-256 thumbprint for an IdP signing certificate")
            })
            .collect::<Result<_>>()?;

        // Load SP signing credentials if request signing is enabled
        let (sp_key, sp_cert) = if config.sign_requests {
            let key_path = config
                .sp_key_path
                .as_ref()
                .context("sp_key_path required when sign_requests = true")?;
            let cert_path = config
                .sp_cert_path
                .as_ref()
                .context("sp_cert_path required when sign_requests = true")?;

            // Load private key
            let key_pem = fs::read_to_string(key_path)
                .with_context(|| format!("Failed to read SP private key from {}", key_path))?;
            let key = PKey::private_key_from_pem(key_pem.as_bytes()).context("Failed to parse SP private key")?;

            // Load certificate
            let cert_pem = fs::read_to_string(cert_path)
                .with_context(|| format!("Failed to read SP certificate from {}", cert_path))?;
            let cert = X509::from_pem(cert_pem.as_bytes()).context("Failed to parse SP certificate")?;

            info!("Loaded SP signing credentials for SAML request signing");
            (Some(key), Some(cert))
        } else {
            (None, None)
        };

        Ok(Self {
            config,
            idp_cert_thumbprints,
            sp_key,
            sp_cert,
            pending_requests: PendingRequests::default(),
            return_targets: ReturnTargetStore::default(),
        })
    }

    /// Generate SP metadata XML
    pub fn generate_metadata(&self) -> Result<String> {
        // Include certificate in metadata if signing is enabled
        let cert_section = if let Some(cert) = &self.sp_cert {
            let cert_der = cert
                .to_der()
                .context("Failed to convert certificate to DER")?;
            let cert_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cert_der);
            format!(
                r#"
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>{}</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>"#,
                cert_b64
            )
        } else {
            String::new()
        };

        // Create SP metadata with certificate if available
        let metadata = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{}">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="{}" WantAssertionsSigned="true">{}
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{}" index="0" isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>"#,
            self.config.sp_entity_id, self.config.sign_requests, cert_section, self.config.sp_acs_url
        );

        Ok(metadata)
    }

    /// Create an authentication request (for SP-initiated flow). Fails with
    /// [`TooManyPendingAuthnRequests`] when too many requests are still outstanding. A return
    /// target is kept on the gateway and only its one-time key is sent as `RelayState`; when that
    /// store is full the request goes without one, so the sign-in lands on the dashboard root.
    pub fn create_authn_request(
        &self,
        return_target: Option<&str>,
    ) -> Result<String> {
        use uuid::Uuid;

        // Generate unique request ID and timestamp
        let request_id = format!("_{}", Uuid::new_v4());
        let issue_instant = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        let now = Utc::now();
        if !self
            .pending_requests
            .register(request_id.clone(), now)
        {
            return Err(TooManyPendingAuthnRequests.into());
        }

        // Create AuthnRequest XML
        let authn_request = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}" AssertionConsumerServiceURL="{}" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>{}</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>
</samlp:AuthnRequest>"#,
            request_id, issue_instant, self.config.idp_sso_url, self.config.sp_acs_url, self.config.sp_entity_id
        );

        // Sign the request if signing is enabled
        let final_request = if self.config.sign_requests {
            self.sign_authn_request(&authn_request)?
        } else {
            authn_request
        };

        // Deflate and base64 encode
        use flate2::Compression;
        use flate2::write::DeflateEncoder;
        use std::io::Write;

        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(final_request.as_bytes())
            .context("Failed to deflate AuthnRequest")?;
        let deflated = encoder
            .finish()
            .context("Failed to finish deflating")?;

        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &deflated);
        let encoded_url = urlencoding::encode(&encoded);

        // Create redirect URL
        let mut redirect_url = format!("{}?SAMLRequest={}", self.config.idp_sso_url, encoded_url);
        let relay_state = return_target.and_then(|target| {
            let key = self
                .return_targets
                .insert(target, now);
            if key.is_none() {
                warn!("Too many pending SAML return targets; sending the AuthnRequest without RelayState");
            }
            key
        });
        if let Some(key) = relay_state {
            redirect_url.push_str(&format!("&RelayState={key}"));
        }

        info!("Created SAML AuthnRequest (signed: {})", self.config.sign_requests);
        Ok(redirect_url)
    }

    /// Returns the return target stored for a `RelayState` key, once. Unknown, expired and
    /// already used keys return `None`.
    pub fn take_return_target(
        &self,
        relay_state: &str,
    ) -> Option<String> {
        self.return_targets
            .take(relay_state, Utc::now())
    }

    /// Sign an AuthnRequest XML
    fn sign_authn_request(
        &self,
        xml: &str,
    ) -> Result<String> {
        use openssl::hash::MessageDigest;
        use openssl::sign::Signer;

        let key = self
            .sp_key
            .as_ref()
            .context("SP private key not loaded")?;
        let cert = self
            .sp_cert
            .as_ref()
            .context("SP certificate not loaded")?;

        // Calculate SHA-256 digest of the canonicalized XML
        let mut signer = Signer::new(MessageDigest::sha256(), key).context("Failed to create signer")?;
        signer
            .update(xml.as_bytes())
            .context("Failed to update signer")?;
        let signature = signer
            .sign_to_vec()
            .context("Failed to sign")?;

        let signature_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &signature);
        let cert_der = cert
            .to_der()
            .context("Failed to convert certificate to DER")?;
        let cert_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cert_der);

        // Insert signature into XML after <Issuer> element (correct SAML position)
        let signed_xml = xml.replace(
            "</saml:Issuer>",
            &format!(
                r#"</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue/>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>{}</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>{}</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>"#,
                signature_b64, cert_b64
            ),
        );

        Ok(signed_xml)
    }

    /// Validate a SAML response and extract assertions
    pub fn validate_response(
        &self,
        saml_response: &str,
    ) -> Result<Assertion> {
        info!("Validating SAML response");

        // Decode base64 response
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(saml_response)
            .context("Failed to decode SAML response")?;

        let response_xml = String::from_utf8(decoded).context("Failed to parse SAML response as UTF-8")?;

        // Reject a response carrying more than one Assertion element before
        // any of it is trusted: xmlsec1 (below) verifies that *a* signature
        // in the document is cryptographically valid, but the struct
        // deserializer further down simply takes whichever Assertion sits at
        // Response.assertion. A second, unsigned or falsely-signed Assertion
        // planted elsewhere in the tree — the classic XML Signature Wrapping
        // attack — would otherwise let a forged assertion be trusted while
        // the original, genuinely-signed one is what gets verified.
        reject_multiple_assertions(&response_xml)?;

        // Verify the IdP's XML-DSig signature with the xmlsec1 CLI — which
        // resolves the SAML Assertion `ID` reference that samael 0.0.21
        // cannot — and pin the signing certificate to the trusted IdP cert
        // before trusting any content in the response.
        self.verify_signing_cert_pinned(&response_xml)?;
        verify_xml_signature(response_xml.as_bytes(), &self.config.idp_cert_path)?;

        let response: Response = quick_xml::de::from_str(&response_xml).context("Failed to parse SAML response XML")?;

        // Validate response
        self.validate_response_structure(&response)?;

        // Extract and validate assertion (assertion is Option<Assertion>)
        let assertion = response
            .assertion
            .context("No assertion found in SAML response")?;

        // Assertion must itself carry a signature.
        self.verify_assertion_signature(&assertion)?;

        // Validate assertion conditions
        self.validate_assertion_conditions(&assertion)?;

        info!("SAML response validated successfully");
        Ok(assertion)
    }

    /// Validate response structure
    fn validate_response_structure(
        &self,
        response: &Response,
    ) -> Result<()> {
        check_response_structure(response, &self.config.sp_acs_url, &self.pending_requests, Utc::now())
    }

    /// Ensure the assertion carries a signature. Cryptographic verification of
    /// the response's XML-DSig signature is performed in `validate_response`.
    fn verify_assertion_signature(
        &self,
        assertion: &Assertion,
    ) -> Result<()> {
        if assertion.signature.is_none() {
            anyhow::bail!("Assertion is not signed");
        }
        Ok(())
    }

    /// Ensure the certificate embedded in the response signature is one of
    /// the trusted IdP signing certs (pinning).
    fn verify_signing_cert_pinned(
        &self,
        xml: &str,
    ) -> Result<()> {
        use base64::Engine;
        let embedded: Vec<String> = extract_cert_b64s(xml)
            .into_iter()
            .filter_map(|b64| {
                base64::engine::general_purpose::STANDARD
                    .decode(b64.as_bytes())
                    .ok()
            })
            .filter_map(|der| X509::from_der(&der).ok())
            .filter_map(|cert| cert_sha256_thumbprint(&cert))
            .collect();
        if embedded.is_empty() {
            anyhow::bail!("SAML response has no embedded signing certificate");
        }
        if embedded.iter().any(|tp| {
            self.idp_cert_thumbprints
                .contains(tp)
        }) {
            Ok(())
        } else {
            anyhow::bail!(
                "SAML response signed by an untrusted certificate (got {embedded:?}, trusted {:?})",
                self.idp_cert_thumbprints
            )
        }
    }

    /// Validate assertion conditions
    fn validate_assertion_conditions(
        &self,
        assertion: &Assertion,
    ) -> Result<()> {
        let conditions = assertion
            .conditions
            .as_ref()
            .context("No conditions in assertion")?;

        check_assertion_conditions(conditions, Utc::now(), &self.config.sp_entity_id)
    }

    /// Extract user attributes from assertion
    pub fn extract_attributes(
        &self,
        assertion: &Assertion,
    ) -> Result<HashMap<String, String>> {
        let mut attributes = HashMap::new();

        // attribute_statements is Option<Vec<AttributeStatement>>
        if let Some(statements) = &assertion.attribute_statements
            && let Some(attribute_statement) = statements.first()
        {
            for attr in &attribute_statement.attributes {
                // Use 'values' instead of 'attribute_values' per samael API
                if let Some(attr_value) = attr.values.first() {
                    // AttributeValue has a 'value: Option<String>' field
                    // attr.name is also Option<String>
                    if let (Some(name), Some(text)) = (&attr.name, &attr_value.value) {
                        attributes.insert(name.clone(), text.clone());
                    }
                }
            }
        }

        // Also extract NameID if present
        if let Some(subject) = &assertion.subject
            && let Some(name_id) = &subject.name_id
        {
            attributes.insert("NameID".to_string(), name_id.value.clone());
        }

        Ok(attributes)
    }

    /// Get configuration
    pub fn config(&self) -> &SamlConfig {
        &self.config
    }
}

/// Reject a SAML response that does not contain exactly one `Assertion`
/// element anywhere in the document (see the XSW comment at the call site).
fn reject_multiple_assertions(xml: &str) -> Result<()> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml);
    let mut count = 0usize;
    loop {
        match reader
            .read_event()
            .context("Failed to scan SAML response for Assertion elements")?
        {
            Event::Eof => break,
            Event::Start(e) | Event::Empty(e) if e.local_name().as_ref() == b"Assertion" => {
                count += 1;
            }
            _ => {}
        }
    }

    if count != 1 {
        anyhow::bail!(
            "SAML response must contain exactly one Assertion element, found {count} (possible XML Signature Wrapping attack)"
        );
    }
    Ok(())
}

/// Enforce a `Response`'s Status, Destination and InResponseTo. All three
/// fields are required (fail closed) — a forged response could otherwise
/// bypass any one check simply by omitting it. Matching InResponseTo
/// consumes the pending request, so a captured response cannot be replayed
/// against a second `/saml/acs` POST, and an unsolicited (IdP-initiated)
/// response is rejected outright since this service only drives SP-initiated
/// login.
fn check_response_structure(
    response: &Response,
    sp_acs_url: &str,
    pending_requests: &PendingRequests,
    now: DateTime<Utc>,
) -> Result<()> {
    let status = response
        .status
        .as_ref()
        .context("SAML response missing Status")?;
    let code_value = status
        .status_code
        .value
        .as_ref()
        .context("SAML response missing StatusCode value")?;
    if code_value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
        anyhow::bail!("SAML authentication failed: {}", code_value);
    }

    let destination = response
        .destination
        .as_ref()
        .context("SAML response missing Destination")?;
    if destination != sp_acs_url {
        anyhow::bail!("Invalid destination in SAML response");
    }

    let in_response_to = response
        .in_response_to
        .as_ref()
        .context("SAML response missing InResponseTo (unsolicited responses are not accepted)")?;
    match pending_requests.consume(in_response_to) {
        Some(expiry) if expiry > now => {}
        Some(_) => anyhow::bail!("SAML response's AuthnRequest has expired"),
        None => {
            anyhow::bail!("SAML response does not match an outstanding AuthnRequest (possible replay)")
        }
    }

    Ok(())
}

/// Enforce an assertion's `Conditions`: NotBefore/NotOnOrAfter (within
/// `CLOCK_SKEW`) and audience restriction against `sp_entity_id`. Both
/// NotOnOrAfter and AudienceRestriction are required — a forged or replayed
/// assertion could otherwise bypass either check simply by omitting it.
fn check_assertion_conditions(
    conditions: &Conditions,
    now: DateTime<Utc>,
    sp_entity_id: &str,
) -> Result<()> {
    if let Some(not_before) = conditions.not_before
        && now < not_before - CLOCK_SKEW
    {
        anyhow::bail!("Assertion is not yet valid (NotBefore: {})", not_before);
    }

    let not_on_or_after = conditions
        .not_on_or_after
        .context("Assertion conditions missing NotOnOrAfter")?;
    if not_on_or_after + CLOCK_SKEW < now {
        anyhow::bail!("Assertion has expired (NotOnOrAfter: {})", not_on_or_after);
    }

    let audience_restrictions = conditions
        .audience_restrictions
        .as_ref()
        .context("Assertion conditions missing AudienceRestriction")?;
    let valid_audience = audience_restrictions
        .iter()
        .any(|restriction| {
            restriction
                .audience
                .iter()
                .any(|a| a == sp_entity_id)
        });
    if !valid_audience {
        anyhow::bail!("Invalid audience in assertion");
    }

    Ok(())
}

/// Removes its wrapped path on drop, guaranteeing cleanup of the staged
/// SAML XML even on an early return or panic from `xmlsec1` invocation.
struct TempFileGuard(std::path::PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Verify an XML digital signature with the `xmlsec1` CLI, registering the SAML
/// `ID` attributes so the enveloped Assertion/Response references resolve, and
/// trusting only the configured IdP certificate. `Ok` means the signature is
/// cryptographically valid and was produced with the trusted IdP key.
fn verify_xml_signature(
    xml_bytes: &[u8],
    idp_cert_path: &str,
) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let tmp = std::env::temp_dir().join(format!("tg-saml-verify-{}.xml", uuid::Uuid::new_v4()));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .context("Failed to stage SAML response for verification")?;
    let _guard = TempFileGuard(tmp.clone());
    std::io::Write::write_all(&mut f, xml_bytes).context("Failed to stage SAML response for verification")?;
    drop(f);

    let output = std::process::Command::new("xmlsec1")
        .args([
            "--verify",
            "--trusted-pem",
            idp_cert_path,
            "--id-attr:ID",
            "urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
            "--id-attr:ID",
            "urn:oasis:names:tc:SAML:2.0:protocol:Response",
        ])
        .arg(&tmp)
        .output()
        .context("Failed to run xmlsec1 (install the xmlsec1 CLI)")?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("XML signature verification failed: {}", stderr.trim())
    }
}

/// SHA-256 thumbprint (`XX:XX:…`) of a certificate.
fn cert_sha256_thumbprint(cert: &X509) -> Option<String> {
    cert.digest(openssl::hash::MessageDigest::sha256())
        .ok()
        .map(|d| {
            d.iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        })
}

/// Extract every base64 `X509Certificate` payload embedded in the XML.
fn extract_cert_b64s(xml: &str) -> Vec<String> {
    let marker = "X509Certificate>";
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find(marker) {
        let after = &rest[i + marker.len()..];
        match after.find('<') {
            Some(end) => {
                let candidate: String = after[..end]
                    .split_whitespace()
                    .collect();
                if !candidate.is_empty() {
                    out.push(candidate);
                }
                rest = &after[end..];
            }
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use samael::schema::{AudienceRestriction, Status, StatusCode};

    const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
    const ACS_URL: &str = "https://sp.example/saml/acs";

    fn conditions(
        not_before: Option<DateTime<Utc>>,
        not_on_or_after: Option<DateTime<Utc>>,
        audience: Option<Vec<String>>,
    ) -> Conditions {
        Conditions {
            not_before,
            not_on_or_after,
            audience_restrictions: audience.map(|a| vec![AudienceRestriction { audience: a }]),
            one_time_use: None,
            proxy_restriction: None,
        }
    }

    #[test]
    fn accepts_conditions_within_window_and_matching_audience() {
        let now = Utc::now();
        let c = conditions(
            Some(now - Duration::minutes(1)),
            Some(now + Duration::minutes(1)),
            Some(vec!["sp-entity".to_string()]),
        );
        assert!(check_assertion_conditions(&c, now, "sp-entity").is_ok());
    }

    #[test]
    fn rejects_expired_assertion() {
        let now = Utc::now();
        let c = conditions(None, Some(now - Duration::minutes(10)), Some(vec!["sp-entity".to_string()]));
        assert!(check_assertion_conditions(&c, now, "sp-entity").is_err());
    }

    #[test]
    fn rejects_assertion_not_yet_valid() {
        let now = Utc::now();
        let c = conditions(
            Some(now + Duration::minutes(10)),
            Some(now + Duration::minutes(20)),
            Some(vec!["sp-entity".to_string()]),
        );
        assert!(check_assertion_conditions(&c, now, "sp-entity").is_err());
    }

    #[test]
    fn rejects_missing_not_on_or_after() {
        let now = Utc::now();
        let c = conditions(None, None, Some(vec!["sp-entity".to_string()]));
        assert!(check_assertion_conditions(&c, now, "sp-entity").is_err());
    }

    #[test]
    fn rejects_missing_audience_restriction() {
        let now = Utc::now();
        let c = conditions(None, Some(now + Duration::minutes(5)), None);
        assert!(check_assertion_conditions(&c, now, "sp-entity").is_err());
    }

    #[test]
    fn rejects_wrong_audience() {
        let now = Utc::now();
        let c = conditions(None, Some(now + Duration::minutes(5)), Some(vec!["someone-else".to_string()]));
        assert!(check_assertion_conditions(&c, now, "sp-entity").is_err());
    }

    fn response_with(
        status_code: Option<&str>,
        destination: Option<&str>,
        in_response_to: Option<&str>,
    ) -> Response {
        Response {
            id: "resp-1".to_string(),
            in_response_to: in_response_to.map(str::to_string),
            version: "2.0".to_string(),
            issue_instant: Utc::now(),
            destination: destination.map(str::to_string),
            consent: None,
            issuer: None,
            signature: None,
            status: status_code.map(|v| Status {
                status_code: StatusCode { value: Some(v.to_string()) },
                status_message: None,
                status_detail: None,
            }),
            encrypted_assertion: None,
            assertion: None,
        }
    }

    #[test]
    fn accepts_matching_pending_request_and_consumes_it() {
        let now = Utc::now();
        let pending = PendingRequests::default();
        assert!(pending.register("req-1".to_string(), now));
        let response = response_with(Some(SUCCESS), Some(ACS_URL), Some("req-1"));

        assert!(check_response_structure(&response, ACS_URL, &pending, now).is_ok());
        // Replaying the same response must fail now that the request is consumed.
        assert!(check_response_structure(&response, ACS_URL, &pending, now).is_err());
    }

    #[test]
    fn rejects_unknown_in_response_to() {
        let pending = PendingRequests::default();
        let response = response_with(Some(SUCCESS), Some(ACS_URL), Some("unknown"));
        assert!(check_response_structure(&response, ACS_URL, &pending, Utc::now()).is_err());
    }

    #[test]
    fn rejects_expired_pending_request() {
        let now = Utc::now();
        let pending = PendingRequests::default();
        assert!(pending.register("req-1".to_string(), now - AUTHN_REQUEST_TTL - Duration::seconds(1)));
        let response = response_with(Some(SUCCESS), Some(ACS_URL), Some("req-1"));
        assert!(check_response_structure(&response, ACS_URL, &pending, now).is_err());
    }

    #[test]
    fn rejects_missing_in_response_to() {
        let pending = PendingRequests::default();
        let response = response_with(Some(SUCCESS), Some(ACS_URL), None);
        assert!(check_response_structure(&response, ACS_URL, &pending, Utc::now()).is_err());
    }

    #[test]
    fn rejects_missing_status() {
        let now = Utc::now();
        let pending = PendingRequests::default();
        assert!(pending.register("req-1".to_string(), now));
        let response = response_with(None, Some(ACS_URL), Some("req-1"));
        assert!(check_response_structure(&response, ACS_URL, &pending, now).is_err());
    }

    #[test]
    fn rejects_failure_status_code() {
        let now = Utc::now();
        let pending = PendingRequests::default();
        assert!(pending.register("req-1".to_string(), now));
        let response =
            response_with(Some("urn:oasis:names:tc:SAML:2.0:status:Requester"), Some(ACS_URL), Some("req-1"));
        assert!(check_response_structure(&response, ACS_URL, &pending, now).is_err());
    }

    #[test]
    fn rejects_missing_destination() {
        let now = Utc::now();
        let pending = PendingRequests::default();
        assert!(pending.register("req-1".to_string(), now));
        let response = response_with(Some(SUCCESS), None, Some("req-1"));
        assert!(check_response_structure(&response, ACS_URL, &pending, now).is_err());
    }

    #[test]
    fn rejects_wrong_destination() {
        let now = Utc::now();
        let pending = PendingRequests::default();
        assert!(pending.register("req-1".to_string(), now));
        let response = response_with(Some(SUCCESS), Some("https://evil.example/acs"), Some("req-1"));
        assert!(check_response_structure(&response, ACS_URL, &pending, now).is_err());
    }

    #[test]
    fn extracts_embedded_certificates() {
        let xml = "<ds:X509Certificate>AAAB\n  BBBB</ds:X509Certificate><X509Certificate>CCCC</X509Certificate>";
        assert_eq!(extract_cert_b64s(xml), vec!["AAABBBBB".to_string(), "CCCC".to_string()]);
    }

    #[test]
    fn extracts_nothing_when_no_certificate_present() {
        assert!(extract_cert_b64s("<samlp:Response>no certs</samlp:Response>").is_empty());
    }

    #[test]
    fn accepts_response_with_exactly_one_assertion() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Assertion ID="a1"></saml:Assertion>
        </samlp:Response>"#;
        assert!(reject_multiple_assertions(xml).is_ok());
    }

    #[test]
    fn rejects_response_with_no_assertion() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"></samlp:Response>"#;
        assert!(reject_multiple_assertions(xml).is_err());
    }

    #[test]
    fn rejects_response_with_a_second_wrapped_assertion() {
        // Simulates an XML Signature Wrapping attempt: a genuine signed
        // Assertion alongside a second, forged one planted elsewhere in the
        // tree (e.g. inside an Extensions wrapper).
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Assertion ID="forged"></saml:Assertion>
            <samlp:Extensions>
                <saml:Assertion ID="genuine"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Signature></saml:Assertion>
            </samlp:Extensions>
        </samlp:Response>"#;
        assert!(reject_multiple_assertions(xml).is_err());
    }

    #[test]
    fn rejects_response_with_self_closing_second_assertion() {
        let xml = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml:Assertion ID="a1"></saml:Assertion>
            <saml:Assertion ID="a2"/>
        </samlp:Response>"#;
        assert!(reject_multiple_assertions(xml).is_err());
    }
}
