//! A SAML identity provider stand-in: starts a sign-in at the gateway and answers it with an
//! assertion signed by the identity provider key the scenario fixture wrote.

use std::io::Read;
use std::path::Path;
use std::process::Command;

use base64::Engine;
use reqwest::header::LOCATION;

const NAME_ID_CLAIM: &str = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
const NAME_CLAIM: &str = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
const EMAIL_CLAIM: &str = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
const ROLE_CLAIM: &str = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";

/// The gateway's answer to an assertion.
pub struct AcsAnswer {
    pub status: u16,
    pub set_cookies: Vec<String>,
    pub body: String,
}

/// Starts a SAML sign-in at the gateway on `port` and returns the AuthnRequest's ID.
async fn start_sign_in(
    client: &reqwest::Client,
    port: u16,
) -> String {
    let response = client
        .get(format!("http://127.0.0.1:{port}/api/saml/login"))
        .send()
        .await
        .expect("start the SAML sign-in");
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("the sign-in redirects to the identity provider; it answered {}", response.status()))
        .to_string();
    let request = location
        .split("SAMLRequest=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("a SAMLRequest in the redirect");
    let decoded = urlencoding::decode(request).expect("a URL-encoded SAMLRequest");
    let deflated = base64::engine::general_purpose::STANDARD
        .decode(decoded.as_bytes())
        .expect("a base64 SAMLRequest");
    let mut xml = String::new();
    flate2::read::DeflateDecoder::new(deflated.as_slice())
        .read_to_string(&mut xml)
        .expect("a deflated AuthnRequest");
    let after_id = xml
        .split(" ID=\"")
        .nth(1)
        .expect("an ID in the AuthnRequest");
    after_id
        .split('"')
        .next()
        .expect("a closing quote")
        .to_string()
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn attribute(
    name: &str,
    values: &[String],
) -> String {
    let values: String = values
        .iter()
        .map(|value| format!("<saml:AttributeValue>{}</saml:AttributeValue>", escape(value)))
        .collect();
    format!("<saml:Attribute Name=\"{name}\">{values}</saml:Attribute>")
}

#[derive(Clone, Copy)]
pub enum AssertionLayout {
    SameStatement,
    SecondStatement,
    RepeatedAttribute,
    RepeatedUserId,
    UserIdInSecondStatement,
    RepeatedUsername,
    RepeatedEmail,
}

fn template(
    port: u16,
    in_response_to: &str,
    subject: &str,
    roles: &[String],
    layout: AssertionLayout,
) -> String {
    let now = chrono::Utc::now();
    let issued = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let expires = (now + chrono::Duration::minutes(5)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let not_before = (now - chrono::Duration::minutes(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut attributes = vec![
        attribute(NAME_ID_CLAIM, &[subject.to_string()]),
        attribute(NAME_CLAIM, &[subject.to_string()]),
        attribute(EMAIL_CLAIM, &[format!("{subject}@example.test")]),
    ];
    let mut second_statement = String::new();
    let other = [format!("{subject}-other")];
    match layout {
        AssertionLayout::RepeatedUserId => attributes.push(attribute(NAME_ID_CLAIM, &other)),
        AssertionLayout::UserIdInSecondStatement => {
            second_statement =
                format!("<saml:AttributeStatement>{}</saml:AttributeStatement>", attribute(NAME_ID_CLAIM, &other));
        }
        AssertionLayout::RepeatedUsername => attributes.push(attribute(NAME_CLAIM, &other)),
        AssertionLayout::RepeatedEmail => attributes.push(attribute(EMAIL_CLAIM, &other)),
        _ => {}
    }
    if !roles.is_empty() {
        match layout {
            AssertionLayout::SameStatement => attributes.push(attribute(ROLE_CLAIM, roles)),
            AssertionLayout::SecondStatement => {
                second_statement =
                    format!("<saml:AttributeStatement>{}</saml:AttributeStatement>", attribute(ROLE_CLAIM, roles));
            }
            AssertionLayout::RepeatedUserId
            | AssertionLayout::UserIdInSecondStatement
            | AssertionLayout::RepeatedUsername
            | AssertionLayout::RepeatedEmail => attributes.push(attribute(ROLE_CLAIM, roles)),
            AssertionLayout::RepeatedAttribute => {
                attributes.extend(
                    roles
                        .iter()
                        .map(|role| attribute(ROLE_CLAIM, std::slice::from_ref(role))),
                );
            }
        }
    }
    let attributes: String = attributes.concat();
    format!(
        r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="{issued}" Destination="http://localhost:{port}/api/saml/acs" InResponseTo="{in_response_to}"><saml:Issuer>https://idp.example.test</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_assertion" Version="2.0" IssueInstant="{issued}"><saml:Issuer>https://idp.example.test</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/><ds:Reference URI="#_assertion"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data/></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID>{subject}</saml:NameID></saml:Subject><saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{expires}"><saml:AudienceRestriction><saml:Audience>http://localhost:{port}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AttributeStatement>{attributes}</saml:AttributeStatement>{second_statement}</saml:Assertion></samlp:Response>"##,
        subject = escape(subject),
    )
}

fn sign(
    base_dir: &Path,
    unsigned: &str,
) -> String {
    let unsigned_path = base_dir.join("idp-unsigned.xml");
    let signed_path = base_dir.join("idp-signed.xml");
    std::fs::write(&unsigned_path, unsigned).expect("write the unsigned response");
    let output = Command::new("xmlsec1")
        .args([
            "--sign",
            "--lax-key-search",
            "--privkey-pem",
            &format!(
                "{},{}",
                base_dir
                    .join("idp.key")
                    .display(),
                base_dir
                    .join("idp.crt")
                    .display()
            ),
            "--id-attr:ID",
            "urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
            "--output",
        ])
        .arg(&signed_path)
        .arg(&unsigned_path)
        .output()
        .expect("run xmlsec1 to sign the assertion");
    assert!(output.status.success(), "xmlsec1 could not sign: {}", String::from_utf8_lossy(&output.stderr));
    std::fs::read_to_string(&signed_path).expect("read the signed response")
}

/// Completes a SAML sign-in of `subject` whose assertion carries `roles` as its role claim, none
/// when empty, and returns the gateway's answer to the assertion.
pub async fn sign_in(
    base_dir: &Path,
    port: u16,
    subject: &str,
    roles: &[String],
    layout: AssertionLayout,
) -> AcsAnswer {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("an HTTP client");
    let request_id = start_sign_in(&client, port).await;
    let signed = sign(base_dir, &template(port, &request_id, subject, roles, layout));
    let form =
        format!("SAMLResponse={}", urlencoding::encode(&base64::engine::general_purpose::STANDARD.encode(signed)));
    let response = client
        .post(format!("http://127.0.0.1:{port}/api/saml/acs"))
        .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form)
        .send()
        .await
        .expect("POST the signed SAML response");
    AcsAnswer {
        status: response.status().as_u16(),
        set_cookies: response
            .headers()
            .get_all(reqwest::header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(str::to_string)
            .collect(),
        body: response
            .text()
            .await
            .unwrap_or_default(),
    }
}
