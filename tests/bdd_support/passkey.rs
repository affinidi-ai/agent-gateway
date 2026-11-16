//! A software passkey: answers WebAuthn registration and sign-in challenges as a platform
//! authenticator that verified its user does, with an ES256 key it keeps in memory.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// User present and user verified.
const FLAGS_SIGN_IN: u8 = 0x05;
/// User present, user verified and attested credential data included.
const FLAGS_REGISTRATION: u8 = 0x45;

pub struct SoftPasskey {
    key: SigningKey,
    credential_id: [u8; 32],
    rp_id: String,
    origin: String,
    sign_count: u32,
}

impl std::fmt::Debug for SoftPasskey {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("SoftPasskey")
            .field("rp_id", &self.rp_id)
            .field("origin", &self.origin)
            .finish()
    }
}

impl SoftPasskey {
    /// A new passkey for the relying party `rp_id`, used from pages served at `origin`.
    pub fn new(
        rp_id: &str,
        origin: &str,
    ) -> Self {
        let key = loop {
            if let Ok(key) = SigningKey::from_slice(&rand::random::<[u8; 32]>()) {
                break key;
            }
        };
        Self {
            key,
            credential_id: rand::random(),
            rp_id: rp_id.to_string(),
            origin: origin.to_string(),
            sign_count: 0,
        }
    }

    /// The base64url ID of this passkey's credential.
    pub fn credential_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.credential_id)
    }

    /// The credential that registers this passkey for `creation_options`, the relying party's
    /// `CredentialCreationOptions`.
    pub fn register(
        &self,
        creation_options: &Value,
    ) -> Value {
        let client_data = self.client_data("webauthn.create", creation_options);
        let mut authenticator_data = self.authenticator_data(FLAGS_REGISTRATION, 0);
        authenticator_data.extend([0; 16]);
        authenticator_data.extend((self.credential_id.len() as u16).to_be_bytes());
        authenticator_data.extend(self.credential_id);
        authenticator_data.extend(self.cose_public_key());

        let mut attestation = Vec::new();
        cbor_head(&mut attestation, 5, 3);
        cbor_text(&mut attestation, "fmt");
        cbor_text(&mut attestation, "none");
        cbor_text(&mut attestation, "attStmt");
        cbor_head(&mut attestation, 5, 0);
        cbor_text(&mut attestation, "authData");
        cbor_bytes(&mut attestation, &authenticator_data);

        json!({
            "id": URL_SAFE_NO_PAD.encode(self.credential_id),
            "rawId": URL_SAFE_NO_PAD.encode(self.credential_id),
            "type": "public-key",
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode(attestation),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data),
            },
            "extensions": {},
        })
    }

    /// The assertion this passkey signs for `request_options`, the relying party's
    /// `CredentialRequestOptions`.
    pub fn sign_in(
        &mut self,
        request_options: &Value,
    ) -> Value {
        self.sign_count += 1;
        let client_data = self.client_data("webauthn.get", request_options);
        let authenticator_data = self.authenticator_data(FLAGS_SIGN_IN, self.sign_count);
        let mut signed = authenticator_data.clone();
        signed.extend(Sha256::digest(&client_data));
        let signature: Signature = self.key.sign(&signed);

        json!({
            "id": URL_SAFE_NO_PAD.encode(self.credential_id),
            "rawId": URL_SAFE_NO_PAD.encode(self.credential_id),
            "type": "public-key",
            "response": {
                "authenticatorData": URL_SAFE_NO_PAD.encode(authenticator_data),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data),
                "signature": URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
                "userHandle": null,
            },
            "extensions": {},
        })
    }

    fn client_data(
        &self,
        ceremony: &str,
        options: &Value,
    ) -> Vec<u8> {
        let challenge = options["publicKey"]["challenge"]
            .as_str()
            .unwrap_or_else(|| panic!("the options carry no challenge: {options}"));
        json!({
            "type": ceremony,
            "challenge": challenge,
            "origin": self.origin,
            "crossOrigin": false,
        })
        .to_string()
        .into_bytes()
    }

    fn authenticator_data(
        &self,
        flags: u8,
        sign_count: u32,
    ) -> Vec<u8> {
        let mut data = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        data.push(flags);
        data.extend(sign_count.to_be_bytes());
        data
    }

    /// The public key as a COSE_Key: EC2, ES256, P-256, x and y.
    fn cose_public_key(&self) -> Vec<u8> {
        let point = self
            .key
            .verifying_key()
            .to_encoded_point(false);
        let mut key = Vec::new();
        cbor_head(&mut key, 5, 5);
        cbor_head(&mut key, 0, 1);
        cbor_head(&mut key, 0, 2);
        cbor_head(&mut key, 0, 3);
        cbor_head(&mut key, 1, 6);
        cbor_head(&mut key, 1, 0);
        cbor_head(&mut key, 0, 1);
        cbor_head(&mut key, 1, 1);
        cbor_bytes(
            &mut key,
            point
                .x()
                .expect("an uncompressed point"),
        );
        cbor_head(&mut key, 1, 2);
        cbor_bytes(
            &mut key,
            point
                .y()
                .expect("an uncompressed point"),
        );
        key
    }
}

fn cbor_head(
    out: &mut Vec<u8>,
    major: u8,
    value: usize,
) {
    let major = major << 5;
    match value {
        0..=23 => out.push(major | value as u8),
        24..=0xff => out.extend([major | 24, value as u8]),
        _ => {
            out.push(major | 25);
            out.extend((u16::try_from(value).expect("a CBOR length below 65536")).to_be_bytes());
        }
    }
}

fn cbor_text(
    out: &mut Vec<u8>,
    text: &str,
) {
    cbor_head(out, 3, text.len());
    out.extend(text.as_bytes());
}

fn cbor_bytes(
    out: &mut Vec<u8>,
    bytes: &[u8],
) {
    cbor_head(out, 2, bytes.len());
    out.extend(bytes);
}
