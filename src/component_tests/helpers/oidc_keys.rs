//! RS256 and ES256 signing keys for tests, generated once per test process so no
//! private key is committed. Two generations of each kind exist so a test can
//! rotate once.

use std::sync::OnceLock;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Rsa,
    Ec,
}

struct Material {
    kind: KeyKind,
    private_pem: String,
    rsa_n: String,
    ec_x: String,
    ec_y: String,
}

#[derive(Clone)]
pub struct SigningFixture {
    pub kid: String,
    pub algorithm: Algorithm,
    material: &'static Material,
}

impl std::fmt::Debug for SigningFixture {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("SigningFixture")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl SigningFixture {
    pub const GENERATIONS: usize = 2;

    pub fn rs256(index: usize) -> Self {
        Self::build(&rsa_keys()[index], Algorithm::RS256, format!("rs256-{index}"))
    }

    pub fn es256(index: usize) -> Self {
        Self::build(&ec_keys()[index], Algorithm::ES256, format!("es256-{index}"))
    }

    pub fn with_kid(
        mut self,
        kid: &str,
    ) -> Self {
        self.kid = kid.to_string();
        self
    }

    fn build(
        material: &'static Material,
        algorithm: Algorithm,
        kid: String,
    ) -> Self {
        Self { kid, algorithm, material }
    }

    pub fn kind(&self) -> KeyKind {
        self.material.kind
    }

    pub fn private_pkcs8_pem(&self) -> &'static str {
        &self.material.private_pem
    }

    pub fn public_jwk(&self) -> Value {
        match self.material.kind {
            KeyKind::Rsa => json!({
                "kty": "RSA", "kid": self.kid, "use": "sig", "alg": "RS256",
                "n": &self.material.rsa_n, "e": "AQAB",
            }),
            KeyKind::Ec => json!({
                "kty": "EC", "kid": self.kid, "use": "sig", "alg": "ES256", "crv": "P-256",
                "x": &self.material.ec_x, "y": &self.material.ec_y,
            }),
        }
    }

    pub fn header(&self) -> Header {
        let mut header = Header::new(self.algorithm);
        header.kid = Some(self.kid.clone());
        header
    }

    pub fn sign(
        &self,
        claims: &Value,
    ) -> String {
        self.sign_with_header(self.header(), claims)
    }

    pub fn sign_with_header(
        &self,
        header: Header,
        claims: &Value,
    ) -> String {
        let key = match self.material.kind {
            KeyKind::Rsa => EncodingKey::from_rsa_pem(
                self.material
                    .private_pem
                    .as_bytes(),
            ),
            KeyKind::Ec => EncodingKey::from_ec_pem(
                self.material
                    .private_pem
                    .as_bytes(),
            ),
        }
        .expect("fixture key parses");
        jsonwebtoken::encode(&header, claims, &key).expect("fixture signing succeeds")
    }
}

pub fn jwks_document(fixtures: &[SigningFixture]) -> Value {
    json!({ "keys": fixtures.iter().map(SigningFixture::public_jwk).collect::<Vec<_>>() })
}

static RSA_KEYS: OnceLock<Vec<Material>> = OnceLock::new();
static EC_KEYS: OnceLock<Vec<Material>> = OnceLock::new();

fn rsa_keys() -> &'static [Material] {
    RSA_KEYS.get_or_init(|| {
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};
        use rsa::traits::PublicKeyParts;
        (0..SigningFixture::GENERATIONS)
            .map(|_| {
                let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("generate RSA key");
                Material {
                    kind: KeyKind::Rsa,
                    private_pem: key
                        .to_pkcs8_pem(LineEnding::LF)
                        .expect("encode RSA key")
                        .to_string(),
                    rsa_n: URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
                    ec_x: String::new(),
                    ec_y: String::new(),
                }
            })
            .collect()
    })
}

fn ec_keys() -> &'static [Material] {
    EC_KEYS.get_or_init(|| {
        use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
        let rng = ring::rand::SystemRandom::new();
        (0..SigningFixture::GENERATIONS)
            .map(|_| {
                let pkcs8 =
                    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("generate EC key");
                let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .expect("load EC key");
                let point = pair.public_key().as_ref();
                Material {
                    kind: KeyKind::Ec,
                    private_pem: pem_encode(pkcs8.as_ref()),
                    rsa_n: String::new(),
                    ec_x: URL_SAFE_NO_PAD.encode(&point[1..33]),
                    ec_y: URL_SAFE_NO_PAD.encode(&point[33..65]),
                }
            })
            .collect()
    })
}

fn pem_encode(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let body: Vec<&str> = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).expect("base64 is ascii"))
        .collect();
    format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", body.join("\n"))
}
