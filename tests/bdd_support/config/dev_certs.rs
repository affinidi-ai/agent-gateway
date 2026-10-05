use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tempfile::TempDir;

/// Directory holding the TLS pair the BDD gateway boots with.
///
/// Prefers the pair `make config-certs` writes to `envs/certs`, and otherwise self-signs one into a
/// temporary directory so a fresh clone can run the suite without a certificate setup step. The
/// `TempDir` is held in a process-wide `OnceLock` because dropping it deletes the files while the
/// gateway is still reading them.
pub fn dev_cert_dir() -> PathBuf {
    static GENERATED_CERTS: OnceLock<TempDir> = OnceLock::new();

    let existing = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("envs/certs");
    dev_cert_dir_or_generate(&existing, &GENERATED_CERTS)
}

fn dev_cert_dir_or_generate(
    existing: &Path,
    generated: &OnceLock<TempDir>,
) -> PathBuf {
    if dev_cert_pair_present(existing) {
        return existing.to_path_buf();
    }

    generated
        .get_or_init(|| {
            let dir = tempfile::Builder::new()
                .prefix("agent-gateway-bdd-certs-")
                .tempdir()
                .expect("create temporary BDD TLS directory");
            write_self_signed_cert_pair(dir.path());
            dir
        })
        .path()
        .to_path_buf()
}

fn dev_cert_pair_present(dir: &Path) -> bool {
    ["cert.pem", "key.pem"]
        .iter()
        .all(|name| std::fs::metadata(dir.join(name)).is_ok_and(|metadata| metadata.is_file() && metadata.len() > 0))
}

fn write_self_signed_cert_pair(dir: &Path) {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.subject_alt_names = vec![
        SanType::DnsName(
            "localhost"
                .try_into()
                .expect("localhost is a valid DNS SAN"),
        ),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    ];

    let key = KeyPair::generate().expect("generate BDD TLS key");
    let cert = params
        .self_signed(&key)
        .expect("self-sign BDD TLS certificate");

    std::fs::write(dir.join("cert.pem"), cert.pem()).expect("write BDD TLS certificate");
    std::fs::write(dir.join("key.pem"), key.serialize_pem()).expect("write BDD TLS key");
}

#[cfg(test)]
mod tests {
    #[test]
    fn missing_dev_cert_pair_uses_process_temporary_material() {
        let absent = tempfile::tempdir()
            .unwrap()
            .path()
            .join("missing");
        let generated = std::sync::OnceLock::new();

        let cert_dir = super::dev_cert_dir_or_generate(&absent, &generated);

        assert_ne!(cert_dir, absent);
        assert!(super::dev_cert_pair_present(&cert_dir));
    }

    #[test]
    fn existing_dev_cert_pair_is_preferred() {
        let existing = tempfile::tempdir().unwrap();
        std::fs::write(
            existing
                .path()
                .join("cert.pem"),
            "existing cert",
        )
        .unwrap();
        std::fs::write(
            existing
                .path()
                .join("key.pem"),
            "existing key",
        )
        .unwrap();
        let generated = std::sync::OnceLock::new();

        let cert_dir = super::dev_cert_dir_or_generate(existing.path(), &generated);

        assert_eq!(cert_dir, existing.path());
        assert!(generated.get().is_none());
    }
}
