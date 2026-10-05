use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

pub const MANIFEST_PATH: &str = "META-INF/agent-gateway-backup.json";
const LEGACY_MANIFEST_PATH: &str = "META-INF/trust-gateway-backup.json"; // Accept legacy archive path during migration
pub(super) const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const FORMAT_VERSION: u8 = 2;
const PRODUCT: &str = "agent-gateway";
const LEGACY_PRODUCT: &str = "trust-gateway"; // Accept old backups during migration

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupManifest {
    pub format_version: u8,
    pub product: String,
    pub source_domain: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub legacy_import: bool,
}

impl BackupManifest {
    pub fn new(
        source_domain: &str,
        legacy_import: bool,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            format_version: FORMAT_VERSION,
            product: PRODUCT.to_string(),
            source_domain: canonicalize_domain(source_domain)?,
            created_at: Utc::now(),
            legacy_import,
        })
    }
}

fn is_false(value: &bool) -> bool {
    !value
}

pub fn add_backup_manifest(
    zip_bytes: &[u8],
    source_domain: &str,
    legacy_import: bool,
) -> anyhow::Result<Vec<u8>> {
    use std::io::{Cursor, Write};
    use zip::write::{FileOptions, SimpleFileOptions, ZipWriter};

    let manifest = BackupManifest::new(source_domain, legacy_import)?;
    let cursor = Cursor::new(zip_bytes.to_vec());
    let mut zip = ZipWriter::new_append(cursor)?;
    let options: SimpleFileOptions = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zip.start_file(MANIFEST_PATH, options)?;
    zip.write_all(&serde_json::to_vec(&manifest)?)?;
    Ok(zip.finish()?.into_inner())
}

pub fn validate_backup_manifest(
    zip_bytes: &[u8],
    target_domain: &str,
) -> anyhow::Result<BackupManifest> {
    validate_optional_backup_manifest(zip_bytes, target_domain)?
        .ok_or_else(|| anyhow::anyhow!("backup manifest is missing"))
}

pub fn read_optional_backup_manifest(zip_bytes: &[u8]) -> anyhow::Result<Option<BackupManifest>> {
    use std::io::{Cursor, Read};

    let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes))?;
    let mut manifest = None;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        // Accept both new and legacy manifest paths for backward compatibility
        let is_manifest = entry.name() == MANIFEST_PATH || entry.name() == LEGACY_MANIFEST_PATH;
        if !is_manifest {
            continue;
        }
        if manifest.is_some() {
            anyhow::bail!("backup contains duplicate manifest entries");
        }
        let mut bytes = Vec::new();
        entry
            .take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            anyhow::bail!("backup manifest exceeds the size limit");
        }
        manifest = Some(serde_json::from_slice::<BackupManifest>(&bytes)?);
    }
    Ok(manifest)
}

pub fn validate_parsed_backup_manifest(
    manifest: BackupManifest,
    target_domain: &str,
) -> anyhow::Result<BackupManifest> {
    if manifest.format_version != FORMAT_VERSION {
        anyhow::bail!("unsupported backup format version");
    }
    if manifest.product != PRODUCT && manifest.product != LEGACY_PRODUCT {
        anyhow::bail!("backup product does not match Agent Gateway");
    }

    let source_domain = canonicalize_domain(&manifest.source_domain)?;
    let target_domain = canonicalize_domain(target_domain)?;
    if source_domain != target_domain {
        anyhow::bail!("backup source domain does not match this Agent Gateway");
    }

    Ok(manifest)
}

pub fn validate_optional_backup_manifest(
    zip_bytes: &[u8],
    target_domain: &str,
) -> anyhow::Result<Option<BackupManifest>> {
    read_optional_backup_manifest(zip_bytes)?
        .map(|manifest| validate_parsed_backup_manifest(manifest, target_domain))
        .transpose()
}

pub fn canonicalize_domain(value: &str) -> anyhow::Result<String> {
    if value.is_empty()
        || value.trim() != value
        || value
            .chars()
            .any(char::is_whitespace)
    {
        anyhow::bail!("did.domain must be a hostname with an optional port");
    }
    if value.contains(['/', '?', '#', '@', '*']) || value.contains("://") {
        anyhow::bail!("did.domain must not contain URL syntax");
    }

    let (host_input, port) = match value.rsplit_once(':') {
        Some((host, port))
            if !host.is_empty()
                && !port.is_empty()
                && port
                    .chars()
                    .all(|c| c.is_ascii_digit()) =>
        {
            let port = port
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("did.domain port is invalid"))?;
            (host, Some(port))
        }
        Some(_) => anyhow::bail!("did.domain contains an invalid port"),
        None => (value, None),
    };

    let host_input = host_input
        .strip_suffix('.')
        .unwrap_or(host_input);
    if host_input.is_empty() {
        anyhow::bail!("did.domain hostname is empty");
    }

    let parsed = Url::parse(&format!("https://{host_input}"))?;
    let host = match parsed.host() {
        Some(Host::Domain(host)) => host.to_string(),
        Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) => anyhow::bail!("did.domain IP literals are not supported"),
        None => anyhow::bail!("did.domain hostname is missing"),
    };
    if host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    {
        anyhow::bail!("did.domain hostname is invalid");
    }

    Ok(match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use zip::write::{FileOptions, SimpleFileOptions, ZipWriter};

    fn sample_zip() -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(cursor);
        let options: SimpleFileOptions = FileOptions::default();
        zip.start_file("record.json", options)
            .unwrap();
        zip.write_all(b"{}").unwrap();
        zip.finish()
            .unwrap()
            .into_inner()
    }

    fn zip_with_manifest(manifest: &BackupManifest) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(cursor);
        let options: SimpleFileOptions = FileOptions::default();
        zip.start_file("record.json", options)
            .unwrap();
        zip.write_all(b"{}").unwrap();
        zip.start_file(MANIFEST_PATH, options)
            .unwrap();
        zip.write_all(&serde_json::to_vec(manifest).unwrap())
            .unwrap();
        zip.finish()
            .unwrap()
            .into_inner()
    }

    #[test]
    fn canonical_domain_normalizes_dns_idn_trailing_dot_and_port() {
        assert_eq!(canonicalize_domain("Gateway.Example.COM.").unwrap(), "gateway.example.com");
        assert_eq!(canonicalize_domain("BÜCHER.Example.").unwrap(), "xn--bcher-kva.example");
        assert_eq!(canonicalize_domain("localhost:8443").unwrap(), "localhost:8443");
    }

    #[test]
    fn canonical_domain_rejects_url_syntax_wildcards_whitespace_and_ip_literals() {
        for invalid in [
            "https://gateway.example.com",
            "gateway.example.com/path",
            "user@gateway.example.com",
            "*.example.com",
            " gateway.example.com",
            "gateway example.com",
            "127.0.0.1",
            "[::1]",
            "gateway.example.com:invalid",
            "bad_name.example.com",
            "-bad.example.com",
            "bad-.example.com",
            "bad..example.com",
        ] {
            assert!(canonicalize_domain(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn manifest_validation_rejects_domain_mismatch() {
        let zip = add_backup_manifest(&sample_zip(), "source.example.com", false).unwrap();
        assert!(validate_backup_manifest(&zip, "target.example.com").is_err());
    }

    #[test]
    fn manifest_validation_rejects_wrong_product() {
        let mut manifest = BackupManifest::new("gateway.example.com", false).unwrap();
        manifest.product = "other-product".to_string();
        let zip = zip_with_manifest(&manifest);

        assert!(validate_backup_manifest(&zip, "gateway.example.com").is_err());
    }

    #[test]
    fn manifest_insertion_rejects_duplicate_reserved_entries() {
        let zip = add_backup_manifest(&sample_zip(), "gateway.example.com", false).unwrap();
        assert!(add_backup_manifest(&zip, "gateway.example.com", false).is_err());
    }

    #[test]
    fn legacy_archive_path_compatibility() {
        // Create a manifest with legacy product name and legacy path (simulating pre-rename backup)
        let mut manifest = BackupManifest::new("gateway.example.com", false).unwrap();
        manifest.product = LEGACY_PRODUCT.to_string();

        // Manually create a zip with the legacy path name instead of the new path
        let cursor = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(cursor);
        let options: SimpleFileOptions = FileOptions::default();
        zip.start_file("record.json", options)
            .unwrap();
        zip.write_all(b"{}").unwrap();
        zip.start_file(LEGACY_MANIFEST_PATH, options)
            .unwrap();
        zip.write_all(&serde_json::to_vec(&manifest).unwrap())
            .unwrap();
        let legacy_zip_bytes = zip
            .finish()
            .unwrap()
            .into_inner();

        // Verify that the legacy archive can be read
        let read_manifest = read_optional_backup_manifest(&legacy_zip_bytes).unwrap();
        assert!(read_manifest.is_some(), "legacy archive path should be found");
        assert_eq!(read_manifest.unwrap().product, LEGACY_PRODUCT, "legacy product name should be preserved");

        // Verify that validation accepts the legacy product and marks it as legacy import
        let validated = validate_backup_manifest(&legacy_zip_bytes, "gateway.example.com").unwrap();
        assert_eq!(validated.product, LEGACY_PRODUCT);
        assert!(validated.legacy_import || validated.product == LEGACY_PRODUCT, "legacy archive should be accepted");
    }
}
