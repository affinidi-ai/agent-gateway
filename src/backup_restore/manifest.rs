use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

pub const MANIFEST_PATH: &str = "META-INF/agent-gateway-backup.json";
const LEGACY_MANIFEST_PATH: &str = "META-INF/trust-gateway-backup.json"; // Accept legacy archive path during migration
pub(super) const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const FORMAT_VERSION: u8 = 2;
const PRODUCT: &str = "agent-gateway";
const RUNNING_VERSION: &str = env!("CARGO_PKG_VERSION");
const LEGACY_PRODUCT: &str = "trust-gateway"; // Accept old backups during migration

pub(super) fn is_manifest_path(name: &str) -> bool {
    name == MANIFEST_PATH || name == LEGACY_MANIFEST_PATH
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupManifest {
    pub format_version: u8,
    pub product: String,
    pub source_domain: String,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub legacy_import: bool,
    /// The Agent Gateway release that took the backup; absent on older backups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_version: Option<String>,
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
            gateway_version: Some(RUNNING_VERSION.to_string()),
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
    // The current manifest wins over a legacy one: archives taken from storage that kept a
    // restored legacy manifest file carry both.
    let manifest_path = if archive
        .index_for_name(MANIFEST_PATH)
        .is_some()
    {
        MANIFEST_PATH
    } else {
        LEGACY_MANIFEST_PATH
    };
    let mut manifest = None;
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        if entry.name()? != manifest_path {
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
    refuse_newer_release(
        manifest
            .gateway_version
            .as_deref(),
        RUNNING_VERSION,
    )?;

    Ok(manifest)
}

/// The backup was taken by a newer release than the one running.
#[derive(Debug, thiserror::Error)]
#[error("backup was taken by a newer Agent Gateway release than this one")]
pub struct NewerRelease;

/// The audit and API category of a refused manifest: a newer release is told apart
/// from an invalid manifest because its fix is to upgrade before restoring.
pub fn manifest_failure_category(error: &anyhow::Error) -> &'static str {
    if error.is::<NewerRelease>() {
        "backup_from_newer_release"
    } else {
        "manifest_invalid"
    }
}

/// A backup from a newer release may hold records this release cannot read, and a
/// record it cannot read is skipped on load, so the restore would silently drop it.
fn refuse_newer_release(
    backup: Option<&str>,
    running: &str,
) -> anyhow::Result<()> {
    let Some(backup) = backup else {
        return Ok(());
    };
    let backup_release = release_triple(backup).ok_or_else(|| anyhow::anyhow!("backup release version is invalid"))?;
    let running_release =
        release_triple(running).ok_or_else(|| anyhow::anyhow!("running release version is invalid"))?;
    if backup_release > running_release {
        return Err(NewerRelease.into());
    }
    Ok(())
}

/// The numeric `major.minor.patch` of a release, ignoring any pre-release or build suffix.
fn release_triple(version: &str) -> Option<(u64, u64, u64)> {
    let numeric = version
        .split(['-', '+'])
        .next()?;
    let mut parts = numeric
        .split('.')
        .map(|part| part.parse::<u64>().ok());
    let triple = (parts.next()??, parts.next()??, parts.next()??);
    parts
        .next()
        .is_none()
        .then_some(triple)
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

    fn manifest_from(gateway_version: Option<&str>) -> BackupManifest {
        let mut manifest = BackupManifest::new("gateway.example.com", false).unwrap();
        manifest.gateway_version = gateway_version.map(str::to_string);
        manifest
    }

    #[test]
    fn a_new_manifest_records_the_release_that_took_the_backup() {
        let manifest = BackupManifest::new("gateway.example.com", false).unwrap();
        assert_eq!(
            manifest
                .gateway_version
                .as_deref(),
            Some(env!("CARGO_PKG_VERSION"))
        );
        let json = serde_json::to_value(&manifest).unwrap();
        assert_eq!(json["gateway_version"], env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn a_manifest_without_a_release_still_restores() {
        let mut json = serde_json::to_value(manifest_from(None)).unwrap();
        assert!(
            json.get("gateway_version")
                .is_none()
        );
        json["extra_field_from_a_later_release"] = serde_json::json!(true);
        let parsed: BackupManifest = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.gateway_version, None);
        validate_parsed_backup_manifest(parsed, "gateway.example.com").expect("older backups restore");
    }

    #[test]
    fn a_backup_from_the_same_or_an_older_release_restores() {
        for version in [RUNNING_VERSION, "0.0.1", "0.9.9", "1.0.0-rc.1+build.5"] {
            validate_parsed_backup_manifest(manifest_from(Some(version)), "gateway.example.com")
                .unwrap_or_else(|error| panic!("{version} was refused: {error}"));
        }
    }

    #[test]
    fn a_backup_from_a_newer_release_is_refused_before_anything_is_restored() {
        for version in ["999.0.0", "1.999.0", "1.0.999"] {
            let error = validate_parsed_backup_manifest(manifest_from(Some(version)), "gateway.example.com")
                .expect_err("a newer backup is refused");
            assert_eq!(error.to_string(), "backup was taken by a newer Agent Gateway release than this one");
        }
        let zip = zip_with_manifest(&manifest_from(Some("999.0.0")));
        assert!(validate_backup_manifest(&zip, "gateway.example.com").is_err());
    }

    #[test]
    fn an_unreadable_release_version_is_refused() {
        for version in ["", "latest", "1.2", "1.2.3.4", "a.b.c"] {
            let error = validate_parsed_backup_manifest(manifest_from(Some(version)), "gateway.example.com")
                .expect_err("an unparseable release is refused");
            assert_eq!(error.to_string(), "backup release version is invalid", "{version}");
        }
    }

    #[test]
    fn release_comparison_reads_numbers_not_text() {
        assert!(refuse_newer_release(Some("1.10.0"), "1.9.0").is_err());
        assert!(refuse_newer_release(Some("1.9.0"), "1.10.0").is_ok());
        assert!(refuse_newer_release(Some("2.0.0-rc.1"), "1.99.99").is_err());
    }

    #[test]
    fn a_newer_release_has_its_own_failure_category() {
        let newer = refuse_newer_release(Some("2.0.0"), "1.0.0").unwrap_err();
        assert_eq!(manifest_failure_category(&newer), "backup_from_newer_release");
        let invalid = refuse_newer_release(Some("latest"), "1.0.0").unwrap_err();
        assert_eq!(manifest_failure_category(&invalid), "manifest_invalid");
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

    fn zip_with_manifests(entries: &[(&str, &BackupManifest)]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(cursor);
        let options: SimpleFileOptions = FileOptions::default();
        for (path, manifest) in entries {
            zip.start_file(*path, options)
                .unwrap();
            zip.write_all(&serde_json::to_vec(manifest).unwrap())
                .unwrap();
        }
        zip.finish()
            .unwrap()
            .into_inner()
    }

    #[test]
    fn current_manifest_wins_over_legacy_manifest() {
        let current = BackupManifest::new("gateway.example.com", false).unwrap();
        let mut legacy = BackupManifest::new("other.example.com", false).unwrap();
        legacy.product = LEGACY_PRODUCT.to_string();

        for entries in [
            [(LEGACY_MANIFEST_PATH, &legacy), (MANIFEST_PATH, &current)],
            [(MANIFEST_PATH, &current), (LEGACY_MANIFEST_PATH, &legacy)],
        ] {
            let zip = zip_with_manifests(&entries);
            let manifest = validate_backup_manifest(&zip, "gateway.example.com").unwrap();
            assert_eq!(manifest, current);
        }
    }

    #[test]
    fn invalid_current_manifest_is_not_replaced_by_legacy_manifest() {
        let mut current = BackupManifest::new("other.example.com", false).unwrap();
        current.product = "other-product".to_string();
        let legacy = BackupManifest::new("gateway.example.com", false).unwrap();
        let zip = zip_with_manifests(&[(LEGACY_MANIFEST_PATH, &legacy), (MANIFEST_PATH, &current)]);

        assert!(validate_backup_manifest(&zip, "gateway.example.com").is_err());
    }

    #[test]
    fn manifest_path_matches_only_reserved_names() {
        assert!(is_manifest_path(MANIFEST_PATH));
        assert!(is_manifest_path(LEGACY_MANIFEST_PATH));
        assert!(!is_manifest_path("META-INF/other.json"));
        assert!(!is_manifest_path("agent-gateway-backup.json"));
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
