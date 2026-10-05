//! Boot-time preflight for encryption backend consistency.
//!
//! Switching `key_source` (e.g. `environment` → `aws_kms`) leaves previously
//! written field-encrypted values unreadable: a `version = 1` (local-MEK) value
//! cannot be read under `aws_kms`, and a `version = 2` (KMS) value cannot be read
//! under a local MEK. Rather than limp into partial unreadability, the gateway
//! scans persisted values at boot and refuses to start if any stored envelope
//! version is incompatible with the active backend.

use crate::encryption::EncryptedData;
use anyhow::{Result, anyhow};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tracing::debug;

/// The on-disk envelope version the active backend writes and reads.
///
/// `0` = development-only pass-through (`local`); `1` = local-MEK
/// (`environment` / `file`); `2` = AWS KMS per-value envelope.
pub fn active_envelope_version(key_source: crate::config::KeySourceConfig) -> u8 {
    match key_source {
        crate::config::KeySourceConfig::AwsKms => 2,
        crate::config::KeySourceConfig::Environment | crate::config::KeySourceConfig::File => 1,
        crate::config::KeySourceConfig::Local => 0,
    }
}

/// Scan `storage_root` for encrypted values whose envelope version is
/// incompatible with `active_version`, and fail closed (with a clear, file-named
/// error) if any are found.
///
/// Covers both field-level encryption (`ENC[...]` tokens inside readable JSON)
/// and whole-file encryption (`.json.enc` files, which store an `ENC[...]` string
/// for the whole record). Only readable UTF-8 files up to a sane size are scanned;
/// `ENC[<v>:...]` tokens with an unknown version are ignored (forward-compat), as
/// are legacy plaintext values.
pub fn check_envelope_versions(
    storage_root: &Path,
    active_version: u8,
) -> Result<()> {
    if !storage_root.exists() {
        debug!("encryption preflight: storage root {} does not exist yet, nothing to check", storage_root.display());
        return Ok(());
    }

    let mut offenders: Vec<(PathBuf, u8)> = Vec::new();
    scan_dir(storage_root, active_version, 0, &mut offenders)?;

    if let Some((path, found_version)) = offenders.first() {
        return Err(anyhow!(
            "encryption backend mismatch: {} contains a version-{} envelope but the active \
             key_source writes version-{} envelopes. The stored values were written under a \
             different key_source and cannot be decrypted now. Restore the original key_source \
             (or migrate the data) before starting. ({} file(s) affected.)",
            path.display(),
            found_version,
            active_version,
            offenders.len()
        ));
    }

    Ok(())
}

/// Maximum directory recursion depth for the preflight scan. Guards against a
/// symlink cycle in the storage tree turning boot into an infinite recursion.
const MAX_SCAN_DEPTH: usize = 64;

/// Skip files larger than this when scanning for envelope tokens. Encrypted
/// storage records are small; a huge file is not one and need not be read into
/// memory in full at boot.
const MAX_SCAN_FILE_BYTES: u64 = 8 * 1024 * 1024;

fn scan_dir(
    dir: &Path,
    active_version: u8,
    depth: usize,
    offenders: &mut Vec<(PathBuf, u8)>,
) -> Result<()> {
    if depth >= MAX_SCAN_DEPTH {
        debug!("encryption preflight: max scan depth reached at {}, not descending further", dir.display());
        return Ok(());
    }
    let entries = std::fs::read_dir(dir).map_err(|e| anyhow!("failed to read {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| anyhow!("failed to read a directory entry in {}: {e}", dir.display()))?;
        let path = entry.path();
        // Use symlink-aware metadata so a symlinked directory is not descended into (avoids cycles);
        // symlinked regular files are still scanned as files.
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            scan_dir(&path, active_version, depth + 1, offenders)?;
        } else if meta.is_file()
            && meta.len() <= MAX_SCAN_FILE_BYTES
            && let Some(found) = mismatched_version_in_file(&path, active_version)
        {
            offenders.push((path, found));
        }
    }
    Ok(())
}

/// Return the first envelope version found in `path` that is a known version and
/// differs from `active_version`, or `None`.
fn mismatched_version_in_file(
    path: &Path,
    active_version: u8,
) -> Option<u8> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut rest = content.as_str();
    while let Some(idx) = rest.find("ENC[") {
        rest = &rest[idx..];
        if let Some(version) = parse_leading_envelope_version(rest)
            && is_known_version(version)
            && version != active_version
        {
            return Some(version);
        }
        // Advance past this "ENC[" to find the next token.
        rest = &rest[4..];
    }
    None
}

/// Parse the version from a string beginning with `ENC[<version>:...`.
fn parse_leading_envelope_version(s: &str) -> Option<u8> {
    let after = s.strip_prefix("ENC[")?;
    let colon = after.find(':')?;
    after[..colon]
        .parse::<u8>()
        .ok()
}

fn is_known_version(version: u8) -> bool {
    // Keep in sync with EncryptedData version routing (0 = local trace, 1 = local MEK, 2 = KMS).
    version <= 2
}

/// Sanity link so a future envelope-version addition is visible here.
#[allow(dead_code)]
fn _assert_encrypted_data_parses() {
    let _ = EncryptedData::from_str("ENC[1::]");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_root(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("ag-preflight-{}-{}", name, uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn passes_on_empty_or_missing_root() {
        let missing = tmp_root("missing").join("nope");
        assert!(check_envelope_versions(&missing, 2).is_ok());

        let empty = tmp_root("empty");
        assert!(check_envelope_versions(&empty, 2).is_ok());
        fs::remove_dir_all(&empty).ok();
    }

    #[test]
    fn passes_when_versions_match() {
        let root = tmp_root("match");
        fs::write(root.join("a.json"), r#"{"secret":"ENC[2:YWJj:ZGVm]"}"#).unwrap();
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub/b.json"), r#"{"k":"ENC[2:AAAA:BBBB]","plain":"hi"}"#).unwrap();
        assert!(check_envelope_versions(&root, 2).is_ok());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn fails_closed_on_cross_version_value() {
        let root = tmp_root("mismatch");
        // A version-1 (local MEK) value present while the active backend is KMS (2).
        fs::write(root.join("legacy.json"), r#"{"secret":"ENC[1:YWJj:ZGVm]"}"#).unwrap();
        let err = check_envelope_versions(&root, 2).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("legacy.json"), "error must name the offending file: {msg}");
        assert!(msg.contains("version-1"), "error must name the found version: {msg}");
        assert!(msg.contains("version-2"), "error must name the active version: {msg}");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn ignores_plaintext_and_unknown_versions() {
        let root = tmp_root("ignore");
        fs::write(root.join("plain.json"), r#"{"secret":"not-encrypted"}"#).unwrap();
        // Unknown/forward version 9 is ignored (forward-compat).
        fs::write(root.join("future.json"), r#"{"secret":"ENC[9:AAAA:BBBB]"}"#).unwrap();
        assert!(check_envelope_versions(&root, 2).is_ok());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn active_version_maps_key_source() {
        use crate::config::KeySourceConfig;
        assert_eq!(active_envelope_version(KeySourceConfig::AwsKms), 2);
        assert_eq!(active_envelope_version(KeySourceConfig::Environment), 1);
        assert_eq!(active_envelope_version(KeySourceConfig::File), 1);
        assert_eq!(active_envelope_version(KeySourceConfig::Local), 0);
    }

    #[test]
    fn fails_closed_on_local_trace_files_under_a_real_backend() {
        // Files written by the development-only `local` source hold plaintext and must not be
        // silently accepted once a real key source is configured.
        let root = tmp_root("localtrace");
        fs::write(root.join("dev.json.enc"), "ENC[0::eyJpZCI6ImEifQ==]").unwrap();
        let msg = check_envelope_versions(&root, 1)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("dev.json.enc"), "{msg}");
        assert!(msg.contains("version-0"), "{msg}");
        assert!(check_envelope_versions(&root, 0).is_ok());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn fails_closed_on_cross_version_whole_file() {
        // Whole-file encryption writes a `.json.enc` file whose content is the ENC[...] string for
        // the whole record. A cross-version whole-file blob must be caught the same as a field value.
        let root = tmp_root("wholefile");
        fs::write(root.join("record.json.enc"), "ENC[1:YWJj:ZGVm]").unwrap();
        let err = check_envelope_versions(&root, 2).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("record.json.enc"), "error must name the offending file: {msg}");
        assert!(msg.contains("version-1"), "error must name the found version: {msg}");
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn skips_oversized_files() {
        // A file above the scan size cap is skipped (not read into memory) — even if it happens to
        // contain a token. Storage records are small; this only affects pathological large files.
        let root = tmp_root("oversized");
        let mut big = String::from("ENC[1:AAAA:BBBB]\n");
        big.push_str(&"x".repeat((MAX_SCAN_FILE_BYTES as usize) + 1));
        fs::write(root.join("huge.json"), big).unwrap();
        assert!(check_envelope_versions(&root, 2).is_ok(), "oversized file must be skipped");
        fs::remove_dir_all(&root).ok();
    }
}
