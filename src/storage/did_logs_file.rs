use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::fs::{OpenOptions, create_dir_all};
use tokio::io::AsyncBufReadExt;
use tokio::io::{AsyncWriteExt, BufReader};
use urlencoding::encode;

use crate::identity::didwebvh::LogEntry;
use crate::storage::DidLogStorage;

/// Filesystem-backed DID log storage (JSON Lines)
pub struct FileDidLogStorage {
    base_dir: PathBuf,
}

impl FileDidLogStorage {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Self {
        Self {
            base_dir: base_dir
                .as_ref()
                .to_path_buf(),
        }
    }

    fn path_for(
        &self,
        did: &str,
    ) -> PathBuf {
        let encoded = encode(did);
        self.base_dir
            .join(format!("{}.jsonl", encoded))
    }
}

#[async_trait::async_trait]
impl DidLogStorage for FileDidLogStorage {
    async fn append(
        &self,
        did: &str,
        entry: &LogEntry,
    ) -> Result<()> {
        let line = serde_json::to_string(entry)?;
        self.append_raw(did, &line)
            .await
    }

    async fn append_raw(
        &self,
        did: &str,
        raw_json: &str,
    ) -> Result<()> {
        let path = self.path_for(did);
        if let Some(parent) = path.parent() {
            create_dir_all(parent)
                .await
                .with_context(|| format!("create dir {:?}", parent))?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("open {:?} for append", path))?;

        file.write_all(raw_json.as_bytes())
            .await?;
        file.write_all(b"\n").await?;
        file.flush().await?;
        Ok(())
    }

    async fn load_all(
        &self,
        did: &str,
    ) -> Result<Vec<LogEntry>> {
        let lines = self.load_all_raw(did).await?;
        lines
            .iter()
            .map(|line| serde_json::from_str(line).map_err(Into::into))
            .collect()
    }

    async fn load_all_raw(
        &self,
        did: &str,
    ) -> Result<Vec<String>> {
        let path = self.path_for(did);
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .await
            .with_context(|| format!("open {:?} for read", path))?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();
        let mut raw_lines = Vec::new();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            raw_lines.push(line);
        }
        Ok(raw_lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::didwebvh::types::{DataIntegrityProof, LogParameters};
    use tempfile::tempdir;

    fn sample_entry(version: u64) -> LogEntry {
        let doc = affinidi_did_common::Document::new("did:webvh:example").unwrap();

        LogEntry {
            version_id: format!("{}-hash", version),
            version_time: format!("2026-01-0{}T00:00:00Z", version),
            parameters: LogParameters {
                method: "did:webvh:1.0".to_string(),
                scid: "z6Mkscid123".to_string(),
                update_keys: vec!["did:key:z6Mk#1".to_string()],
                next_key_hashes: None,
                portable: false,
                ttl: None,
                witness: None,
                watchers: None,
                deactivated: false,
            },
            state: doc,
            proof: vec![DataIntegrityProof {
                proof_type: "DataIntegrityProof".to_string(),
                cryptosuite: "eddsa-jcs-2022".to_string(),
                verification_method: "did:key:z6Mk#1".to_string(),
                proof_purpose: "assertionMethod".to_string(),
                proof_value: "proofvalue".to_string(),
            }],
        }
    }

    #[tokio::test]
    async fn append_creates_file_if_not_exists() {
        let dir = tempdir().unwrap();
        let storage = FileDidLogStorage::new(dir.path());
        let did = "did:webvh:example";

        storage
            .append(did, &sample_entry(1))
            .await
            .unwrap();

        let path = storage.path_for(did);
        assert!(path.exists(), "File should be created");
    }

    #[tokio::test]
    async fn append_creates_parent_directories() {
        let dir = tempdir().unwrap();
        let nested_path = dir
            .path()
            .join("nested")
            .join("directories");
        let storage = FileDidLogStorage::new(&nested_path);

        storage
            .append("did:webvh:test", &sample_entry(1))
            .await
            .unwrap();

        assert!(nested_path.exists(), "Parent directories should be created");
    }

    #[tokio::test]
    async fn append_and_load_single_entry() {
        let dir = tempdir().unwrap();
        let storage = FileDidLogStorage::new(dir.path());
        let did = "did:webvh:example";

        let entry = sample_entry(1);
        storage
            .append(did, &entry)
            .await
            .unwrap();

        let loaded = storage
            .load_all(did)
            .await
            .unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].version_id, entry.version_id);
        assert_eq!(loaded[0].parameters.scid, entry.parameters.scid);
    }

    #[tokio::test]
    async fn append_multiple_entries() {
        let dir = tempdir().unwrap();
        let storage = FileDidLogStorage::new(dir.path());
        let did = "did:webvh:example";

        storage
            .append(did, &sample_entry(1))
            .await
            .unwrap();
        storage
            .append(did, &sample_entry(2))
            .await
            .unwrap();
        storage
            .append(did, &sample_entry(3))
            .await
            .unwrap();

        let loaded = storage
            .load_all(did)
            .await
            .unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].version_id, "1-hash");
        assert_eq!(loaded[1].version_id, "2-hash");
        assert_eq!(loaded[2].version_id, "3-hash");
    }

    #[tokio::test]
    async fn load_all_returns_empty_for_nonexistent_did() {
        let dir = tempdir().unwrap();
        let storage = FileDidLogStorage::new(dir.path());

        let loaded = storage
            .load_all("did:webvh:nonexistent")
            .await
            .unwrap();
        assert!(loaded.is_empty());
    }

    #[tokio::test]
    async fn load_all_skips_empty_lines() {
        let dir = tempdir().unwrap();
        let storage = FileDidLogStorage::new(dir.path());
        let did = "did:webvh:example";

        // Append entries
        storage
            .append(did, &sample_entry(1))
            .await
            .unwrap();
        storage
            .append(did, &sample_entry(2))
            .await
            .unwrap();

        // Manually add empty line
        let path = storage.path_for(did);
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .await
            .unwrap();
        file.write_all(b"\n")
            .await
            .unwrap();
        file.flush().await.unwrap();

        // Should still load 2 entries
        let loaded = storage
            .load_all(did)
            .await
            .unwrap();
        assert_eq!(loaded.len(), 2);
    }

    #[tokio::test]
    async fn path_encoding_handles_special_characters() {
        let dir = tempdir().unwrap();
        let storage = FileDidLogStorage::new(dir.path());
        let did = "did:webvh:example.com/path";

        use crate::storage::DidLogStorage;
        storage
            .append(did, &sample_entry(1))
            .await
            .unwrap();

        let loaded = storage
            .load_all(did)
            .await
            .unwrap();
        assert_eq!(loaded.len(), 1);
    }

    #[tokio::test]
    async fn entries_preserve_order() {
        let dir = tempdir().unwrap();
        let storage = FileDidLogStorage::new(dir.path());
        let did = "did:webvh:example";

        use crate::storage::DidLogStorage;
        for i in 1..=10 {
            storage
                .append(did, &sample_entry(i))
                .await
                .unwrap();
        }

        let loaded = storage
            .load_all(did)
            .await
            .unwrap();
        assert_eq!(loaded.len(), 10);

        for (i, entry) in loaded.iter().enumerate() {
            assert_eq!(entry.version_id, format!("{}-hash", i + 1));
        }
    }

    #[tokio::test]
    async fn concurrent_appends_to_different_dids() {
        use crate::storage::DidLogStorage;

        let dir = tempdir().unwrap();
        let storage = std::sync::Arc::new(FileDidLogStorage::new(dir.path()));

        let tasks: Vec<_> = (1..=5)
            .map(|i| {
                let storage = storage.clone();
                tokio::spawn(async move {
                    let did = format!("did:webvh:example{}", i);
                    storage
                        .append(&did, &sample_entry(1))
                        .await
                })
            })
            .collect::<Vec<_>>();

        for task in tasks {
            task.await.unwrap().unwrap();
        }

        // Verify all DIDs have entries
        for i in 1..=5 {
            let did = format!("did:webvh:example{}", i);
            let loaded = storage
                .load_all(&did)
                .await
                .unwrap();
            assert_eq!(loaded.len(), 1);
        }
    }
}
