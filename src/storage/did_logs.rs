use crate::identity::didwebvh::LogEntry;
use anyhow::Result;

#[async_trait::async_trait]
pub trait DidLogStorage: Send + Sync {
    async fn append(
        &self,
        did: &str,
        entry: &LogEntry,
    ) -> Result<()>;

    /// Append a raw JSON line to the log, preserving the exact bytes as written.
    /// Implementations override this to write the verbatim string without re-serialization,
    /// which is required to preserve cryptographic signatures.
    /// The default falls back to a typed round-trip (may break signatures).
    async fn append_raw(
        &self,
        did: &str,
        raw_json: &str,
    ) -> Result<()> {
        let entry: LogEntry = serde_json::from_str(raw_json)?;
        self.append(did, &entry).await
    }

    async fn load_all(
        &self,
        did: &str,
    ) -> Result<Vec<LogEntry>>;

    /// Load all log entries as raw JSON strings, preserving exact bytes.
    /// Required for library validation where re-serialization would break signatures.
    async fn load_all_raw(
        &self,
        did: &str,
    ) -> Result<Vec<String>> {
        let entries = self.load_all(did).await?;
        entries
            .iter()
            .map(|e| serde_json::to_string(e).map_err(Into::into))
            .collect()
    }
}
