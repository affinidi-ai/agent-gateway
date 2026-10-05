use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tempfile::{Builder, TempDir};

/// Drops a `TempDir` on normal scope exit. Preserves it when `BDD_KEEP_TEMP_DIRS`
/// is set or when dropped during panic, and prints the path for debugging.
pub struct TempDirGuard {
    temp_dir: Option<TempDir>,
    path: PathBuf,
}

impl TempDirGuard {
    pub fn new(
        temp_dir: TempDir,
        label: &str,
    ) -> Self {
        let path = temp_dir.path().to_path_buf();
        if std::env::var("BDD_KEEP_TEMP_DIRS").is_ok() {
            let kept_path = temp_dir.keep();
            eprintln!("[harness] {label} preserving temp dir at {} (BDD_KEEP_TEMP_DIRS set)", kept_path.display());
            Self { temp_dir: None, path }
        } else {
            Self { temp_dir: Some(temp_dir), path }
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }

        if let Some(temp_dir) = self.temp_dir.take() {
            let path = temp_dir.keep();
            eprintln!("[harness] preserving temp dir at {} because the BDD scenario is failing", path.display());
        }
    }
}

impl std::fmt::Debug for TempDirGuard {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match &self.temp_dir {
            Some(_) => f
                .debug_tuple("TempDirGuard")
                .field(&self.path)
                .finish(),
            None => f
                .debug_tuple("TempDirGuard")
                .field(&self.path)
                .finish(),
        }
    }
}

pub fn create_project_temp_dir(prefix: &str) -> Result<TempDir> {
    let tmp_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tmp");
    std::fs::create_dir_all(&tmp_root).with_context(|| format!("create tmp dir at {}", tmp_root.display()))?;
    Builder::new()
        .prefix(prefix)
        .tempdir_in(&tmp_root)
        .with_context(|| format!("create temp dir under {}", tmp_root.display()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn project_temp_dir_is_created_under_repo_tmp() {
        let temp_dir = super::create_project_temp_dir("bdd-support-temp-test-").expect("create project temp dir");
        let expected_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tmp");

        assert!(
            temp_dir
                .path()
                .starts_with(expected_root)
        );
    }
}
