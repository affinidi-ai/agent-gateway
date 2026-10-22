//! A one-time move of the live version's integrations (`2470747`) onto endpoints, event sets
//! and integrations. See "Upgrading from the previous version" in `docs/INTEGRATIONS.md`.

pub mod apply;
pub mod cleanup;
pub mod legacy;
pub mod plan;
pub mod received;
pub mod run;

/// Loads a `config.toml` holding `storage_paths` from `config_dir`, which is not the working
/// directory, the way the gateway loads its bootstrap configuration.
#[cfg(test)]
fn config_in(
    config_dir: &std::path::Path,
    storage_paths: &str,
) -> crate::config::BootstrapConfig {
    std::fs::create_dir_all(config_dir).expect("config dir");
    let path = config_dir.join("config.toml");
    std::fs::write(
        &path,
        format!("backup_encryption_key = \"unused\"\n\n[tls]\ncert_path = \"cert.pem\"\nkey_path = \"key.pem\"\n\n[storage_paths]\n{storage_paths}\n"),
    )
    .expect("config");
    crate::config::BootstrapConfig::from_file(&path).expect("loads")
}
