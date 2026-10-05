use crate::config::loaders::{environment::optional_env, load};

const LOG_TARGET: &str = "credential_identity";
const PEPPER_HASH_ENV_NAME: &str = "AG_IDENTITY_HASH_PEPPER";
// export AG_IDENTITY_HASH_PEPPER=<64 hex characters / 32 random bytes>
pub struct PepperCacheConfig {
    pub pepper_hash: Vec<u8>,
}

fn decode_pepper_hex(
    source: &str,
    hex_str: &str,
) -> Option<Vec<u8>> {
    match hex::decode(hex_str.trim()) {
        Ok(bytes) if bytes.len() >= 32 => {
            tracing::info!(
                target: LOG_TARGET,
                source,
                bytes = bytes.len(),
                "Using configured credential identity pepper"
            );
            Some(bytes)
        }
        Ok(bytes) => {
            tracing::warn!(
                target: LOG_TARGET,
                source,
                bytes = bytes.len(),
                "Configured credential identity pepper decoded to <32 bytes; ignoring"
            );
            None
        }
        Err(e) => {
            tracing::warn!(
                target: LOG_TARGET,
                source,
                error = %e,
                "Configured credential identity pepper is not valid hex; ignoring"
            );
            None
        }
    }
}

impl PepperCacheConfig {
    pub async fn load() -> Self {
        // it can be just a hex string or a path to secret manager
        let maybe_env_value = optional_env(PEPPER_HASH_ENV_NAME);

        if let Some(env_value) = maybe_env_value.as_ref() {
            return PepperCacheConfig::from_env(env_value)
                .await
                .unwrap_or_else(|err| {
                    tracing::error!(
                        target: LOG_TARGET,
                        "AG_IDENTITY_HASH_PEPPER is presented, but failed to turn value in pepper hash. Error: {err:?}"
                    );
                    Self::new_ephemeral()
                });
        } else {
            tracing::warn!(
                target: LOG_TARGET,
                "AG_IDENTITY_HASH_PEPPER is not set."
            );
            Self::new_ephemeral()
        }
    }

    async fn from_env(env_value: &str) -> Result<Self, String> {
        let pepper_hash_string = load(env_value).await?;
        let pepper_hash = decode_pepper_hex("env", pepper_hash_string.trim())
            .ok_or_else(|| "Failed to decode AG_IDENTITY_HASH_PEPPER as hex".to_string())?;
        tracing::info!(
            target: LOG_TARGET,
            "Using AG_IDENTITY_HASH_PEPPER from env"
        );
        Ok(Self { pepper_hash })
    }

    fn new_ephemeral() -> Self {
        let mut out = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut out);
        tracing::warn!(
          target: LOG_TARGET,
          "Ephemeral credential-identity pepper generated. DIDs derived from FromMtls / FromApiKey / Static \
           will NOT persist across gateway restarts. Set AG_IDENTITY_HASH_PEPPER (>=32 bytes hex) for stable DIDs."
        );
        Self { pepper_hash: out }
    }
}
