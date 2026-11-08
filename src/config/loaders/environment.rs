use std::env;

pub fn load(env_name: &str) -> Result<String, String> {
    required_env(env_name)
}

pub fn required_env(env_name: &str) -> Result<String, String> {
    env::var(env_name).map_err(|_| format!("Required environment variable '{env_name}' is not set"))
}

pub fn optional_env(env_name: &str) -> Option<String> {
    env::var(env_name).ok()
}

#[allow(dead_code)]
pub fn env_or(
    env_name: &str,
    default: &str,
) -> String {
    optional_env(env_name).unwrap_or_else(|| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Set by `.cargo/config.toml` `[env]`.
    const PRESENT: &str = "AG_TEST_PRESENT_VAR";
    const MISSING: &str = "AG_TEST_NEVER_SET_VAR_3F9C";

    #[test]
    fn test_required_env_success() {
        assert_eq!(required_env(PRESENT).unwrap(), "value");
    }

    #[test]
    fn test_required_env_missing() {
        assert!(required_env(MISSING).is_err());
    }

    #[test]
    fn test_optional_env_present() {
        assert_eq!(optional_env(PRESENT), Some("value".to_string()));
    }

    #[test]
    fn test_optional_env_missing() {
        assert_eq!(optional_env(MISSING), None);
    }

    #[test]
    fn test_env_or_present() {
        assert_eq!(env_or(PRESENT, "default"), "value");
    }

    #[test]
    fn test_env_or_missing_uses_default() {
        assert_eq!(env_or(MISSING, "default"), "default");
    }
}
