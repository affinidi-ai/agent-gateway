//! The template placeholder syntax: `${NAME}`, or `${NAME:Label}` where the label is ignored,
//! unless `integration.variable_pattern` in `gateway.json` sets another.

use regex::Regex;
use std::sync::OnceLock;

const DEFAULT_VARIABLE_PATTERN: &str = r"\$\{([^:}]+)(?::[^}]+)?\}";

/// The placeholder syntax, fixed at startup from `integration.variable_pattern`.
pub(crate) struct VariablePatterns {
    pub regex: Regex,
}

impl VariablePatterns {
    fn new(pattern: &str) -> Result<Self, regex::Error> {
        Ok(Self { regex: Regex::new(pattern)? })
    }

    fn defaults() -> Self {
        Self::new(DEFAULT_VARIABLE_PATTERN).expect("default variable pattern compiles")
    }
}

static PATTERNS: OnceLock<VariablePatterns> = OnceLock::new();

/// The configured patterns, or the defaults if startup never set them.
pub(crate) fn patterns() -> &'static VariablePatterns {
    PATTERNS.get_or_init(VariablePatterns::defaults)
}

/// Fixes the placeholder syntax from config. Must run once, before any template is rendered
/// or validated; a second call, or a call after a read, is a startup bug.
pub fn set_variable_patterns(variable_pattern: String) -> anyhow::Result<()> {
    let patterns = VariablePatterns::new(&variable_pattern)
        .map_err(|e| anyhow::anyhow!("integration.variable_pattern is not a valid regex: {e}"))?;
    PATTERNS
        .set(patterns)
        .map_err(|_| anyhow::anyhow!("variable patterns were read or set before startup configured them"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // `set_variable_patterns` fixes process-wide state, so these tests only call it in ways that
    // fail before anything is stored: an invalid pattern, or the default pattern after a read.
    #[test]
    fn set_variable_patterns_rejects_an_invalid_regex() {
        let error = set_variable_patterns("([".to_string()).expect_err("invalid pattern");

        assert!(
            error
                .to_string()
                .contains("integration.variable_pattern"),
            "{error}"
        );
    }

    #[test]
    fn set_variable_patterns_fails_after_patterns_were_read() {
        assert!(
            patterns()
                .regex
                .is_match("${GATEWAY_NAME:Gateway}")
        );

        let error =
            set_variable_patterns(DEFAULT_VARIABLE_PATTERN.to_string()).expect_err("patterns were already read");

        assert!(
            error
                .to_string()
                .contains("before startup configured them"),
            "{error}"
        );
    }
}
