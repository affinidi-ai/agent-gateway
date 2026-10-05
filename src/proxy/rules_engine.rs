use anyhow::{Context, Result};
use jsonschema::Validator;
use regex::Regex;
use serde_json::Value as JsonValue;
use tracing::debug;

use crate::config::{ExtensionRules, ValidationRule};

/// Compiled rules engine for efficient validation
pub struct RulesEngine {
    /// Compiled JSON Schema validator (if provided)
    schema_validator: Option<Validator>,
    /// Custom validation rules
    rules: Vec<ValidationRule>,
}

impl RulesEngine {
    /// Create a new rules engine from extension rules configuration
    pub fn new(extension_rules: &ExtensionRules) -> Result<Self> {
        let schema_validator = if let Some(ref schema) = extension_rules.json_schema {
            let compiled = Validator::options()
                .build(schema)
                .context("Failed to compile JSON schema")?;
            Some(compiled)
        } else {
            None
        };

        Ok(Self {
            schema_validator,
            rules: extension_rules.rules.clone(),
        })
    }

    /// Validate a JSON payload against the rules
    /// Returns Ok(()) if validation passes, or Err with details if it fails
    pub fn validate(
        &self,
        payload: &JsonValue,
        channel_name: &str,
    ) -> Result<()> {
        // First validate custom rules (which provide detailed error messages)
        for rule in &self.rules {
            self.validate_rule(rule, payload, channel_name)?;
        }

        // Then validate against JSON Schema if provided (for structural validation)
        if let Some(ref validator) = self.schema_validator {
            if !validator.is_valid(payload) {
                // Try to provide more specific error information
                let payload_str = serde_json::to_string_pretty(payload).unwrap_or_else(|_| "invalid JSON".to_string());
                anyhow::bail!(
                    "JSON Schema structural validation failed. This usually indicates missing required fields, incorrect data types, or constraint violations. Payload: {}",
                    payload_str
                );
            }
            debug!(channel = channel_name, "JSON Schema validation passed");
        }

        Ok(())
    }

    /// Validate a single rule
    fn validate_rule(
        &self,
        rule: &ValidationRule,
        payload: &JsonValue,
        channel_name: &str,
    ) -> Result<()> {
        match rule {
            ValidationRule::Equals { path, value } => match get_field_by_path(payload, path) {
                Ok(field_value) => {
                    if field_value != value {
                        anyhow::bail!(
                            "Property '{}' with validation 'equals {}' was provided value '{}' which does not match the required value",
                            path,
                            serde_json::to_string(value).unwrap_or_else(|_| format!("{:?}", value)),
                            serde_json::to_string(field_value).unwrap_or_else(|_| format!("{:?}", field_value))
                        );
                    }
                    debug!(channel = channel_name, path = path, "Equals rule passed");
                    Ok(())
                }
                Err(e) => {
                    anyhow::bail!(
                        "Property '{}' with validation 'equals {}' is required but the field was not found in the extension payload: {}",
                        path,
                        serde_json::to_string(value).unwrap_or_else(|_| format!("{:?}", value)),
                        e
                    );
                }
            },
            ValidationRule::NotEquals { path, value } => match get_field_by_path(payload, path) {
                Ok(field_value) => {
                    if field_value == value {
                        anyhow::bail!(
                            "Property '{}' with validation 'not-equals {}' was provided value '{}' which matches the forbidden value",
                            path,
                            serde_json::to_string(value).unwrap_or_else(|_| format!("{:?}", value)),
                            serde_json::to_string(field_value).unwrap_or_else(|_| format!("{:?}", field_value))
                        );
                    }
                    debug!(channel = channel_name, path = path, "NotEquals rule passed");
                    Ok(())
                }
                Err(e) => {
                    anyhow::bail!(
                        "Property '{}' with validation 'not-equals {}' is required but the field was not found in the extension payload: {}",
                        path,
                        serde_json::to_string(value).unwrap_or_else(|_| format!("{:?}", value)),
                        e
                    );
                }
            },
            ValidationRule::Regex { path, pattern } => match get_field_by_path(payload, path) {
                Ok(field_value) => {
                    let string_value = field_value
                        .as_str()
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "Property '{}' with validation 'regex {}' expected a string but got: {:?}",
                                path,
                                pattern,
                                field_value
                            )
                        })?;

                    let regex = Regex::new(pattern).with_context(|| format!("Invalid regex pattern: {}", pattern))?;

                    if !regex.is_match(string_value) {
                        anyhow::bail!(
                            "Property '{}' with validation 'regex {}' was provided value '{}' which does not match the required pattern",
                            path,
                            pattern,
                            string_value
                        );
                    }
                    debug!(channel = channel_name, path = path, "Regex rule passed");
                    Ok(())
                }
                Err(e) => {
                    anyhow::bail!(
                        "Property '{}' with validation 'regex {}' is required but the field was not found in the extension payload: {}",
                        path,
                        pattern,
                        e
                    );
                }
            },
            ValidationRule::Exists { path } => match get_field_by_path(payload, path) {
                Ok(_) => {
                    debug!(channel = channel_name, path = path, "Exists rule passed");
                    Ok(())
                }
                Err(e) => {
                    anyhow::bail!(
                        "Property '{}' with validation 'required' is missing from extension payload: {}",
                        path,
                        e
                    );
                }
            },
            ValidationRule::Range { path, min, max } => match get_field_by_path(payload, path) {
                Ok(field_value) => {
                    let number_value = field_value
                        .as_f64()
                        .ok_or_else(|| {
                            let range_desc = match (min, max) {
                                (Some(min_val), Some(max_val)) => format!("{}-{}", min_val, max_val),
                                (Some(min_val), None) => format!(">= {}", min_val),
                                (None, Some(max_val)) => format!("><= {}", max_val),
                                (None, None) => "numeric".to_string(),
                            };
                            anyhow::anyhow!(
                                "Property '{}' with validation 'range {}' expected a number but got: {:?}",
                                path,
                                range_desc,
                                field_value
                            )
                        })?;

                    if let Some(min_val) = min
                        && number_value < *min_val
                    {
                        let range_desc = match max {
                            Some(max_val) => {
                                format!("{}-{}", min_val, max_val)
                            }
                            None => format!(">= {}", min_val),
                        };
                        anyhow::bail!(
                            "Property '{}' with validation 'range {}' was provided value '{}' which is less than the minimum allowed value",
                            path,
                            range_desc,
                            number_value
                        );
                    }

                    if let Some(max_val) = max
                        && number_value > *max_val
                    {
                        let range_desc = match min {
                            Some(min_val) => {
                                format!("{}-{}", min_val, max_val)
                            }
                            None => format!("<= {}", max_val),
                        };
                        anyhow::bail!(
                            "Property '{}' with validation 'range {}' was provided value '{}' which is greater than the maximum allowed value",
                            path,
                            range_desc,
                            number_value
                        );
                    }

                    Ok(())
                }
                Err(e) => {
                    let range_desc = match (min, max) {
                        (Some(min_val), Some(max_val)) => {
                            format!("{}-{}", min_val, max_val)
                        }
                        (Some(min_val), None) => format!(">= {}", min_val),
                        (None, Some(max_val)) => format!("<= {}", max_val),
                        (None, None) => "numeric".to_string(),
                    };
                    anyhow::bail!(
                        "Property '{}' with validation 'range {}' is required but the field was not found in the extension payload: {}",
                        path,
                        range_desc,
                        e
                    );
                }
            },
            ValidationRule::OneOf { path, values } => match get_field_by_path(payload, path) {
                Ok(field_value) => {
                    if !values.contains(field_value) {
                        let allowed_values = values
                            .iter()
                            .map(|v| serde_json::to_string(v).unwrap_or_else(|_| format!("{:?}", v)))
                            .collect::<Vec<_>>()
                            .join(", ");
                        anyhow::bail!(
                            "Property '{}' with validation 'one-of [{}]' was provided value '{}' which is not in the allowed values",
                            path,
                            allowed_values,
                            serde_json::to_string(field_value).unwrap_or_else(|_| format!("{:?}", field_value))
                        );
                    }
                    debug!(channel = channel_name, path = path, "OneOf rule passed");
                    Ok(())
                }
                Err(e) => {
                    let allowed_values = values
                        .iter()
                        .map(|v| serde_json::to_string(v).unwrap_or_else(|_| format!("{:?}", v)))
                        .collect::<Vec<_>>()
                        .join(", ");
                    anyhow::bail!(
                        "Property '{}' with validation 'one-of [{}]' is required but the field was not found in the extension payload: {}",
                        path,
                        allowed_values,
                        e
                    );
                }
            },
            ValidationRule::ArrayAll { path, element_type, values } => {
                match get_field_by_path(payload, path) {
                    Ok(field_value) => {
                        let array = field_value
                            .as_array()
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "Property '{}' with validation 'array-all {}' expected an array but got: {:?}",
                                    path,
                                    element_type,
                                    field_value
                                )
                            })?;

                        for (idx, element) in array.iter().enumerate() {
                            // Check element type
                            let type_matches = match element_type.as_str() {
                                "string" => element.is_string(),
                                "number" => element.is_number(),
                                "boolean" => element.is_boolean(),
                                "object" => element.is_object(),
                                "array" => element.is_array(),
                                _ => false,
                            };

                            if !type_matches {
                                let actual_array_str =
                                    serde_json::to_string(array).unwrap_or_else(|_| format!("{:?}", array));
                                anyhow::bail!(
                                    "Property '{}' with validation 'array-all {}' has element at index {} with wrong type: expected {}, got {:?}. Actual array received: {}",
                                    path,
                                    element_type,
                                    idx,
                                    element_type,
                                    element,
                                    actual_array_str
                                );
                            }

                            // Check specific values if provided
                            if let Some(required_values) = values
                                && !required_values.contains(element)
                            {
                                let actual_array_str =
                                    serde_json::to_string(array).unwrap_or_else(|_| format!("{:?}", array));
                                let allowed_values = required_values
                                    .iter()
                                    .map(|v| serde_json::to_string(v).unwrap_or_else(|_| format!("{:?}", v)))
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                anyhow::bail!(
                                    "Property '{}' with validation 'array-all {} [{}]' has element at index {} with value '{}' which is not in the allowed values. Actual array received: {}",
                                    path,
                                    element_type,
                                    allowed_values,
                                    idx,
                                    serde_json::to_string(element).unwrap_or_else(|_| format!("{:?}", element)),
                                    actual_array_str
                                );
                            }
                        }

                        debug!(channel = channel_name, path = path, "ArrayAll rule passed");
                        Ok(())
                    }
                    Err(e) => {
                        anyhow::bail!(
                            "Property '{}' with validation 'array-all {}' is required but the field was not found in the extension payload: {}",
                            path,
                            element_type,
                            e
                        );
                    }
                }
            }
            ValidationRule::ArrayAny { path, element_type, values } => {
                match get_field_by_path(payload, path) {
                    Ok(field_value) => {
                        let array = field_value
                            .as_array()
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "Property '{}' with validation 'array-any {}' expected an array but got: {:?}",
                                    path,
                                    element_type,
                                    field_value
                                )
                            })?;

                        let mut found_match = false;

                        for element in array.iter() {
                            // Check element type
                            let type_matches = match element_type.as_str() {
                                "string" => element.is_string(),
                                "number" => element.is_number(),
                                "boolean" => element.is_boolean(),
                                "object" => element.is_object(),
                                "array" => element.is_array(),
                                _ => false,
                            };

                            if type_matches {
                                if let Some(required_values) = values {
                                    if required_values.contains(element) {
                                        found_match = true;
                                        break;
                                    }
                                } else {
                                    found_match = true;
                                    break;
                                }
                            }
                        }

                        if !found_match {
                            let actual_array_str =
                                serde_json::to_string(array).unwrap_or_else(|_| format!("{:?}", array));

                            if let Some(required_values) = values {
                                let allowed_values = required_values
                                    .iter()
                                    .map(|v| serde_json::to_string(v).unwrap_or_else(|_| format!("{:?}", v)))
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                anyhow::bail!(
                                    "Property '{}' with validation 'array-any {} [{}]' has no elements matching the required type and values. Actual array received: {}",
                                    path,
                                    element_type,
                                    allowed_values,
                                    actual_array_str
                                );
                            } else {
                                anyhow::bail!(
                                    "Property '{}' with validation 'array-any {}' has no elements matching the required type. Actual array received: {}",
                                    path,
                                    element_type,
                                    actual_array_str
                                );
                            }
                        }

                        debug!(channel = channel_name, path = path, "ArrayAny rule passed");
                        Ok(())
                    }
                    Err(e) => {
                        anyhow::bail!(
                            "Property '{}' with validation 'array-any {}' is required but the field was not found in the extension payload: {}",
                            path,
                            element_type,
                            e
                        );
                    }
                }
            }
            ValidationRule::ArrayLength { path, min, max } => match get_field_by_path(payload, path) {
                Ok(field_value) => {
                    let array = field_value
                        .as_array()
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "Property '{}' with validation 'array-length' expected an array but got: {:?}",
                                path,
                                field_value
                            )
                        })?;

                    let array_length = array.len();

                    if let Some(min_val) = min
                        && array_length < *min_val
                    {
                        let actual_array_str = serde_json::to_string(array).unwrap_or_else(|_| format!("{:?}", array));
                        let range_desc = match max {
                            Some(max_val) => {
                                format!("{}-{}", min_val, max_val)
                            }
                            None => format!(">= {}", min_val),
                        };
                        anyhow::bail!(
                            "Property '{}' with validation 'array-length {}' has {} elements which is less than the minimum allowed length. Actual array received: {}",
                            path,
                            range_desc,
                            array_length,
                            actual_array_str
                        );
                    }

                    if let Some(max_val) = max
                        && array_length > *max_val
                    {
                        let actual_array_str = serde_json::to_string(array).unwrap_or_else(|_| format!("{:?}", array));
                        let range_desc = match min {
                            Some(min_val) => {
                                format!("{}-{}", min_val, max_val)
                            }
                            None => format!("<= {}", max_val),
                        };
                        anyhow::bail!(
                            "Property '{}' with validation 'array-length {}' has {} elements which is greater than the maximum allowed length. Actual array received: {}",
                            path,
                            range_desc,
                            array_length,
                            actual_array_str
                        );
                    }

                    debug!(channel = channel_name, path = path, "ArrayLength rule passed");
                    Ok(())
                }
                Err(e) => {
                    let range_desc = match (min, max) {
                        (Some(min_val), Some(max_val)) => {
                            format!("{}-{}", min_val, max_val)
                        }
                        (Some(min_val), None) => format!(">= {}", min_val),
                        (None, Some(max_val)) => format!("<= {}", max_val),
                        (None, None) => "any length".to_string(),
                    };
                    anyhow::bail!(
                        "Property '{}' with validation 'array-length {}' is required but the field was not found in the extension payload: {}",
                        path,
                        range_desc,
                        e
                    );
                }
            },
        }
    }
}

/// Get a field from JSON using dot notation path
/// Example: "agentIdentity.provisioningInfo.cloudProvider"
fn get_field_by_path<'a>(
    payload: &'a JsonValue,
    path: &str,
) -> Result<&'a JsonValue> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = payload;

    for part in parts {
        current = current
            .get(part)
            .ok_or_else(|| anyhow::anyhow!("Field '{}' not found in path '{}'", part, path))?;
    }

    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_equals_rule() {
        let rules = ExtensionRules {
            json_schema: None,
            rules: vec![ValidationRule::Equals {
                path: "cloudProvider".to_string(),
                value: json!("local"),
            }],
            filter_rules: vec![],
            default_action: None,
        };

        let engine = RulesEngine::new(&rules).unwrap();
        let payload = json!({ "cloudProvider": "local" });

        assert!(
            engine
                .validate(&payload, "test")
                .is_ok()
        );

        let bad_payload = json!({ "cloudProvider": "aws" });
        assert!(
            engine
                .validate(&bad_payload, "test")
                .is_err()
        );
    }

    #[test]
    fn test_nested_path() {
        let payload = json!({
            "agentIdentity": {
                "provisioningInfo": {
                    "cloudProvider": "local"
                }
            }
        });

        let result = get_field_by_path(&payload, "agentIdentity.provisioningInfo.cloudProvider");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), &json!("local"));
    }

    #[test]
    fn test_oneof_rule() {
        let rules = ExtensionRules {
            json_schema: None,
            rules: vec![ValidationRule::OneOf {
                path: "environment".to_string(),
                values: vec![json!("dev"), json!("staging"), json!("prod")],
            }],
            filter_rules: vec![],
            default_action: None,
        };

        let engine = RulesEngine::new(&rules).unwrap();

        assert!(
            engine
                .validate(&json!({ "environment": "dev" }), "test")
                .is_ok()
        );
        assert!(
            engine
                .validate(&json!({ "environment": "prod" }), "test")
                .is_ok()
        );
        assert!(
            engine
                .validate(&json!({ "environment": "test" }), "test")
                .is_err()
        );
    }
}
