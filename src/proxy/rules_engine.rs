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
                anyhow::bail!(
                    "JSON Schema structural validation failed: {}",
                    crate::identity::identity_selector::format_schema_errors(validator, payload)
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
                            "Property '{}' with validation 'equals {}' was provided a value which does not match the required value",
                            path,
                            serde_json::to_string(value).unwrap_or_else(|_| format!("{:?}", value))
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
                            "Property '{}' with validation 'not-equals {}' was provided the forbidden value",
                            path,
                            serde_json::to_string(value).unwrap_or_else(|_| format!("{:?}", value))
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
                                "Property '{}' with validation 'regex {}' expected a string but got {}",
                                path,
                                pattern,
                                json_type(field_value)
                            )
                        })?;

                    let regex = Regex::new(pattern).with_context(|| format!("Invalid regex pattern: {}", pattern))?;

                    if !regex.is_match(string_value) {
                        anyhow::bail!(
                            "Property '{}' with validation 'regex {}' was provided a value which does not match the required pattern",
                            path,
                            pattern
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
                                "Property '{}' with validation 'range {}' expected a number but got {}",
                                path,
                                range_desc,
                                json_type(field_value)
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
                            "Property '{}' with validation 'range {}' was provided a value which is less than the minimum allowed value",
                            path,
                            range_desc
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
                            "Property '{}' with validation 'range {}' was provided a value which is greater than the maximum allowed value",
                            path,
                            range_desc
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
                            "Property '{}' with validation 'one-of [{}]' was provided a value which is not in the allowed values",
                            path,
                            allowed_values
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
                                    "Property '{}' with validation 'array-all {}' expected an array but got {}",
                                    path,
                                    element_type,
                                    json_type(field_value)
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
                                anyhow::bail!(
                                    "Property '{}' with validation 'array-all {}' has element at index {} with wrong type: expected {}, got {}",
                                    path,
                                    element_type,
                                    idx,
                                    element_type,
                                    json_type(element)
                                );
                            }

                            // Check specific values if provided
                            if let Some(required_values) = values
                                && !required_values.contains(element)
                            {
                                let allowed_values = required_values
                                    .iter()
                                    .map(|v| serde_json::to_string(v).unwrap_or_else(|_| format!("{:?}", v)))
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                anyhow::bail!(
                                    "Property '{}' with validation 'array-all {} [{}]' has element at index {} which is not in the allowed values",
                                    path,
                                    element_type,
                                    allowed_values,
                                    idx
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
                                    "Property '{}' with validation 'array-any {}' expected an array but got {}",
                                    path,
                                    element_type,
                                    json_type(field_value)
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
                            if let Some(required_values) = values {
                                let allowed_values = required_values
                                    .iter()
                                    .map(|v| serde_json::to_string(v).unwrap_or_else(|_| format!("{:?}", v)))
                                    .collect::<Vec<_>>()
                                    .join(", ");
                                anyhow::bail!(
                                    "Property '{}' with validation 'array-any {} [{}]' has no elements matching the required type and values",
                                    path,
                                    element_type,
                                    allowed_values
                                );
                            } else {
                                anyhow::bail!(
                                    "Property '{}' with validation 'array-any {}' has no elements matching the required type",
                                    path,
                                    element_type
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
                                "Property '{}' with validation 'array-length' expected an array but got {}",
                                path,
                                json_type(field_value)
                            )
                        })?;

                    let array_length = array.len();

                    if let Some(min_val) = min
                        && array_length < *min_val
                    {
                        let range_desc = match max {
                            Some(max_val) => {
                                format!("{}-{}", min_val, max_val)
                            }
                            None => format!(">= {}", min_val),
                        };
                        anyhow::bail!(
                            "Property '{}' with validation 'array-length {}' has {} elements which is less than the minimum allowed length",
                            path,
                            range_desc,
                            array_length
                        );
                    }

                    if let Some(max_val) = max
                        && array_length > *max_val
                    {
                        let range_desc = match min {
                            Some(min_val) => {
                                format!("{}-{}", min_val, max_val)
                            }
                            None => format!("<= {}", max_val),
                        };
                        anyhow::bail!(
                            "Property '{}' with validation 'array-length {}' has {} elements which is greater than the maximum allowed length",
                            path,
                            range_desc,
                            array_length
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

/// The JSON type of `value`, named in validation errors instead of the value itself.
fn json_type(value: &JsonValue) -> &'static str {
    match value {
        JsonValue::Null => "null",
        JsonValue::Bool(_) => "a boolean",
        JsonValue::Number(_) => "a number",
        JsonValue::String(_) => "a string",
        JsonValue::Array(_) => "an array",
        JsonValue::Object(_) => "an object",
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

    const VALUE_MARKER: &str = "caller-value-marker-2d9f";

    fn engine(
        json_schema: Option<JsonValue>,
        rules: Vec<ValidationRule>,
    ) -> RulesEngine {
        RulesEngine::new(&ExtensionRules {
            json_schema,
            rules,
            filter_rules: vec![],
            default_action: None,
        })
        .unwrap()
    }

    fn violation(
        engine: &RulesEngine,
        payload: &JsonValue,
    ) -> String {
        engine
            .validate(payload, "test")
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn rule_violations_name_path_and_rule_without_the_provided_value() {
        let cases = [
            (
                ValidationRule::Equals {
                    path: "provider".to_string(),
                    value: json!("local"),
                },
                json!({ "provider": VALUE_MARKER }),
                "Property 'provider' with validation 'equals \"local\"' was provided a value which does not match the required value",
            ),
            (
                ValidationRule::NotEquals {
                    path: "provider".to_string(),
                    value: json!(VALUE_MARKER),
                },
                json!({ "provider": VALUE_MARKER }),
                "Property 'provider' with validation 'not-equals \"caller-value-marker-2d9f\"' was provided the forbidden value",
            ),
            (
                ValidationRule::Regex {
                    path: "provider".to_string(),
                    pattern: "^aws$".to_string(),
                },
                json!({ "provider": VALUE_MARKER }),
                "Property 'provider' with validation 'regex ^aws$' was provided a value which does not match the required pattern",
            ),
            (
                ValidationRule::Regex {
                    path: "provider".to_string(),
                    pattern: "^aws$".to_string(),
                },
                json!({ "provider": [VALUE_MARKER] }),
                "Property 'provider' with validation 'regex ^aws$' expected a string but got an array",
            ),
            (
                ValidationRule::OneOf {
                    path: "provider".to_string(),
                    values: vec![json!("aws")],
                },
                json!({ "provider": VALUE_MARKER }),
                "Property 'provider' with validation 'one-of [\"aws\"]' was provided a value which is not in the allowed values",
            ),
            (
                ValidationRule::ArrayAll {
                    path: "tags".to_string(),
                    element_type: "string".to_string(),
                    values: Some(vec![json!("aws")]),
                },
                json!({ "tags": ["aws", VALUE_MARKER] }),
                "Property 'tags' with validation 'array-all string [\"aws\"]' has element at index 1 which is not in the allowed values",
            ),
            (
                ValidationRule::ArrayLength {
                    path: "tags".to_string(),
                    min: None,
                    max: Some(1),
                },
                json!({ "tags": ["aws", VALUE_MARKER] }),
                "Property 'tags' with validation 'array-length <= 1' has 2 elements which is greater than the maximum allowed length",
            ),
        ];

        for (rule, payload, expected) in cases {
            assert_eq!(violation(&engine(None, vec![rule]), &payload), expected);
        }
    }

    #[test]
    fn schema_violation_names_location_and_rule_without_the_payload() {
        let schema = json!({
            "type": "object",
            "required": ["model"],
            "properties": { "provider": { "type": "integer" }, "model": { "type": "string" } }
        });

        let error = violation(&engine(Some(schema), vec![]), &json!({ "provider": VALUE_MARKER }));

        assert_eq!(
            error,
            "JSON Schema structural validation failed: <root>: \"model\" is a required property; provider: fails 'type'"
        );
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
