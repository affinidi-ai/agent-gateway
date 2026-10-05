use std::collections::HashSet;

use axum::http::{HeaderMap, HeaderName};
use rust_decimal::Decimal;
use serde_json::Value;

use super::request_validation::{McpRequestValidationError, decode_mirrored_value, header_mismatch};

const MAX_SCHEMA_NODES: usize = 8192;
const MAX_SCHEMA_DEPTH: usize = 64;
const MAX_BINDINGS: usize = 128;
const MAX_HEADER_NAME_BYTES: usize = 128;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrimitiveKind {
    String,
    Integer,
    Boolean,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HeaderBinding {
    name: HeaderName,
    path: Vec<String>,
    kind: PrimitiveKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolHeaderBindings {
    bindings: Vec<HeaderBinding>,
}

impl ToolHeaderBindings {
    pub fn compile(schema: &Value) -> Result<Self, String> {
        let mut pending = vec![(schema, Vec::<String>::new(), true, 0_usize)];
        let mut names = HashSet::new();
        let mut bindings = Vec::new();
        let mut visited = 0;
        while let Some((schema, path, reachable, depth)) = pending.pop() {
            visited += 1;
            if visited > MAX_SCHEMA_NODES || depth > MAX_SCHEMA_DEPTH {
                return Err("MCP tool schema exceeds annotation traversal limits".to_string());
            }
            let Some(schema) = schema.as_object() else { continue };
            if let Some(annotation) = schema.get("x-mcp-header") {
                if !reachable || path.is_empty() {
                    return Err("x-mcp-header must be reachable from the root through properties only".to_string());
                }
                let suffix = annotation
                    .as_str()
                    .filter(|name| !name.is_empty() && name.len() <= MAX_HEADER_NAME_BYTES)
                    .ok_or("x-mcp-header must be a nonempty HTTP field-name token of at most 128 bytes")?;
                let name = HeaderName::from_bytes(format!("Mcp-Param-{suffix}").as_bytes())
                    .map_err(|_| "x-mcp-header must be an HTTP field-name token")?;
                if !names.insert(name.clone()) {
                    return Err("x-mcp-header names must be case-insensitively unique within a tool".to_string());
                }
                let kind = match schema
                    .get("type")
                    .and_then(Value::as_str)
                {
                    Some("string") => PrimitiveKind::String,
                    Some("integer") => PrimitiveKind::Integer,
                    Some("boolean") => PrimitiveKind::Boolean,
                    _ => return Err("x-mcp-header requires a string, integer or boolean property type".to_string()),
                };
                if bindings.len() == MAX_BINDINGS {
                    return Err("MCP tool has more than 128 mirrored parameters".to_string());
                }
                bindings.push(HeaderBinding { name, path: path.clone(), kind });
            }
            for (keyword, value) in schema {
                match keyword.as_str() {
                    "properties" | "patternProperties" | "$defs" | "definitions" | "dependentSchemas"
                    | "dependencies" => {
                        if let Some(children) = value.as_object() {
                            if pending
                                .len()
                                .saturating_add(children.len())
                                .saturating_add(visited)
                                > MAX_SCHEMA_NODES
                            {
                                return Err("MCP tool schema exceeds annotation traversal limits".to_string());
                            }
                            for (property, child) in children {
                                let mut child_path = path.clone();
                                child_path.push(property.clone());
                                pending.push((child, child_path, reachable && keyword == "properties", depth + 1));
                            }
                        }
                    }
                    "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                        if let Some(children) = value.as_array() {
                            if pending
                                .len()
                                .saturating_add(children.len())
                                .saturating_add(visited)
                                > MAX_SCHEMA_NODES
                            {
                                return Err("MCP tool schema exceeds annotation traversal limits".to_string());
                            }
                            for child in children {
                                pending.push((child, path.clone(), false, depth + 1));
                            }
                        }
                    }
                    "items" if value.is_array() => {
                        let children = value.as_array().unwrap();
                        if pending
                            .len()
                            .saturating_add(children.len())
                            .saturating_add(visited)
                            > MAX_SCHEMA_NODES
                        {
                            return Err("MCP tool schema exceeds annotation traversal limits".to_string());
                        }
                        for child in children {
                            pending.push((child, path.clone(), false, depth + 1));
                        }
                    }
                    "items"
                    | "additionalItems"
                    | "additionalProperties"
                    | "unevaluatedItems"
                    | "unevaluatedProperties"
                    | "propertyNames"
                    | "contains"
                    | "not"
                    | "if"
                    | "then"
                    | "else" => {
                        pending.push((value, path.clone(), false, depth + 1));
                    }
                    _ => {}
                }
            }
        }
        bindings.sort_by(|left, right| {
            left.name
                .as_str()
                .cmp(right.name.as_str())
        });
        Ok(Self { bindings })
    }

    pub fn validate(
        &self,
        arguments: &Value,
        headers: &HeaderMap,
        id: Option<Value>,
    ) -> Result<(), Box<McpRequestValidationError>> {
        for binding in &self.bindings {
            let mismatch =
                || header_mismatch(id.clone(), format!("Header {} does not match its tool argument", binding.name));
            let value = binding.value(arguments);
            let mut fields = headers
                .get_all(&binding.name)
                .iter();
            let field = fields.next();
            if fields.next().is_some() {
                return Err(mismatch());
            }
            let Some(value) = value else {
                if field.is_some() {
                    return Err(mismatch());
                }
                continue;
            };
            let field = field
                .and_then(|field| field.to_str().ok())
                .ok_or_else(mismatch)?;
            let decoded = decode_mirrored_value(field).map_err(|_| mismatch())?;
            let matches = match binding.kind {
                PrimitiveKind::String => value.as_str() == Some(decoded.as_str()),
                PrimitiveKind::Boolean => value
                    .as_bool()
                    .is_some_and(|value| {
                        decoded
                            == if value {
                                "true"
                            } else {
                                "false"
                            }
                    }),
                PrimitiveKind::Integer => value
                    .as_number()
                    .and_then(|value| safe_integer(&value.to_string()))
                    .is_some_and(|value| safe_integer(&decoded) == Some(value)),
            };
            if !matches {
                return Err(mismatch());
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn encode(
        &self,
        arguments: &Value,
    ) -> Result<HeaderMap, String> {
        let mut headers = HeaderMap::new();
        for binding in &self.bindings {
            let Some(value) = binding.value(arguments) else { continue };
            let value = match binding.kind {
                PrimitiveKind::String => value
                    .as_str()
                    .map(str::to_string),
                PrimitiveKind::Boolean => value
                    .as_bool()
                    .map(|value| value.to_string()),
                PrimitiveKind::Integer => value
                    .as_number()
                    .and_then(|value| safe_integer(&value.to_string()))
                    .map(|value| value.normalize().to_string()),
            }
            .ok_or_else(|| format!("Invalid primitive argument for {}", binding.name))?;
            let encoded = axum::http::HeaderValue::from_str(&super::request_validation::encode_mirrored_value(&value))
                .map_err(|_| format!("Invalid encoded value for {}", binding.name))?;
            headers.insert(binding.name.clone(), encoded);
        }
        Ok(headers)
    }
}

impl HeaderBinding {
    fn value<'value>(
        &self,
        arguments: &'value Value,
    ) -> Option<&'value Value> {
        self.path
            .iter()
            .try_fold(arguments, |value, property| {
                value
                    .as_object()?
                    .get(property)
            })
            .filter(|value| !value.is_null())
    }
}

fn safe_integer(value: &str) -> Option<Decimal> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'.' | b'-' | b'+' | b'e' | b'E'))
    {
        return None;
    }
    let parsed = Decimal::from_str_exact(value)
        .or_else(|_| Decimal::from_scientific(value))
        .ok()?;
    (parsed.is_integer() && parsed >= Decimal::from(-MAX_SAFE_INTEGER) && parsed <= Decimal::from(MAX_SAFE_INTEGER))
        .then_some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mirrored_values_round_trip_with_exact_nested_paths_and_safe_encoding() {
        let bindings = ToolHeaderBindings::compile(&json!({"properties": {"nested.path": {"properties": {
            "text/value": {"type": "string", "x-mcp-header": "Text"},
            "count": {"type": "integer", "x-mcp-header": "Count"},
            "enabled": {"type": "boolean", "x-mcp-header": "Enabled"}
        }}}}))
        .unwrap();
        for text in [
            "plain",
            "",
            "=?base64?prefix",
            "suffix?=",
            "=?base64?literal?=",
            " padded ",
            "line1\nline2",
            "s\u{f8}k",
            "interior\ttab",
        ] {
            let arguments = json!({"nested.path": {"text/value": text, "count": MAX_SAFE_INTEGER, "enabled": false}});
            let headers = bindings
                .encode(&arguments)
                .unwrap();
            assert_eq!(bindings.validate(&arguments, &headers, Some(json!(7))), Ok(()), "{text:?}");
            assert_eq!(headers["mcp-param-count"], MAX_SAFE_INTEGER.to_string());
            assert_eq!(headers["mcp-param-enabled"], "false");
            let mut mismatch = arguments.clone();
            mismatch["nested.path"]["text/value"] = json!("different");
            let error = bindings
                .validate(&mismatch, &headers, Some(json!(7)))
                .unwrap_err();
            assert_eq!(error.code, super::super::error_codes::HEADER_MISMATCH);
            assert_eq!(error.status, axum::http::StatusCode::BAD_REQUEST);
            assert_eq!(error.id, Some(json!(7)));
        }
    }

    #[test]
    fn absent_and_null_values_omit_headers_but_duplicates_and_missing_values_fail() {
        let bindings =
            ToolHeaderBindings::compile(&json!({"properties": {"value": {"type": "string", "x-mcp-header": "Value"}}}))
                .unwrap();
        for arguments in [json!({}), json!({"value": null})] {
            assert!(
                bindings
                    .encode(&arguments)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                bindings
                    .validate(&arguments, &HeaderMap::new(), None)
                    .is_ok()
            );
            let mut headers = HeaderMap::new();
            headers.insert("mcp-param-value", "unexpected".parse().unwrap());
            assert!(
                bindings
                    .validate(&arguments, &headers, None)
                    .is_err()
            );
        }
        let arguments = json!({"value": "literal"});
        assert!(
            bindings
                .validate(&arguments, &HeaderMap::new(), None)
                .is_err()
        );
        let mut headers = bindings
            .encode(&arguments)
            .unwrap();
        headers.append("mcp-param-value", "literal".parse().unwrap());
        assert!(
            bindings
                .validate(&arguments, &headers, None)
                .is_err()
        );
        headers.remove("mcp-param-value");
        headers.insert("mcp-param-value", "literal".parse().unwrap());
        headers.append("mcp-param-unknown", "=?base64?=".parse().unwrap());
        assert!(
            bindings
                .validate(&arguments, &headers, None)
                .is_ok()
        );
    }

    #[test]
    fn integer_comparison_is_numeric_and_never_rounds_to_an_equal_value() {
        let bindings = ToolHeaderBindings::compile(
            &json!({"properties": {"value": {"type": "integer", "x-mcp-header": "Value"}}}),
        )
        .unwrap();
        for (argument, field, valid) in [
            (json!(42), "42.0", true),
            (json!(42.0), "4.2e1", true),
            (json!(-7), "-7.000", true),
            (json!(MAX_SAFE_INTEGER), "9007199254740991.0", true),
            (json!(MAX_SAFE_INTEGER), "9007199254740991.1", false),
            (json!(MAX_SAFE_INTEGER + 1), "9007199254740992", false),
            (json!(-MAX_SAFE_INTEGER - 1), "-9007199254740992", false),
            (json!(42), "42.000000000000000000000000001", false),
            (json!(42), "4_2", false),
            (json!(42), "NaN", false),
            (json!(42), "42e99999999", false),
            (json!(42.5), "42.5", false),
            (json!("42"), "42", false),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert("mcp-param-value", field.parse().unwrap());
            assert_eq!(
                bindings
                    .validate(&json!({"value": argument}), &headers, None)
                    .is_ok(),
                valid,
                "{field}"
            );
        }
    }

    #[test]
    fn malformed_encoded_or_unencoded_header_values_are_rejected_without_panics() {
        let bindings =
            ToolHeaderBindings::compile(&json!({"properties": {"value": {"type": "string", "x-mcp-header": "Value"}}}))
                .unwrap();
        for value in ["=?base64?=", "=?base64?%%%?=", "=?base64?/w==?=", " padded "] {
            let mut headers = HeaderMap::new();
            headers.insert("mcp-param-value", value.parse().unwrap());
            assert!(
                bindings
                    .validate(&json!({"value": value}), &headers, Some(json!("request")))
                    .is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn compiles_exact_nested_property_paths_without_mutating_the_schema() {
        let schema = json!({"type": "object", "properties": {
            "tenant.with.dot": {"type": "object", "properties": {
                "region/name": {"type": "string", "x-mcp-header": "Region"},
                "enabled": {"type": "boolean", "x-mcp-header": "Enabled"},
                "count": {"type": "integer", "x-mcp-header": "Count"}
            }},
            "x-mcp-header": {"type": "string"}
        }, "$defs": {"named": {"type": "string"}}, "com.example/data": [true, null]});
        let original = schema.clone();
        let compiled = ToolHeaderBindings::compile(&schema).unwrap();
        assert_eq!(schema, original);
        assert_eq!(compiled.bindings.len(), 3);
        assert_eq!(compiled.bindings[0].name, "mcp-param-count");
        assert_eq!(compiled.bindings[0].kind, PrimitiveKind::Integer);
        assert_eq!(compiled.bindings[2].path, ["tenant.with.dot", "region/name"]);
    }

    #[test]
    fn rejects_invalid_duplicate_or_nonprimitive_annotations() {
        for annotation in [json!(""), json!("bad name"), json!("bad:name"), json!("bad\r\nname"), json!(1), json!(null)]
        {
            let schema = json!({"properties": {"value": {"type": "string", "x-mcp-header": annotation}}});
            assert!(ToolHeaderBindings::compile(&schema).is_err());
        }
        for kind in [json!("number"), json!("object"), json!("array"), json!(["string", "integer"]), Value::Null] {
            assert!(
                ToolHeaderBindings::compile(&json!({"properties": {"value": {"type": kind, "x-mcp-header": "Value"}}}))
                    .is_err()
            );
        }
        assert!(
            ToolHeaderBindings::compile(&json!({"properties": {
                "one": {"type": "string", "x-mcp-header": "Tenant"},
                "two": {"type": "string", "x-mcp-header": "tenant"}
            }}))
            .unwrap_err()
            .contains("unique")
        );
        assert!(ToolHeaderBindings::compile(&json!({"type": "string", "x-mcp-header": "Root"})).is_err());
    }

    #[test]
    fn rejects_annotations_inside_nonstatic_schema_locations() {
        let annotation = json!({"type": "string", "x-mcp-header": "Hidden"});
        for keyword in ["allOf", "anyOf", "oneOf", "prefixItems", "items"] {
            assert!(ToolHeaderBindings::compile(&json!({keyword: [annotation.clone()]})).is_err(), "{keyword}");
        }
        for keyword in ["$defs", "definitions", "patternProperties", "dependentSchemas", "dependencies"] {
            assert!(
                ToolHeaderBindings::compile(&json!({keyword: {"hidden": annotation.clone()}})).is_err(),
                "{keyword}"
            );
        }
        for keyword in [
            "if",
            "then",
            "else",
            "not",
            "items",
            "contains",
            "additionalProperties",
            "unevaluatedProperties",
            "propertyNames",
        ] {
            assert!(
                ToolHeaderBindings::compile(&json!({keyword: {"properties": {"hidden": annotation.clone()}}})).is_err(),
                "{keyword}"
            );
        }
        assert!(
            ToolHeaderBindings::compile(&json!({"$ref": "#/$defs/hidden", "$defs": {"hidden": annotation}})).is_err()
        );
    }

    #[test]
    fn annotation_shaped_instance_data_and_remote_refs_are_not_traversed() {
        let schema = json!({"type": "object", "properties": {"payload": {
            "const": {"x-mcp-header": "data"}, "default": {"x-mcp-header": "data"},
            "examples": [{"x-mcp-header": "data"}], "enum": [{"x-mcp-header": "data"}]
        }}, "$ref": "https://unreachable.invalid/schema", "$defs": {"x-mcp-header": {"type": "string"}}});
        assert_eq!(ToolHeaderBindings::compile(&schema), Ok(ToolHeaderBindings::default()));
    }

    #[test]
    fn annotation_walk_has_bounded_depth_and_count() {
        let mut schema = json!({"type": "string"});
        for _ in 0..MAX_SCHEMA_DEPTH {
            schema = json!({"properties": {"child": schema}});
        }
        assert!(ToolHeaderBindings::compile(&schema).is_ok());
        schema = json!({"properties": {"child": schema}});
        assert!(ToolHeaderBindings::compile(&schema).is_err());
        let properties: serde_json::Map<String, Value> = (0..MAX_BINDINGS)
            .map(|index| {
                (format!("property-{index}"), json!({"type": "string", "x-mcp-header": format!("Header-{index}")}))
            })
            .collect();
        let mut schema = json!({"properties": properties});
        assert!(ToolHeaderBindings::compile(&schema).is_ok());
        schema["properties"]["extra"] = json!({"type": "string", "x-mcp-header": "Extra"});
        assert!(ToolHeaderBindings::compile(&schema).is_err());
    }
}
