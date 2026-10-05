//! JSON schema derivation from agent identity metadata

/// Derive a JSON schema from the agentIdentity metadata structure
/// This inspects the actual values to determine their types and generates a matching schema
#[allow(dead_code)]
pub fn derive_schema_from_metadata(metadata: &serde_json::Value) -> serde_json::Value {
    use serde_json::json;

    // Helper function to infer type from a JSON value
    fn infer_type(value: &serde_json::Value) -> &str {
        match value {
            serde_json::Value::String(_) => "string",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::Bool(_) => "boolean",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
            serde_json::Value::Null => "null",
        }
    }

    // Helper function to recursively build schema from object
    fn build_schema_from_object(obj: &serde_json::Map<String, serde_json::Value>) -> serde_json::Value {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();

        for (key, value) in obj.iter() {
            let prop_schema = match value {
                serde_json::Value::Object(nested_obj) => build_schema_from_object(nested_obj),
                serde_json::Value::Array(arr) => {
                    if let Some(first) = arr.first() {
                        json!({
                            "type": "array",
                            "items": match first {
                                serde_json::Value::Object(item_obj) => build_schema_from_object(item_obj),
                                _ => json!({ "type": infer_type(first) })
                            }
                        })
                    } else {
                        json!({ "type": "array", "items": {} })
                    }
                }
                _ => json!({ "type": infer_type(value) }),
            };

            properties.insert(key.clone(), prop_schema);
            required.push(key.clone());
        }

        json!({
            "type": "object",
            "properties": properties,
            "required": required
        })
    }

    let agent_identity_schema = if let Some(obj) = metadata.as_object() {
        build_schema_from_object(obj)
    } else {
        // Default empty schema
        json!({
            "type": "object",
            "properties": {},
            "required": []
        })
    };

    // Wrap in the required structure with proper root-level schema properties
    json!({
        "type": "object",
        "properties": {
            "agentIdentity": agent_identity_schema
        },
        "required": ["agentIdentity"]
    })
}
