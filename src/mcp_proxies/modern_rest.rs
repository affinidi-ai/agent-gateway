use std::collections::HashMap;
use std::time::Duration;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use base64::Engine;
use futures::TryStreamExt;
use rmcp::model::{CallToolResult, Content};
use rmcp_openapi::{ExtractedParameters, ToolGenerator, ToolMetadata};
use serde_json::{Value, json};
use url::Url;

use crate::config::McpHttpConfig;

#[derive(Debug, thiserror::Error)]
pub(super) enum RestError {
    #[error("Invalid REST tool arguments")]
    Arguments,
    #[error("REST tool target is not permitted")]
    Target,
    #[error("REST tool redirects are not permitted")]
    Redirect,
    #[error("REST tool response exceeds its configured limit")]
    Limit,
    #[error("REST tool HTTP client is unavailable")]
    Unavailable,
    #[error("REST tool execution failed")]
    Execution,
}

struct OfflineSchemas;

impl jsonschema::Retrieve for OfflineSchemas {
    fn retrieve(
        &self,
        _uri: &jsonschema::Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err("External tool schema references are not permitted".into())
    }
}

pub(super) fn compile_schema(schema: &Value) -> Result<jsonschema::Validator, RestError> {
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .with_retriever(OfflineSchemas)
        .build(schema)
        .map_err(|_| RestError::Arguments)
}

pub(super) fn output_schema(
    spec: &Value,
    metadata: &ToolMetadata,
) -> Result<Option<Value>, RestError> {
    let path = spec
        .get("paths")
        .and_then(|paths| paths.get(&metadata.path))
        .ok_or(RestError::Arguments)?;
    let operation = local_reference(spec, path)?
        .get(
            metadata
                .method
                .to_ascii_lowercase(),
        )
        .ok_or(RestError::Arguments)?;
    let Some(responses) = operation
        .get("responses")
        .and_then(Value::as_object)
    else {
        return Ok(None);
    };
    for status in ["200", "201", "202", "203", "2XX", "default"] {
        let Some(response) = responses.get(status) else { continue };
        let Some(content) = local_reference(spec, response)?
            .get("content")
            .and_then(Value::as_object)
        else {
            continue;
        };
        let media = ["application/json", "application/ld+json", "application/vnd.api+json"]
            .into_iter()
            .find_map(|kind| content.get(kind))
            .or_else(|| {
                content
                    .iter()
                    .find(|(kind, _)| {
                        kind.parse::<mime::Mime>()
                            .is_ok_and(|mime| mime.suffix() == Some(mime::JSON))
                    })
                    .map(|(_, media)| media)
            });
        let Some(body_schema) = media.and_then(|media| media.get("schema")) else { continue };
        let mut schema = metadata
            .output_schema
            .clone()
            .unwrap_or_else(|| {
                json!({
                    "type": "object", "required": ["status", "body"], "additionalProperties": false,
                    "properties": {"status": {"type": "integer", "minimum": 100, "maximum": 599},
                        "body": {"oneOf": [true]}}
                })
            });
        match schema
            .pointer_mut("/properties/body/oneOf")
            .and_then(Value::as_array_mut)
        {
            Some(variants) if !variants.is_empty() => variants[0] = body_schema.clone(),
            _ => {
                let properties = schema
                    .get_mut("properties")
                    .and_then(Value::as_object_mut)
                    .ok_or(RestError::Arguments)?;
                properties.insert("body".into(), json!({"oneOf": [body_schema]}));
            }
        }
        retain_component_schemas(&mut schema, spec)?;
        compile_schema(&schema)?;
        return Ok(Some(schema));
    }
    Ok(None)
}

pub(super) fn routing_spec(spec: &Value) -> Result<Value, RestError> {
    fn project(
        value: &mut Value,
        depth: usize,
        visited: &mut usize,
    ) -> Result<(), RestError> {
        *visited += 1;
        if *visited > 8192 || depth > 64 {
            return Err(RestError::Arguments);
        }
        match value {
            Value::Object(object) => {
                if object
                    .get("$ref")
                    .and_then(Value::as_str)
                    .is_some_and(|reference| !reference.starts_with("#/components/"))
                {
                    object.remove("$ref");
                }
                object.remove("$dynamicRef");
                for child in object.values_mut() {
                    project(child, depth + 1, visited)?;
                }
            }
            Value::Array(children) => {
                for child in children {
                    project(child, depth + 1, visited)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    if serde_json::to_vec(spec)
        .map_err(|_| RestError::Arguments)?
        .len()
        > 1024 * 1024
    {
        return Err(RestError::Arguments);
    }
    let mut projected = spec.clone();
    project(&mut projected, 0, &mut 0)?;
    Ok(projected)
}

pub(super) fn retain_component_schemas(
    schema: &mut Value,
    spec: &Value,
) -> Result<(), RestError> {
    let mut components = serde_json::Map::new();
    let mut pending = vec![(schema.clone(), 0usize)];
    let mut visited = 0usize;
    while let Some((value, depth)) = pending.pop() {
        visited += 1;
        if visited > 8192 || depth > 64 {
            return Err(RestError::Arguments);
        }
        let Some(object) = value.as_object() else { continue };
        for keyword in ["$ref", "$dynamicRef"] {
            if let Some(reference) = object
                .get(keyword)
                .and_then(Value::as_str)
                && let Some(path) = reference.strip_prefix("#/components/schemas/")
            {
                spec.pointer(&reference[1..])
                    .ok_or(RestError::Arguments)?;
                let name = path
                    .split('/')
                    .next()
                    .ok_or(RestError::Arguments)?
                    .replace("~1", "/")
                    .replace("~0", "~");
                if !components.contains_key(&name) {
                    if components.len() >= 128 {
                        return Err(RestError::Arguments);
                    }
                    let definition = spec
                        .pointer("/components/schemas")
                        .and_then(|schemas| schemas.get(&name))
                        .ok_or(RestError::Arguments)?;
                    crate::mcp::tool_headers::ToolHeaderBindings::compile(&json!({"$defs": {"component": definition}}))
                        .map_err(|_| RestError::Arguments)?;
                    components.insert(name, definition.clone());
                    pending.push((definition.clone(), depth + 1));
                }
            }
        }
        for (keyword, child) in object {
            match keyword.as_str() {
                "properties" | "patternProperties" | "$defs" | "definitions" | "dependentSchemas" | "dependencies" => {
                    if let Some(children) = child.as_object() {
                        pending.extend(
                            children
                                .values()
                                .cloned()
                                .map(|child| (child, depth + 1)),
                        );
                    }
                }
                "allOf" | "anyOf" | "oneOf" | "prefixItems" => {
                    if let Some(children) = child.as_array() {
                        pending.extend(
                            children
                                .iter()
                                .cloned()
                                .map(|child| (child, depth + 1)),
                        );
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
                    pending.push((child.clone(), depth + 1));
                }
                _ => {}
            }
        }
        if pending
            .len()
            .saturating_add(visited)
            > 8192
        {
            return Err(RestError::Arguments);
        }
    }
    if !components.is_empty() {
        let root = schema
            .as_object_mut()
            .ok_or(RestError::Arguments)?;
        if root.contains_key("components") {
            return Err(RestError::Arguments);
        }
        root.insert("components".into(), json!({"schemas": components}));
    }
    if serde_json::to_vec(schema)
        .map_err(|_| RestError::Arguments)?
        .len()
        > 1024 * 1024
    {
        return Err(RestError::Arguments);
    }
    Ok(())
}

fn text(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        value => value.to_string(),
    }
}

pub(super) fn local_reference<'spec>(
    spec: &'spec Value,
    mut value: &'spec Value,
) -> Result<&'spec Value, RestError> {
    for _depth in 0..32 {
        let Some(reference) = value.get("$ref") else { return Ok(value) };
        let pointer = reference
            .as_str()
            .and_then(|reference| reference.strip_prefix('#'))
            .filter(|pointer| pointer.starts_with('/'))
            .ok_or(RestError::Arguments)?;
        value = spec
            .pointer(pointer)
            .ok_or(RestError::Arguments)?;
    }
    Err(RestError::Arguments)
}

pub(super) fn request_content_type(
    spec: &Value,
    metadata: &ToolMetadata,
) -> Result<String, RestError> {
    let path = spec
        .get("paths")
        .and_then(|paths| paths.get(&metadata.path))
        .ok_or(RestError::Arguments)?;
    let operation = local_reference(spec, path)?
        .get(
            metadata
                .method
                .to_ascii_lowercase(),
        )
        .ok_or(RestError::Arguments)?;
    let Some(body) = operation.get("requestBody") else { return Ok("application/json".into()) };
    let content = local_reference(spec, body)?
        .get("content")
        .and_then(Value::as_object)
        .ok_or(RestError::Arguments)?;
    let selected = ["multipart/form-data", "application/json", "application/x-www-form-urlencoded"]
        .into_iter()
        .find(|kind| content.contains_key(*kind))
        .or_else(|| {
            content
                .keys()
                .next()
                .map(String::as_str)
        })
        .ok_or(RestError::Arguments)?;
    selected
        .parse::<mime::Mime>()
        .map_err(|_| RestError::Arguments)?;
    Ok(selected.to_string())
}

fn request_url(
    base: &str,
    metadata: &ToolMetadata,
    parameters: &ExtractedParameters,
) -> Result<Url, RestError> {
    let mut url = Url::parse(base).map_err(|_| RestError::Target)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !metadata.path.starts_with('/')
        || metadata
            .path
            .starts_with("//")
        || metadata
            .path
            .contains(['\\', '?', '#'])
    {
        return Err(RestError::Target);
    }
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| RestError::Target)?;
        segments.pop_if_empty();
        for template in metadata.path[1..].split('/') {
            let mut segment = template.to_string();
            for (name, value) in &parameters.path {
                segment = segment.replace(&format!("{{{name}}}"), &text(value));
            }
            if matches!(segment.as_str(), "." | "..") || segment.contains(['{', '}']) {
                return Err(RestError::Arguments);
            }
            segments.push(&segment);
        }
    }
    if !parameters.query.is_empty() {
        let mut query = url.query_pairs_mut();
        for (name, parameter) in &parameters.query {
            match &parameter.value {
                Value::Array(values) if parameter.explode => {
                    for value in values {
                        query.append_pair(name, &text(value));
                    }
                }
                Value::Array(values) => {
                    query.append_pair(
                        name,
                        &values
                            .iter()
                            .map(text)
                            .collect::<Vec<_>>()
                            .join(","),
                    );
                }
                value => {
                    query.append_pair(name, &text(value));
                }
            }
        }
    }
    crate::url_validation::reject_cloud_metadata_url(url.as_str()).map_err(|_| RestError::Target)?;
    Ok(url)
}

fn protected_header(name: &HeaderName) -> bool {
    name.as_str()
        .starts_with("mcp-")
        || matches!(
            name.as_str(),
            "host"
                | "connection"
                | "content-length"
                | "transfer-encoding"
                | "upgrade"
                | "te"
                | "trailer"
                | "keep-alive"
                | "proxy-authorization"
                | "proxy-authenticate"
                | "last-event-id"
        )
}

fn request_headers(
    parameters: &ExtractedParameters,
    target: &HeaderMap,
) -> Result<HeaderMap, RestError> {
    let mut headers = HeaderMap::new();
    for (name, value) in target {
        if !protected_header(name) {
            headers.append(name.clone(), value.clone());
        }
    }
    for (name, value) in &parameters.headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| RestError::Arguments)?;
        let value = HeaderValue::from_str(&text(value)).map_err(|_| RestError::Arguments)?;
        if protected_header(&name)
            || headers
                .get(&name)
                .is_some_and(|current| current != value)
        {
            return Err(RestError::Arguments);
        }
        headers.insert(name, value);
    }
    if !parameters.cookies.is_empty() {
        if headers.contains_key(axum::http::header::COOKIE) {
            return Err(RestError::Arguments);
        }
        let mut cookies = Vec::new();
        for (name, value) in &parameters.cookies {
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| RestError::Arguments)?;
            let value = url::form_urlencoded::byte_serialize(text(value).as_bytes()).collect::<String>();
            cookies.push(format!("{name}={value}"));
        }
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&cookies.join("; ")).map_err(|_| RestError::Arguments)?,
        );
    }
    for (name, value) in headers.iter_mut() {
        if name == axum::http::header::AUTHORIZATION || name == axum::http::header::COOKIE {
            value.set_sensitive(true);
        }
    }
    Ok(headers)
}

async fn add_body(
    mut request: reqwest::RequestBuilder,
    parameters: &ExtractedParameters,
    content_type: &str,
    max_bytes: usize,
) -> Result<reqwest::RequestBuilder, RestError> {
    if parameters.body.is_empty() {
        return Ok(request);
    }
    let body = if parameters.body.len() == 1
        && parameters
            .body
            .contains_key("request_body")
    {
        parameters.body["request_body"].clone()
    } else {
        Value::Object(
            parameters
                .body
                .iter()
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
        )
    };
    let mime: mime::Mime = content_type
        .parse()
        .map_err(|_| RestError::Arguments)?;
    if mime.subtype() == mime::JSON || mime.suffix() == Some(mime::JSON) {
        request = request
            .header(axum::http::header::CONTENT_TYPE, mime.as_ref())
            .body(serde_json::to_vec(&body).map_err(|_| RestError::Arguments)?);
    } else if mime.essence_str() == mime::APPLICATION_WWW_FORM_URLENCODED.as_ref() {
        let body = body
            .as_object()
            .ok_or(RestError::Arguments)?;
        request = request.form(
            &body
                .iter()
                .map(|(name, value)| (name.clone(), text(value)))
                .collect::<Vec<_>>(),
        );
    } else if mime.essence_str() == mime::MULTIPART_FORM_DATA.as_ref() {
        let body = body
            .as_object()
            .ok_or(RestError::Arguments)?;
        let mut form = reqwest::multipart::Form::new();
        for (name, value) in body {
            if name.len() > 1024
                || name
                    .chars()
                    .any(char::is_control)
            {
                return Err(RestError::Arguments);
            }
            if let Some(content) = value
                .get("content")
                .and_then(Value::as_str)
                .filter(|content| content.starts_with("data:"))
            {
                if content.len()
                    > max_bytes
                        .saturating_mul(2)
                        .saturating_add(512)
                {
                    return Err(RestError::Arguments);
                }
                let data = rmcp_openapi::parse_data_uri(content, name).map_err(|_| RestError::Arguments)?;
                let filename = value
                    .get("filename")
                    .and_then(Value::as_str)
                    .unwrap_or("file");
                if data.bytes.len() > max_bytes
                    || filename.len() > 1024
                    || filename
                        .chars()
                        .any(char::is_control)
                {
                    return Err(RestError::Arguments);
                }
                let part = reqwest::multipart::Part::bytes(data.bytes)
                    .file_name(filename.to_string())
                    .mime_str(&data.mime_type)
                    .map_err(|_| RestError::Arguments)?;
                form = form.part(name.clone(), part);
            } else {
                form = form.text(name.clone(), text(value));
            }
        }
        let content_type = format!("multipart/form-data; boundary={}", form.boundary());
        let mut stream = Box::pin(form.into_stream());
        let mut encoded = Vec::new();
        while let Some(chunk) = stream
            .try_next()
            .await
            .map_err(|_| RestError::Arguments)?
        {
            if encoded
                .len()
                .saturating_add(chunk.len())
                > max_bytes
            {
                return Err(RestError::Arguments);
            }
            encoded.extend_from_slice(&chunk);
        }
        request = request
            .header(axum::http::header::CONTENT_TYPE, content_type)
            .body(encoded);
    } else if mime.type_() == mime::TEXT {
        request = request
            .header(axum::http::header::CONTENT_TYPE, mime.as_ref())
            .body(
                body.as_str()
                    .ok_or(RestError::Arguments)?
                    .to_string(),
            );
    } else {
        return Err(RestError::Arguments);
    }
    Ok(request)
}

pub(super) async fn call(
    base_url: &str,
    metadata: &ToolMetadata,
    arguments: &Value,
    target_headers: &HeaderMap,
    limits: &McpHttpConfig,
    content_type: &str,
    egress_allowlist: Option<&str>,
) -> Result<CallToolResult, RestError> {
    if serde_json::to_vec(arguments)
        .map_err(|_| RestError::Arguments)?
        .len()
        > limits.max_request_bytes.get()
    {
        return Err(RestError::Arguments);
    }
    let output_validator = metadata
        .output_schema
        .as_ref()
        .map(compile_schema)
        .transpose()?;
    let parameters = ToolGenerator::extract_parameters(metadata, arguments).map_err(|_| RestError::Arguments)?;
    let url = request_url(base_url, metadata, &parameters)?;
    let method = reqwest::Method::from_bytes(
        metadata
            .method
            .to_uppercase()
            .as_bytes(),
    )
    .map_err(|_| RestError::Arguments)?;
    if !matches!(
        method,
        reqwest::Method::GET
            | reqwest::Method::POST
            | reqwest::Method::PUT
            | reqwest::Method::PATCH
            | reqwest::Method::DELETE
            | reqwest::Method::HEAD
            | reqwest::Method::OPTIONS
    ) {
        return Err(RestError::Arguments);
    }
    let timeout = limits
        .stream_max_lifetime_secs
        .get()
        .min(
            u64::from(
                parameters
                    .config
                    .timeout_seconds,
            )
            .max(1),
        );
    // Resolve the target once, vet it with the save-time policy and pin the
    // client to that address, so DNS cannot rebind it to loopback between the
    // save-time check and this call. Redirects stay off.
    let raw_url = url.to_string();
    let egress_allowlist = egress_allowlist.map(str::to_string);
    let (client, _) = tokio::task::spawn_blocking(move || {
        crate::egress::pinned_configured_client(&raw_url, Duration::from_secs(timeout), egress_allowlist.as_deref())
    })
    .await
    .map_err(|_| RestError::Unavailable)?
    .map_err(|_| RestError::Target)?;
    let headers = request_headers(&parameters, target_headers)?;
    if headers
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        > limits.max_header_bytes.get()
    {
        return Err(RestError::Arguments);
    }
    let request = add_body(
        client
            .request(method, url.clone())
            .headers(headers),
        &parameters,
        content_type,
        limits.max_request_bytes.get(),
    )
    .await?
    .build()
    .map_err(|_| RestError::Arguments)?;
    if request
        .body()
        .and_then(reqwest::Body::as_bytes)
        .is_some_and(|body| body.len() > limits.max_request_bytes.get())
    {
        return Err(RestError::Arguments);
    }
    let mut response = client
        .execute(request)
        .await
        .map_err(|_| RestError::Execution)?;
    if response
        .status()
        .is_redirection()
    {
        return Err(RestError::Redirect);
    }
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|size| {
            size > limits
                .max_response_bytes
                .get() as u64
        })
        || response
            .headers()
            .iter()
            .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
            .sum::<usize>()
            > limits.max_header_bytes.get()
    {
        return Err(RestError::Limit);
    }
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| RestError::Execution)?
    {
        if chunk.len() > limits.max_chunk_bytes.get()
            || body
                .len()
                .saturating_add(chunk.len())
                > limits
                    .max_response_bytes
                    .get()
        {
            return Err(RestError::Limit);
        }
        body.extend_from_slice(&chunk);
    }
    let mime = content_type
        .as_ref()
        .and_then(|value| {
            value
                .parse::<mime::Mime>()
                .ok()
        });
    let (content, structured) = if mime
        .as_ref()
        .is_some_and(|mime| mime.type_() == mime::IMAGE)
    {
        (
            vec![Content::image(
                base64::engine::general_purpose::STANDARD.encode(&body),
                content_type.unwrap_or_default(),
            )],
            None,
        )
    } else {
        let body = String::from_utf8(body).map_err(|_| RestError::Execution)?;
        let structured = metadata
            .output_schema
            .as_ref()
            .and_then(|_| serde_json::from_str::<Value>(&body).ok())
            .map(|body| json!({"status": status.as_u16(), "body": body}));
        let content = match structured.as_ref() {
            Some(structured) => serde_json::to_string(structured).map_err(|_| RestError::Execution)?,
            None => rmcp_openapi::HttpResponse {
                status_code: status.as_u16(),
                status_text: status
                    .canonical_reason()
                    .unwrap_or("Unknown")
                    .into(),
                headers: HashMap::new(),
                content_type,
                body,
                body_bytes: None,
                is_success: status.is_success(),
                request_method: metadata.method.clone(),
                request_url: url.to_string(),
                request_body: String::new(),
            }
            .to_mcp_content(),
        };
        (vec![Content::text(content)], structured)
    };
    let mut result = if status.is_success() {
        CallToolResult::success(content)
    } else {
        CallToolResult::error(content)
    };
    if status.is_success()
        && output_validator
            .as_ref()
            .is_some_and(|validator| {
                structured
                    .as_ref()
                    .is_none_or(|value| !validator.is_valid(value))
            })
    {
        return Ok(CallToolResult::error(vec![Content::text("REST response does not match the tool output schema")]));
    }
    result.structured_content = structured;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(path: &str) -> ToolMetadata {
        ToolMetadata {
            name: "test".into(),
            title: None,
            description: None,
            parameters: json!({"type": "object", "properties": {}}),
            output_schema: None,
            method: "GET".into(),
            path: path.into(),
            security: None,
            parameter_mappings: HashMap::new(),
        }
    }

    #[test]
    fn advertised_schemas_validate_modern_constraints_without_external_fetches() {
        let schema = json!({"type": "object", "$defs": {"pair": {
            "type": "array", "prefixItems": [{"type": "string"}, {"type": "integer"}], "items": false
        }}, "properties": {"pair": {"$ref": "#/$defs/pair"}}, "required": ["pair"], "unevaluatedProperties": false});
        let validator = compile_schema(&schema).unwrap();
        assert!(validator.is_valid(&json!({"pair": ["value", 2]})));
        assert!(!validator.is_valid(&json!({"pair": ["value", "wrong"]})));
        assert!(!validator.is_valid(&json!({"pair": ["value", 2, 3]})));
        assert!(!validator.is_valid(&json!({"pair": ["value", 2], "extra": true})));
        for reference in ["https://127.0.0.1:1/schema", "file:///private/schema", "#/missing"] {
            assert!(compile_schema(&json!({"$ref": reference})).is_err());
        }
    }

    #[test]
    fn request_media_types_resolve_only_bounded_local_openapi_references() {
        let spec = json!({"paths": {"/test": {"post": {"requestBody": {"$ref": "#/components/requestBodies/Form"}}}},
            "components": {"requestBodies": {"Form": {"content": {"application/x-www-form-urlencoded": {"schema": {"type": "object"}}}}}}});
        let mut tool = metadata("/test");
        tool.method = "POST".into();
        assert_eq!(request_content_type(&spec, &tool).unwrap(), "application/x-www-form-urlencoded");
        for reference in ["https://other.example/schema", "#/missing", "#/paths/~1test/post/requestBody"] {
            let mut changed = spec.clone();
            changed["paths"]["/test"]["post"]["requestBody"]["$ref"] = json!(reference);
            assert!(request_content_type(&changed, &tool).is_err());
        }
    }

    #[tokio::test]
    async fn rest_body_encoders_preserve_forms_and_bound_multipart_before_sending() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let app = axum::Router::new()
            .route(
                "/form",
                axum::routing::post(|axum::Form(fields): axum::Form<HashMap<String, String>>| async move {
                    assert_eq!(
                        fields
                            .get("message")
                            .map(String::as_str),
                        Some("hello world")
                    );
                    assert_eq!(
                        fields
                            .get("count")
                            .map(String::as_str),
                        Some("2")
                    );
                    axum::Json(json!({"ok": true}))
                }),
            )
            .route(
                "/multipart",
                axum::routing::post(move |mut multipart: axum::extract::Multipart| {
                    let observed = observed.clone();
                    async move {
                        observed.fetch_add(1, Ordering::SeqCst);
                        let mut fields = HashMap::new();
                        while let Some(field) = multipart
                            .next_field()
                            .await
                            .unwrap()
                        {
                            let name = field
                                .name()
                                .unwrap()
                                .to_string();
                            if name == "document" {
                                assert_eq!(field.file_name(), Some("document.txt"));
                                assert_eq!(field.content_type(), Some("text/plain"));
                            }
                            fields.insert(name, field.bytes().await.unwrap());
                        }
                        assert_eq!(fields["document"].as_ref(), b"file contents");
                        assert_eq!(fields["message"].as_ref(), b"hello world");
                        axum::Json(json!({"ok": true}))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        let mut tool = metadata("/form");
        tool.method = "POST".into();
        tool.parameters =
            json!({"type": "object", "properties": {"request_body": {"type": "object", "additionalProperties": true}}});
        let limits = McpHttpConfig::default();
        let result = call(
            &base,
            &tool,
            &json!({"request_body": {"message": "hello world", "count": 2}}),
            &HeaderMap::new(),
            &limits,
            "application/x-www-form-urlencoded",
            Some(base.as_str()),
        )
        .await
        .unwrap();
        assert_eq!(result.is_error, Some(false));
        tool.path = "/multipart".into();
        let arguments = json!({"request_body": {"message": "hello world", "document": {
            "content": format!("data:text/plain;base64,{}", base64::engine::general_purpose::STANDARD.encode(b"file contents")),
            "filename": "document.txt"
        }}});
        let result =
            call(&base, &tool, &arguments, &HeaderMap::new(), &limits, "multipart/form-data", Some(base.as_str()))
                .await
                .unwrap();
        assert_eq!(result.is_error, Some(false));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let bounded = McpHttpConfig {
            max_request_bytes: std::num::NonZeroUsize::new(256).unwrap(),
            ..Default::default()
        };
        assert!(matches!(
            call(&base, &tool, &arguments, &HeaderMap::new(), &bounded, "multipart/form-data", Some(base.as_str()))
                .await,
            Err(RestError::Arguments)
        ));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        tasks.shutdown().await;
    }

    #[test]
    fn parameters_cannot_change_the_target_authority_or_override_credentials() {
        let tool = metadata("/records/{id}");
        let mut parameters = ToolGenerator::extract_parameters(&tool, &json!({})).unwrap();
        parameters
            .path
            .insert("id".into(), json!("//other.example/a?value#fragment"));
        parameters.query.insert(
            "labels".into(),
            rmcp_openapi::tool_generator::QueryParameter::new(json!(["one two", "three"]), true),
        );
        let url = request_url("https://target.example/api", &tool, &parameters).unwrap();
        assert_eq!(url.host_str(), Some("target.example"));
        assert_eq!(url.path(), "/api/records/%2F%2Fother.example%2Fa%3Fvalue%23fragment");
        assert_eq!(
            url.query_pairs()
                .collect::<Vec<_>>(),
            vec![("labels".into(), "one two".into()), ("labels".into(), "three".into())]
        );
        assert!(url.fragment().is_none());
        parameters
            .path
            .insert("id".into(), json!(".."));
        assert!(matches!(request_url("https://target.example/api", &tool, &parameters), Err(RestError::Arguments)));
        for path in ["//other.example/", "/../escape", "/bad?query", "/bad#fragment", "/bad\\path"] {
            assert!(request_url("https://target.example/api", &metadata(path), &parameters).is_err());
        }
        for base in [
            "file:///private",
            "http://169.254.169.254/",
            "https://user:password@target.example/",
            "https://target.example/?query",
        ] {
            assert!(request_url(base, &metadata("/ok"), &parameters).is_err());
        }
        let mut target = HeaderMap::new();
        target.insert(
            "authorization",
            "Bearer target-token"
                .parse()
                .unwrap(),
        );
        target.insert("mcp-session-id", "ignored".parse().unwrap());
        parameters
            .headers
            .insert("Authorization".into(), json!("Bearer argument-token"));
        assert!(matches!(request_headers(&parameters, &target), Err(RestError::Arguments)));
        parameters.headers.clear();
        for name in ["host", "content-length", "mcp-param-header", "connection"] {
            parameters
                .headers
                .insert(name.into(), json!("override"));
            assert!(request_headers(&parameters, &target).is_err());
            parameters.headers.clear();
        }
        let headers = request_headers(&parameters, &target).unwrap();
        assert_eq!(headers["authorization"], "Bearer target-token");
        assert!(headers["authorization"].is_sensitive());
        assert!(!headers.contains_key("mcp-session-id"));
    }

    #[tokio::test]
    async fn bounded_rest_responses_keep_structured_errors_and_cancel_oversized_reads() {
        use axum::response::IntoResponse;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };

        struct Dropped(Arc<AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0
                    .store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let observer = dropped.clone();
        let app = axum::Router::new()
            .route("/ok", axum::routing::get(|| async { axum::Json(json!({"value": [1, true, null]})) }))
            .route(
                "/error",
                axum::routing::get(|| async {
                    (axum::http::StatusCode::BAD_REQUEST, axum::Json(json!({"reason": "invalid"})))
                }),
            )
            .route("/length", axum::routing::get(|| async { "x".repeat(8192) }))
            .route(
                "/image",
                axum::routing::get(|| async {
                    ([("content-type", "image/png")], vec![137u8, 80, 78, 71]).into_response()
                }),
            )
            .route(
                "/stream",
                axum::routing::get(move || {
                    let observer = observer.clone();
                    async move {
                        axum::body::Body::from_stream(futures::stream::unfold(
                            (Dropped(observer), 0usize),
                            |(guard, count)| async move {
                                if count >= 16 {
                                    std::future::pending::<()>().await;
                                }
                                Some((
                                    Ok::<_, std::io::Error>(bytes::Bytes::from(vec![b'x'; 1024])),
                                    (guard, count + 1),
                                ))
                            },
                        ))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        let limits = McpHttpConfig {
            max_response_bytes: std::num::NonZeroUsize::new(4096).unwrap(),
            ..Default::default()
        };
        for path in ["/ok", "/error"] {
            let mut tool = metadata(path);
            tool.output_schema = Some(json!({"type": "object"}));
            let result =
                call(&base, &tool, &json!({}), &HeaderMap::new(), &limits, "application/json", Some(base.as_str()))
                    .await
                    .unwrap();
            assert_eq!(result.is_error, Some(path == "/error"));
            assert_eq!(
                result
                    .structured_content
                    .as_ref()
                    .unwrap()["status"],
                if path == "/error" {
                    400
                } else {
                    200
                }
            );
            if path == "/ok" {
                assert_eq!(
                    result
                        .structured_content
                        .as_ref()
                        .unwrap()["body"]["value"],
                    json!([1, true, null])
                );
            }
        }
        let image = call(
            &base,
            &metadata("/image"),
            &json!({}),
            &HeaderMap::new(),
            &limits,
            "application/json",
            Some(base.as_str()),
        )
        .await
        .unwrap();
        let image = serde_json::to_value(image).unwrap();
        assert_eq!(image["content"][0]["type"], "image");
        assert_eq!(image["content"][0]["mimeType"], "image/png");
        assert!(
            matches!(
                call(&base, &metadata("/ok"), &json!({}), &HeaderMap::new(), &limits, "application/json", None).await,
                Err(RestError::Target)
            ),
            "a backend that resolves to loopback is refused at call time"
        );
        for path in ["/length", "/stream"] {
            assert!(matches!(
                call(
                    &base,
                    &metadata(path),
                    &json!({}),
                    &HeaderMap::new(),
                    &limits,
                    "application/json",
                    Some(base.as_str())
                )
                .await,
                Err(RestError::Limit)
            ));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while !dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("oversized upstream must be dropped without waiting for EOF");
        tasks.shutdown().await;
    }
}
