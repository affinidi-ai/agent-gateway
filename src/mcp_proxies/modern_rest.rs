use std::collections::HashMap;
use std::time::Duration;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use base64::Engine;
use futures::TryStreamExt;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp_openapi::{ExtractedParameters, ToolGenerator, ToolMetadata};
use serde_json::{Value, json};
use url::Url;

use crate::config::McpHttpConfig;
use crate::proxy::handler::SentServiceToken;

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
    /// A tool call that carries a grant by binding would send a body whose
    /// top-level key asks the backend to run another HTTP method.
    #[error("REST tool call asks for another HTTP method")]
    MethodOverride,
    /// The backend refused the grant by binding the call carried, as
    /// [`crate::delegation_vault::release::vendor_answer`] reads its answer: its
    /// status and `WWW-Authenticate` challenges, never its body.
    #[error("REST backend refused the grant")]
    GrantRefused { status: u16, challenges: Vec<HeaderValue> },
}

/// How the client of a tool call is vetted.
#[derive(Clone, Copy)]
enum RestEgress<'a> {
    /// A stored backend, under the Configured egress policy;
    /// `exact_allowlist` is the BDD allow-list of fixtures.
    Configured { exact_allowlist: Option<&'a str> },
    /// A tool call of a Transit Point's MCP Proxy: through Strict,
    /// `https`-only egress pinned to the vetted addresses, as a Transit Point
    /// sends a grant ([`crate::egress::pinned_vendor_client`]). With
    /// `grant_destination`, the call carries a grant by binding: it goes only
    /// to that origin, the origin of its provider's `resource`, and an answer
    /// that refuses the grant is [`RestError::GrantRefused`].
    Transit { grant_destination: Option<&'a url::Origin>, exact_allowlist: Option<&'a str> },
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

/// The OpenAPI extension on a JSON media type of an operation's answer that
/// says the answer carries a file ([`FileAnswer`]).
const FILE_EXTENSION: &str = "x-gateway-file";

/// The longest JSON Pointer, in characters, a [`FileAnswer`] may name.
const MAX_FILE_POINTER: usize = 256;

/// A success answer of an operation, as its `responses` names it: one status,
/// `2XX`, or `default`. Ordered as the output schema and the file
/// declaration are taken from the answers: each status in turn, then `2XX`,
/// then `default`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SuccessStatus {
    Exact(u16),
    Any,
    Default,
}

impl SuccessStatus {
    /// The success answer `key` names, or `None` for a failure status and for
    /// a key OpenAPI does not define.
    fn named(key: &str) -> Option<Self> {
        match key {
            "default" => Some(Self::Default),
            "2XX" | "2xx" => Some(Self::Any),
            _ => key
                .parse::<u16>()
                .ok()
                .filter(|code| (200..300).contains(code))
                .map(Self::Exact),
        }
    }

    /// Whether an answer of `status` is one this names.
    fn names(
        self,
        status: u16,
    ) -> bool {
        match self {
            Self::Exact(code) => status == code,
            Self::Any | Self::Default => (200..300).contains(&status),
        }
    }
}

/// A success answer of an operation and the JSON media types it declares,
/// the one the output schema is taken from first.
struct JsonAnswer<'spec> {
    status: SuccessStatus,
    media: Vec<(&'spec str, &'spec Value)>,
}

/// Every JSON media type of each success answer `metadata`'s operation
/// declares, in the order the output schema and the file declarations are
/// taken from them: by status, and within an answer `application/json`,
/// `application/ld+json` and `application/vnd.api+json` first, then every
/// other media type whose subtype ends in `+json`. A media type is listed
/// whether or not it has a `schema`, which OpenAPI leaves optional.
fn json_answers<'spec>(
    spec: &'spec Value,
    metadata: &ToolMetadata,
) -> Result<Vec<JsonAnswer<'spec>>, RestError> {
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
        return Ok(Vec::new());
    };
    let mut answers = Vec::new();
    for (key, response) in responses {
        let Some(status) = SuccessStatus::named(key) else { continue };
        let Some(content) = local_reference(spec, response)?
            .get("content")
            .and_then(Value::as_object)
        else {
            continue;
        };
        let mut media: Vec<(&str, &Value)> = ["application/json", "application/ld+json", "application/vnd.api+json"]
            .into_iter()
            .filter_map(|kind| {
                content
                    .get(kind)
                    .map(|media| (kind, media))
            })
            .collect();
        for (kind, value) in content {
            if media
                .iter()
                .any(|(named, _)| *named == kind.as_str())
            {
                continue;
            }
            if kind
                .parse::<mime::Mime>()
                .is_ok_and(|mime| mime.suffix() == Some(mime::JSON))
            {
                media.push((kind.as_str(), value));
            }
        }
        if !media.is_empty() {
            answers.push(JsonAnswer { status, media });
        }
    }
    answers.sort_by_key(|answer| answer.status);
    Ok(answers)
}

/// What `metadata`'s tool answers, read from its operation's success answers
/// in one pass: the tool's output schema, and the files its answers carry
/// ([`FileAnswers`]). A tool whose answer carries a file has no output
/// schema, since it answers the file, not the JSON.
pub(super) fn answer_contract(
    spec: &Value,
    metadata: &ToolMetadata,
) -> Result<(Option<Value>, Option<FileAnswers>), RestError> {
    let answers = json_answers(spec, metadata)?;
    if let Some(files) = declared_files(&answers)? {
        return Ok((None, Some(files)));
    }
    let Some(body_schema) = answers
        .iter()
        .find_map(|answer| {
            answer
                .media
                .first()
                .and_then(|(_, media)| media.get("schema"))
        })
    else {
        return Ok((None, None));
    };
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
    Ok((Some(schema), None))
}

/// The output schema of `metadata`'s tool: its JSON answer's schema as the
/// `body` of a status and body. A tool whose answer carries a file
/// ([`file_answer`]) has none, since it answers the file, not the JSON.
pub(super) fn output_schema(
    spec: &Value,
    metadata: &ToolMetadata,
) -> Result<Option<Value>, RestError> {
    answer_contract(spec, metadata).map(|(schema, _)| schema)
}

/// A file a REST API answers inside its JSON, as a string of base64 or
/// base64url, declared on a JSON media type of a success answer of the
/// operation with `x-gateway-file`:
/// `{"pointer": "/data", "encoding": "base64url"}`. That answer of the tool
/// is then the decoded file as an embedded resource, never the JSON around
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FileAnswer {
    declaration: FileDeclaration,
    /// The success answer the declaration was found on. Only that answer
    /// carries the file; another answer is answered without it.
    status: SuccessStatus,
    /// The JSON media type it was declared on, which an answer of several
    /// declaring media types is matched against.
    media_type: String,
}

/// Every file an operation's success answers declare, in the order they were
/// read, beside every JSON media type those answers declare. An operation
/// declares more than one file when it answers several JSON media types, or a
/// file on more than one status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FileAnswers {
    files: Vec<FileAnswer>,
    /// Every JSON media type each success answer declares, whether or not it
    /// declares a file, so an answer sent as a media type the operation
    /// declares without one is answered as its JSON instead of another
    /// media type's file.
    media_types: Vec<(SuccessStatus, String)>,
}

impl FileAnswers {
    /// The file an answer of `status`, sent as `content_type`, carries: the
    /// one declared on that status whose media type the answer names. An
    /// answer of a media type that status declares without a file carries
    /// none, so it is answered as its JSON. One whose media type that status
    /// does not declare, or that names none at all, carries the first file
    /// declared on the status.
    fn governing(
        &self,
        status: u16,
        content_type: Option<&str>,
    ) -> Option<&FileAnswer> {
        let declared = || {
            self.files
                .iter()
                .filter(|file| file.status.names(status))
        };
        let answered = content_type.and_then(|value| {
            value
                .parse::<mime::Mime>()
                .ok()
        });
        let Some(answered) = answered else { return declared().next() };
        let answered = answered.essence_str();
        if let Some(file) = declared().find(|file| {
            file.media_type
                .eq_ignore_ascii_case(answered)
        }) {
            return Some(file);
        }
        let declared_without_file = self
            .media_types
            .iter()
            .any(|(declared_on, media_type)| declared_on.names(status) && media_type.eq_ignore_ascii_case(answered));
        if declared_without_file {
            None
        } else {
            declared().next()
        }
    }
}

/// The `x-gateway-file` declaration itself.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDeclaration {
    /// The JSON Pointer (RFC 6901) of the string holding the file.
    pointer: String,
    encoding: FileEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum FileEncoding {
    /// RFC 4648 section 4, padded or not.
    Base64,
    /// RFC 4648 section 5, padded or not.
    Base64url,
}

impl FileDeclaration {
    fn declared(declared: &Value) -> Result<Self, RestError> {
        let file: Self = serde::Deserialize::deserialize(declared).map_err(|_| RestError::Arguments)?;
        if !file.pointer.starts_with('/') || file.pointer.chars().count() > MAX_FILE_POINTER {
            return Err(RestError::Arguments);
        }
        Ok(file)
    }
}

impl FileAnswer {
    /// The file `body` carries: the string at the pointer of its JSON,
    /// decoded. `None` when `body` is not JSON, has no string there or the
    /// string is not in the declared encoding.
    fn bytes(
        &self,
        body: &[u8],
    ) -> Option<Vec<u8>> {
        use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
        const EITHER_PADDING: GeneralPurposeConfig =
            GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent);
        const BASE64: GeneralPurpose = GeneralPurpose::new(&base64::alphabet::STANDARD, EITHER_PADDING);
        const BASE64URL: GeneralPurpose = GeneralPurpose::new(&base64::alphabet::URL_SAFE, EITHER_PADDING);
        let answer: Value = serde_json::from_slice(body).ok()?;
        let encoded = answer
            .pointer(&self.declaration.pointer)?
            .as_str()?;
        match self.declaration.encoding {
            FileEncoding::Base64 => BASE64.decode(encoded),
            FileEncoding::Base64url => BASE64URL.decode(encoded),
        }
        .ok()
    }
}

/// The files `metadata`'s tool answers inside its JSON, when a JSON media
/// type of a success answer of its operation declares one with
/// `x-gateway-file`. A declaration that is not a [`FileDeclaration`], on any
/// of them, refuses the tool as an unusable output schema does.
pub(super) fn file_answers(
    spec: &Value,
    metadata: &ToolMetadata,
) -> Result<Option<FileAnswers>, RestError> {
    declared_files(&json_answers(spec, metadata)?)
}

/// The files the success answers declare, beside every JSON media type those
/// answers declare. Every JSON media type of every success answer is read, so
/// a malformed declaration on any of them refuses the tool.
fn declared_files(answers: &[JsonAnswer<'_>]) -> Result<Option<FileAnswers>, RestError> {
    let mut files = Vec::new();
    let mut media_types = Vec::new();
    for answer in answers {
        for (media_type, media) in &answer.media {
            media_types.push((answer.status, (*media_type).to_string()));
            let Some(declared) = media.get(FILE_EXTENSION) else { continue };
            files.push(FileAnswer {
                declaration: FileDeclaration::declared(declared)?,
                status: answer.status,
                media_type: (*media_type).to_string(),
            });
        }
    }
    Ok((!files.is_empty()).then_some(FileAnswers { files, media_types }))
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
    let base = url.clone();
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
    if !base
        .path()
        .trim_matches('/')
        .is_empty()
        && !crate::proxy::paths::is_within_target_base(base.as_str(), url.as_str())
    {
        return Err(RestError::Arguments);
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
            // The target's headers carry its credential, a grant among them,
            // in whichever header it goes: never indexed by HPACK.
            let mut value = value.clone();
            value.set_sensitive(true);
            headers.append(name.clone(), value);
        }
    }
    for (name, value) in &parameters.headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| RestError::Arguments)?;
        let value = HeaderValue::from_str(&text(value)).map_err(|_| RestError::Arguments)?;
        if protected_header(&name)
            || crate::config::caller_key::is_caller_key_header(name.as_str())
            || headers
                .get(&name)
                .is_some_and(|current| current != value)
            || headers
                .keys()
                .any(|existing| {
                    existing != name
                        && crate::config::target_auth_rules::same_header_name(name.as_str(), existing.as_str())
                })
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

/// The body a tool call sends: its `request_body` argument, or its body
/// arguments as one object; `None` when it sends none.
fn request_body(parameters: &ExtractedParameters) -> Option<Value> {
    if parameters.body.is_empty() {
        return None;
    }
    Some(
        if parameters.body.len() == 1
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
        },
    )
}

async fn add_body(
    mut request: reqwest::RequestBuilder,
    parameters: &ExtractedParameters,
    content_type: &str,
    max_bytes: usize,
) -> Result<reqwest::RequestBuilder, RestError> {
    let Some(body) = request_body(parameters) else {
        return Ok(request);
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
    files: Option<&FileAnswers>,
    arguments: &Value,
    target_headers: &HeaderMap,
    limits: &McpHttpConfig,
    content_type: &str,
    egress_allowlist: Option<&str>,
    sent_token: Option<&SentServiceToken<'_>>,
) -> Result<CallToolResult, RestError> {
    send(
        base_url,
        metadata,
        files,
        arguments,
        target_headers,
        limits,
        content_type,
        RestEgress::Configured {
            exact_allowlist: egress_allowlist,
        },
        sent_token,
        None,
    )
    .await
}

/// A tool call of a Transit Point's MCP Proxy, with a grant by binding in
/// `target_headers` or with no credential: sent through Strict, `https`-only
/// egress pinned to the vetted addresses, with redirects refused
/// (`exact_allowlist`, the BDD allow-list, alone admits a fixture). With
/// `grant_destination`, the origin of the grant's `resource`, the call goes
/// only to that origin, and an answer that refuses the grant, as
/// [`crate::delegation_vault::release::vendor_answer`] reads it, is
/// [`RestError::GrantRefused`], without its body, so the caller can refresh
/// the grant or refuse the call with a fixed reason, and a call whose body
/// has a top-level key that asks for another HTTP method is
/// [`RestError::MethodOverride`], never sent. `progress` records the call as
/// sent just before the request goes out, once its URL, egress, headers and
/// body passed every check, so a call refused by any of them is never taken
/// as sent, and then the status the backend answered, even when the answer
/// is refused afterwards.
pub(super) async fn call_through_transit_point(
    base_url: &str,
    metadata: &ToolMetadata,
    files: Option<&FileAnswers>,
    arguments: &Value,
    target_headers: &HeaderMap,
    limits: &McpHttpConfig,
    content_type: &str,
    grant_destination: Option<&url::Origin>,
    exact_allowlist: Option<&str>,
    progress: &super::handlers::TransitCallProgress,
) -> Result<CallToolResult, RestError> {
    send(
        base_url,
        metadata,
        files,
        arguments,
        target_headers,
        limits,
        content_type,
        RestEgress::Transit {
            grant_destination,
            exact_allowlist,
        },
        None,
        Some(progress),
    )
    .await
}

/// The client a tool call to `url` is sent with, vetted as `egress` says and
/// pinned to the vetted address, so DNS cannot rebind it between the check
/// and the call. Redirects stay off.
async fn pinned_client(
    url: &Url,
    timeout: Duration,
    egress: RestEgress<'_>,
) -> Result<reqwest::Client, RestError> {
    match egress {
        RestEgress::Configured { exact_allowlist } => {
            let raw_url = url.to_string();
            let exact_allowlist = exact_allowlist.map(str::to_string);
            Ok(tokio::task::spawn_blocking(move || {
                crate::egress::pinned_configured_client(&raw_url, timeout, exact_allowlist.as_deref())
            })
            .await
            .map_err(|_| RestError::Unavailable)?
            .map_err(|_| RestError::Target)?
            .0)
        }
        RestEgress::Transit {
            grant_destination,
            exact_allowlist,
        } => {
            if grant_destination.is_some_and(|destination| url.origin() != *destination) {
                return Err(RestError::Target);
            }
            crate::egress::pinned_vendor_client(url.as_str(), timeout, exact_allowlist)
                .await
                .map_err(|_| RestError::Target)
        }
    }
}

async fn send(
    base_url: &str,
    metadata: &ToolMetadata,
    files: Option<&FileAnswers>,
    arguments: &Value,
    target_headers: &HeaderMap,
    limits: &McpHttpConfig,
    content_type: &str,
    egress: RestEgress<'_>,
    sent_token: Option<&SentServiceToken<'_>>,
    progress: Option<&super::handlers::TransitCallProgress>,
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
    let client = pinned_client(&url, Duration::from_secs(timeout), egress).await?;
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
            .timeout(Duration::from_secs(timeout))
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
    if let RestEgress::Transit { grant_destination: Some(_), .. } = egress
        && request_body(&parameters).is_some_and(|body| {
            body.as_object()
                .is_some_and(|fields| {
                    fields
                        .keys()
                        .any(|field| super::handlers::overrides_the_method(field))
                })
        })
    {
        return Err(RestError::MethodOverride);
    }
    if let Some(progress) = progress {
        progress.mark_sent();
    }
    let mut response = client
        .execute(request)
        .await
        .map_err(|_| RestError::Execution)?;
    if let Some(progress) = progress {
        progress.mark_answered(response.status());
    }
    if let Some(sent_token) = sent_token {
        sent_token
            .forget_if_refused(response.status().as_u16(), response.headers())
            .await;
    }
    if let RestEgress::Transit { grant_destination: Some(_), .. } = egress
        && !matches!(
            crate::delegation_vault::release::vendor_answer(response.status(), response.headers()),
            crate::delegation_vault::release::VendorAnswer::Pass
        )
    {
        return Err(RestError::GrantRefused {
            status: response.status().as_u16(),
            challenges: response
                .headers()
                .get_all(axum::http::header::WWW_AUTHENTICATE)
                .iter()
                .cloned()
                .collect(),
        });
    }
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
    if let Some(file) = files.and_then(|files| files.governing(status.as_u16(), content_type.as_deref())) {
        return Ok(match file.bytes(&body) {
            Some(bytes) => CallToolResult::success(vec![binary_content(&url, None, &bytes)]),
            None => CallToolResult::error(vec![ContentBlock::text(
                "REST response does not carry the file its tool declares",
            )]),
        });
    }
    let is_image = !body.is_empty()
        && content_type
            .as_deref()
            .and_then(|value| {
                value
                    .parse::<mime::Mime>()
                    .ok()
            })
            .is_some_and(|mime| mime.type_() == mime::IMAGE);
    let (content, structured) = if is_image {
        (
            vec![ContentBlock::image(
                base64::engine::general_purpose::STANDARD.encode(&body),
                content_type.unwrap_or_default(),
            )],
            None,
        )
    } else {
        match String::from_utf8(body) {
            Ok(body) => text_content(metadata, &url, status, content_type, body)?,
            Err(error) => (vec![binary_content(&url, content_type, error.as_bytes())], None),
        }
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
        return Ok(CallToolResult::error(vec![ContentBlock::text(
            "REST response does not match the tool output schema",
        )]));
    }
    result.structured_content = structured;
    Ok(result)
}

fn text_content(
    metadata: &ToolMetadata,
    url: &Url,
    status: reqwest::StatusCode,
    content_type: Option<String>,
    body: String,
) -> Result<(Vec<ContentBlock>, Option<Value>), RestError> {
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
    Ok((vec![ContentBlock::text(content)], structured))
}

fn resource_uri(url: &Url) -> String {
    let mut url = url.clone();
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn binary_content(
    url: &Url,
    content_type: Option<String>,
    body: &[u8],
) -> ContentBlock {
    ContentBlock::resource(rmcp::model::ResourceContents::BlobResourceContents {
        uri: resource_uri(url),
        mime_type: Some(content_type.unwrap_or_else(|| "application/octet-stream".into())),
        blob: base64::engine::general_purpose::STANDARD.encode(body),
        meta: None,
    })
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
            None,
            &json!({"request_body": {"message": "hello world", "count": 2}}),
            &HeaderMap::new(),
            &limits,
            "application/x-www-form-urlencoded",
            Some(base.as_str()),
            None,
        )
        .await
        .unwrap();
        assert_eq!(result.is_error, Some(false));
        tool.path = "/multipart".into();
        let arguments = json!({"request_body": {"message": "hello world", "document": {
            "content": format!("data:text/plain;base64,{}", base64::engine::general_purpose::STANDARD.encode(b"file contents")),
            "filename": "document.txt"
        }}});
        let result = call(
            &base,
            &tool,
            None,
            &arguments,
            &HeaderMap::new(),
            &limits,
            "multipart/form-data",
            Some(base.as_str()),
            None,
        )
        .await
        .unwrap();
        assert_eq!(result.is_error, Some(false));
        assert_eq!(count.load(Ordering::SeqCst), 1);
        let bounded = McpHttpConfig {
            max_request_bytes: std::num::NonZeroUsize::new(256).unwrap(),
            ..Default::default()
        };
        assert!(matches!(
            call(
                &base,
                &tool,
                None,
                &arguments,
                &HeaderMap::new(),
                &bounded,
                "multipart/form-data",
                Some(base.as_str()),
                None
            )
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
        for climbing in ["../../admin", "..\\..\\admin", "..;", "%2e%2e/admin", "..%2Fadmin"] {
            parameters
                .path
                .insert("id".into(), json!(climbing));
            assert!(
                matches!(request_url("https://target.example/api", &tool, &parameters), Err(RestError::Arguments)),
                "{climbing}"
            );
        }
        for kept in ["a/b", "x..y", "...", ".hidden"] {
            parameters
                .path
                .insert("id".into(), json!(kept));
            assert!(request_url("https://target.example/api", &tool, &parameters).is_ok(), "{kept}");
        }
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
        target.insert("x-api-key", "target-key".parse().unwrap());
        parameters
            .headers
            .insert("X_Api_Key".into(), json!("argument-key"));
        assert!(matches!(request_headers(&parameters, &target), Err(RestError::Arguments)));
        parameters.headers.clear();
        parameters
            .headers
            .insert("X-Api-Key-Hint".into(), json!("kept"));
        assert_eq!(request_headers(&parameters, &target).unwrap()["x-api-key-hint"], "kept");
        parameters.headers.clear();
        target.remove("x-api-key");
        for name in ["host", "content-length", "mcp-param-header", "connection", "x-caller-key", "X_Caller_Key_Memory"]
        {
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
            let result = call(
                &base,
                &tool,
                None,
                &json!({}),
                &HeaderMap::new(),
                &limits,
                "application/json",
                Some(base.as_str()),
                None,
            )
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
            None,
            &json!({}),
            &HeaderMap::new(),
            &limits,
            "application/json",
            Some(base.as_str()),
            None,
        )
        .await
        .unwrap();
        let image = serde_json::to_value(image).unwrap();
        assert_eq!(image["content"][0]["type"], "image");
        assert_eq!(image["content"][0]["mimeType"], "image/png");
        assert!(
            matches!(
                call(
                    &base,
                    &metadata("/ok"),
                    None,
                    &json!({}),
                    &HeaderMap::new(),
                    &limits,
                    "application/json",
                    None,
                    None
                )
                .await,
                Err(RestError::Target)
            ),
            "a backend that resolves to loopback is refused at call time"
        );
        for path in ["/length", "/stream"] {
            assert!(matches!(
                call(
                    &base,
                    &metadata(path),
                    None,
                    &json!({}),
                    &HeaderMap::new(),
                    &limits,
                    "application/json",
                    Some(base.as_str()),
                    None,
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

    #[tokio::test]
    async fn binary_rest_responses_arrive_as_embedded_resources_with_their_bytes() {
        use axum::response::IntoResponse;

        const PDF: &[u8] = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog >>\nendobj\n";
        let app = axum::Router::new()
            .route(
                "/pdf",
                axum::routing::get(|| async { ([("content-type", "application/pdf")], PDF).into_response() }),
            )
            .route(
                "/untyped",
                axum::routing::get(|| async {
                    axum::http::Response::builder()
                        .body(axum::body::Body::from(vec![0u8, 159, 146, 150]))
                        .unwrap()
                }),
            )
            .route(
                "/latin1",
                axum::routing::get(|| async {
                    ([("content-type", "text/plain; charset=iso-8859-1")], vec![b'c', b'a', b'f', 0xe9]).into_response()
                }),
            )
            .route(
                "/denied",
                axum::routing::get(|| async {
                    (axum::http::StatusCode::FORBIDDEN, [("content-type", "application/pdf")], PDF).into_response()
                }),
            )
            .route("/plain", axum::routing::get(|| async { "hello" }));
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
        let limits = McpHttpConfig::default();
        let fetch = |path: &'static str| {
            let base = base.clone();
            let limits = limits.clone();
            async move {
                let result = call(
                    &base,
                    &metadata(path),
                    None,
                    &json!({}),
                    &HeaderMap::new(),
                    &limits,
                    "application/json",
                    Some(base.as_str()),
                    None,
                )
                .await
                .unwrap();
                assert!(
                    result
                        .structured_content
                        .is_none()
                );
                serde_json::to_value(result).unwrap()
            }
        };
        let blob = |value: &Value| {
            base64::engine::general_purpose::STANDARD
                .decode(
                    value["content"][0]["resource"]["blob"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap()
        };
        for (path, mime, bytes, is_error) in [
            ("/pdf", "application/pdf", PDF.to_vec(), false),
            ("/untyped", "application/octet-stream", vec![0u8, 159, 146, 150], false),
            ("/latin1", "text/plain; charset=iso-8859-1", vec![b'c', b'a', b'f', 0xe9], false),
            ("/denied", "application/pdf", PDF.to_vec(), true),
        ] {
            let result = fetch(path).await;
            assert_eq!(result["isError"], is_error, "{path}");
            assert_eq!(
                result["content"]
                    .as_array()
                    .map(Vec::len),
                Some(1),
                "{path}"
            );
            assert_eq!(result["content"][0]["type"], "resource", "{path}");
            assert_eq!(result["content"][0]["resource"]["mimeType"], mime, "{path}");
            assert_eq!(result["content"][0]["resource"]["uri"], format!("{base}{path}"), "{path}");
            assert_eq!(blob(&result), bytes, "{path}");
        }
        let mut schema_tool = metadata("/pdf");
        schema_tool.output_schema = Some(json!({"type": "object"}));
        let mismatched = call(
            &base,
            &schema_tool,
            None,
            &json!({}),
            &HeaderMap::new(),
            &limits,
            "application/json",
            Some(base.as_str()),
            None,
        )
        .await
        .unwrap();
        assert_eq!(mismatched.is_error, Some(true), "a file is not the JSON the tool's output schema names");
        let plain = fetch("/plain").await;
        assert_eq!(plain["content"][0]["type"], "text");
        assert!(
            plain["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("hello")
        );
        tasks.shutdown().await;
    }

    /// One file declared on `status` and `media_type`, as a spec declares it.
    fn declared_on(
        status: SuccessStatus,
        media_type: &str,
        pointer: &str,
        encoding: &str,
    ) -> FileAnswers {
        FileAnswers {
            files: vec![FileAnswer {
                declaration: FileDeclaration::declared(&json!({"pointer": pointer, "encoding": encoding})).unwrap(),
                status,
                media_type: media_type.to_string(),
            }],
            media_types: vec![(status, media_type.to_string())],
        }
    }

    /// The one file `spec` declares for `path`, for a spec that declares at
    /// most one.
    fn only_file(
        spec: &Value,
        path: &str,
    ) -> Option<FileAnswer> {
        let files = file_answers(spec, &metadata(path)).unwrap()?;
        assert_eq!(files.files.len(), 1, "one declaration, got {:?}", files.files);
        files.files.into_iter().next()
    }

    #[test]
    fn a_file_answer_is_declared_on_the_json_answer_and_a_malformed_declaration_refuses_the_tool() {
        let spec = |declared: Option<Value>| {
            let mut media = json!({"schema": {"type": "object"}});
            if let Some(declared) = declared {
                media[FILE_EXTENSION] = declared;
            }
            json!({
                "paths": {
                    "/file": {"get": {"responses": {"200": {"content": {"application/json": media}}}}},
                    "/shared": {"get": {"responses": {"200": {"$ref": "#/components/responses/File"}}}}
                },
                "components": {"responses": {"File": {"content": {"application/json": {
                    "schema": {"type": "object"}, FILE_EXTENSION: {"pointer": "/file/content", "encoding": "base64"}
                }}}}}
            })
        };
        let declared = spec(Some(json!({"pointer": "/data", "encoding": "base64url"})));
        assert_eq!(
            only_file(&declared, "/file"),
            Some(FileAnswer {
                declaration: FileDeclaration {
                    pointer: "/data".into(),
                    encoding: FileEncoding::Base64url
                },
                status: SuccessStatus::Exact(200),
                media_type: "application/json".into()
            })
        );
        assert_eq!(
            output_schema(&declared, &metadata("/file")).unwrap(),
            None,
            "a tool answering a file has no output schema"
        );
        assert_eq!(
            only_file(&declared, "/shared"),
            Some(FileAnswer {
                declaration: FileDeclaration {
                    pointer: "/file/content".into(),
                    encoding: FileEncoding::Base64
                },
                status: SuccessStatus::Exact(200),
                media_type: "application/json".into()
            })
        );
        let undeclared = spec(None);
        assert_eq!(only_file(&undeclared, "/file"), None);
        assert!(
            output_schema(&undeclared, &metadata("/file"))
                .unwrap()
                .is_some()
        );
        for malformed in [
            json!({"pointer": "data", "encoding": "base64url"}),
            json!({"pointer": "", "encoding": "base64url"}),
            json!({"pointer": format!("/{}", "a".repeat(MAX_FILE_POINTER)), "encoding": "base64url"}),
            json!({"pointer": "/data"}),
            json!({"pointer": "/data", "encoding": "hex"}),
            json!({"pointer": "/data", "encoding": "Base64"}),
            json!({"pointer": "/data", "encoding": "base64url", "media_type": "application/pdf"}),
            json!({"encoding": "base64url"}),
            json!("/data"),
            json!(true),
        ] {
            let spec = spec(Some(malformed.clone()));
            assert!(file_answers(&spec, &metadata("/file")).is_err(), "{malformed}");
            assert!(output_schema(&spec, &metadata("/file")).is_err(), "{malformed}");
        }
    }

    /// A declaration stands on its own: OpenAPI leaves `schema` optional on a
    /// media type, and a success answer the output schema is not taken from
    /// still declares the file its own answer carries.
    #[test]
    fn a_file_answer_is_read_without_a_schema_and_on_any_success_answer() {
        let spec = |status: &str, media: Value| {
            json!({"paths": {"/file": {"get": {"responses": {
                status: {"description": "OK", "content": {"application/json": media}}
            }}}}})
        };
        for status in ["200", "206", "2XX", "default"] {
            let schemaless = spec(status, json!({FILE_EXTENSION: {"pointer": "/data", "encoding": "base64"}}));
            assert_eq!(
                only_file(&schemaless, "/file").map(|file| file.status),
                SuccessStatus::named(status),
                "{status}: a declaration beside no schema is read"
            );
            assert_eq!(output_schema(&schemaless, &metadata("/file")).unwrap(), None, "{status}");
            let malformed = spec(status, json!({FILE_EXTENSION: {"pointer": "/data", "encoding": "hex"}}));
            assert!(
                file_answers(&malformed, &metadata("/file")).is_err(),
                "{status}: a malformed declaration beside no schema refuses the tool"
            );
            assert!(output_schema(&malformed, &metadata("/file")).is_err(), "{status}");
        }
        let undeclared = spec("200", json!({}));
        assert_eq!(only_file(&undeclared, "/file"), None);
        assert_eq!(
            output_schema(&undeclared, &metadata("/file")).unwrap(),
            None,
            "a JSON answer with no schema carries no output schema either"
        );
        let both = json!({"paths": {"/file": {"get": {"responses": {
            "200": {"description": "OK", "content": {"application/json": {"schema": {"type": "object"}}}},
            "206": {"description": "Partial", "content": {"application/json": {
                FILE_EXTENSION: {"pointer": "/data", "encoding": "base64"}
            }}}
        }}}}});
        let files = file_answers(&both, &metadata("/file"))
            .unwrap()
            .expect("the declaration on the later success answer is read");
        assert_eq!(
            files
                .governing(206, None)
                .map(|file| file.status),
            Some(SuccessStatus::Exact(206)),
            "the answer it was declared on carries the file"
        );
        assert!(
            files
                .governing(200, None)
                .is_none(),
            "another success answer does not"
        );
        assert_eq!(
            output_schema(&both, &metadata("/file")).unwrap(),
            None,
            "a tool answering a file advertises no output schema"
        );
        for status in [SuccessStatus::Any, SuccessStatus::Default] {
            assert!(status.names(204) && !status.names(404), "{status:?} names every success answer");
        }
        let pointer = |characters: usize| format!("/{}", "é".repeat(characters));
        let longest =
            spec("200", json!({FILE_EXTENSION: {"pointer": pointer(MAX_FILE_POINTER - 1), "encoding": "base64"}}));
        assert!(only_file(&longest, "/file").is_some(), "the pointer limit counts characters, not UTF-8 bytes");
        let too_long =
            spec("200", json!({FILE_EXTENSION: {"pointer": pointer(MAX_FILE_POINTER), "encoding": "base64"}}));
        assert!(file_answers(&too_long, &metadata("/file")).is_err());
    }

    /// A declaration is read on every JSON media type of an answer, not only
    /// the one the output schema is taken from, and the media type the REST
    /// API answered picks which declaration that answer carries.
    #[test]
    fn a_file_answer_is_declared_on_any_json_media_type_of_an_answer() {
        let spec = |vendor: Value| {
            json!({"paths": {"/file": {"get": {"responses": {"200": {"description": "OK", "content": {
                "application/json": {"schema": {"type": "object"}},
                "application/vnd.example+json": vendor
            }}}}}}})
        };
        let declared = spec(json!({FILE_EXTENSION: {"pointer": "/data", "encoding": "base64"}}));
        assert_eq!(
            only_file(&declared, "/file").map(|file| file.media_type),
            Some("application/vnd.example+json".to_string()),
            "a declaration on a vendor JSON media type is read"
        );
        assert_eq!(
            output_schema(&declared, &metadata("/file")).unwrap(),
            None,
            "the tool answers a file, so it advertises no output schema"
        );
        let schema_only = file_answers(&declared, &metadata("/file"))
            .unwrap()
            .expect("the vendor media type declares a file");
        assert!(
            schema_only
                .governing(200, Some("application/json"))
                .is_none(),
            "a media type the answer declares without a file is answered as its JSON"
        );
        assert_eq!(
            schema_only
                .governing(200, Some("application/vnd.example+json"))
                .map(|file| file
                    .declaration
                    .pointer
                    .clone()),
            Some("/data".to_string()),
            "the media type the file is declared on still carries it"
        );
        assert_eq!(
            schema_only
                .governing(200, None)
                .map(|file| file
                    .declaration
                    .pointer
                    .clone()),
            Some("/data".to_string()),
            "an answer naming no media type carries the first file of its status"
        );
        let malformed = spec(json!({FILE_EXTENSION: {"pointer": "/data", "encoding": "hex"}}));
        assert!(
            file_answers(&malformed, &metadata("/file")).is_err(),
            "a malformed declaration on a vendor media type refuses the tool"
        );
        assert!(output_schema(&malformed, &metadata("/file")).is_err());
        let two = json!({"paths": {"/file": {"get": {"responses": {"200": {"description": "OK", "content": {
            "application/json": {FILE_EXTENSION: {"pointer": "/data", "encoding": "base64"}},
            "application/vnd.example+json": {FILE_EXTENSION: {"pointer": "/file/content", "encoding": "base64url"}}
        }}}}}}});
        let files = file_answers(&two, &metadata("/file"))
            .unwrap()
            .expect("both declarations are read");
        assert_eq!(files.files.len(), 2, "{files:?}");
        let pointer = |content_type: Option<&str>| {
            files
                .governing(200, content_type)
                .map(|file| {
                    file.declaration
                        .pointer
                        .clone()
                })
        };
        assert_eq!(
            pointer(Some("application/vnd.example+json")),
            Some("/file/content".to_string()),
            "the media type the API answered picks its declaration"
        );
        assert_eq!(
            pointer(Some("application/json; charset=utf-8")),
            Some("/data".to_string()),
            "media type parameters are ignored"
        );
        assert_eq!(
            pointer(None),
            Some("/data".to_string()),
            "an answer naming no media type carries the first declaration of its status"
        );
        assert_eq!(
            pointer(Some("text/plain")),
            Some("/data".to_string()),
            "so does one whose media type the operation does not declare"
        );
        assert!(
            files
                .governing(404, Some("application/json"))
                .is_none(),
            "a failure answer carries no file"
        );
    }

    #[tokio::test]
    async fn a_file_inside_a_json_answer_arrives_as_an_embedded_resource_with_its_bytes() {
        use axum::response::IntoResponse;

        const FILE: &[u8] = b"%PDF-1.7\n\xfb\xff\xbf\x00\x01";
        let engine = |alphabet: &base64::alphabet::Alphabet, padded: bool| {
            base64::engine::GeneralPurpose::new(
                alphabet,
                base64::engine::GeneralPurposeConfig::new().with_encode_padding(padded),
            )
        };
        let padded = engine(&base64::alphabet::URL_SAFE, true).encode(FILE);
        let unpadded = engine(&base64::alphabet::URL_SAFE, false).encode(FILE);
        let standard = engine(&base64::alphabet::STANDARD, true).encode(FILE);
        let unpadded_standard = engine(&base64::alphabet::STANDARD, false).encode(FILE);
        assert!(padded.ends_with('=') && padded.contains(['-', '_']), "{padded}");
        assert!(standard.contains(['+', '/']), "{standard}");
        assert!(!unpadded.ends_with('=') && !unpadded_standard.ends_with('='), "{unpadded_standard}");
        let vendor_body = json!({"file": {"content": standard.clone()}}).to_string();
        let vendor = axum::routing::get(move || {
            let body = vendor_body.clone();
            async move { ([("content-type", "application/vnd.example+json")], body).into_response() }
        });
        let answers = [
            ("/padded", json!({"size": FILE.len(), "data": padded})),
            ("/unpadded", json!({"size": FILE.len(), "data": unpadded})),
            ("/unpadded-standard", json!({"size": FILE.len(), "data": unpadded_standard})),
            ("/nested", json!({"file": {"content": standard.clone()}})),
            ("/missing", json!({"size": FILE.len()})),
            ("/number", json!({"data": 5})),
            ("/garbled", json!({"data": "not base64!"})),
            ("/other-alphabet", json!({"data": standard})),
        ];
        let mut app = axum::Router::new()
            .route("/not-json", axum::routing::get(|| async { "plain words" }))
            .route("/vendor", vendor)
            .route(
                "/accepted",
                axum::routing::get(|| async {
                    (axum::http::StatusCode::ACCEPTED, axum::Json(json!({"size": 4, "data": "AAECAw"}))).into_response()
                }),
            )
            .route(
                "/denied",
                axum::routing::get(|| async {
                    (axum::http::StatusCode::FORBIDDEN, axum::Json(json!({"error": "no access to this file"})))
                        .into_response()
                }),
            );
        for (path, answer) in answers {
            app = app.route(path, axum::routing::get(move || async move { axum::Json(answer).into_response() }));
        }
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
        let limits = McpHttpConfig::default();
        let fetch = |path: &'static str, pointer: &'static str, encoding: &'static str| {
            let base = base.clone();
            let limits = limits.clone();
            async move {
                let files = declared_on(SuccessStatus::Any, "application/json", pointer, encoding);
                let result = call(
                    &base,
                    &metadata(path),
                    Some(&files),
                    &json!({}),
                    &HeaderMap::new(),
                    &limits,
                    "application/json",
                    Some(base.as_str()),
                    None,
                )
                .await
                .unwrap();
                assert!(
                    result
                        .structured_content
                        .is_none(),
                    "{path}"
                );
                serde_json::to_value(result).unwrap()
            }
        };
        for (path, pointer, encoding) in [
            ("/padded", "/data", "base64url"),
            ("/unpadded", "/data", "base64url"),
            ("/unpadded-standard", "/data", "base64"),
            ("/nested", "/file/content", "base64"),
        ] {
            let result = fetch(path, pointer, encoding).await;
            assert_eq!(result["isError"], false, "{path}");
            assert_eq!(
                result["content"]
                    .as_array()
                    .map(Vec::len),
                Some(1),
                "{path}"
            );
            assert_eq!(result["content"][0]["type"], "resource", "{path}");
            assert_eq!(result["content"][0]["resource"]["mimeType"], "application/octet-stream", "{path}");
            assert_eq!(result["content"][0]["resource"]["uri"], format!("{base}{path}"), "{path}");
            let blob = base64::engine::general_purpose::STANDARD
                .decode(
                    result["content"][0]["resource"]["blob"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap();
            assert_eq!(blob, FILE, "{path}");
        }
        for (path, encoding) in [
            ("/missing", "base64url"),
            ("/number", "base64url"),
            ("/garbled", "base64url"),
            ("/other-alphabet", "base64url"),
            ("/not-json", "base64url"),
        ] {
            let result = fetch(path, "/data", encoding).await;
            assert_eq!(result["isError"], true, "{path}");
            assert_eq!(
                result["content"],
                json!([{"type": "text", "text": "REST response does not carry the file its tool declares"}]),
                "{path}: the answer is never quoted back"
            );
        }
        let denied = fetch("/denied", "/data", "base64url").await;
        assert_eq!(denied["isError"], true);
        assert_eq!(denied["content"][0]["type"], "text", "a failed answer is the REST API's own error");
        assert!(
            denied["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("no access to this file")
        );
        let declared_on_200 = declared_on(SuccessStatus::Exact(200), "application/json", "/data", "base64url");
        let accepted = call(
            &base,
            &metadata("/accepted"),
            Some(&declared_on_200),
            &json!({}),
            &HeaderMap::new(),
            &limits,
            "application/json",
            Some(base.as_str()),
            None,
        )
        .await
        .unwrap();
        let accepted = serde_json::to_value(accepted).unwrap();
        assert_eq!(accepted["isError"], false, "{accepted}");
        assert_eq!(
            accepted["content"][0]["type"], "text",
            "a success answer the file was not declared on is answered as its JSON: {accepted}"
        );
        let two_media_types = FileAnswers {
            files: vec![
                declared_on(SuccessStatus::Exact(200), "application/json", "/data", "base64url").files[0].clone(),
                declared_on(SuccessStatus::Exact(200), "application/vnd.example+json", "/file/content", "base64").files
                    [0]
                .clone(),
            ],
            media_types: vec![
                (SuccessStatus::Exact(200), "application/json".to_string()),
                (SuccessStatus::Exact(200), "application/vnd.example+json".to_string()),
            ],
        };
        let vendor = call(
            &base,
            &metadata("/vendor"),
            Some(&two_media_types),
            &json!({}),
            &HeaderMap::new(),
            &limits,
            "application/json",
            Some(base.as_str()),
            None,
        )
        .await
        .unwrap();
        let vendor = serde_json::to_value(vendor).unwrap();
        assert_eq!(vendor["isError"], false, "{vendor}");
        assert_eq!(vendor["content"][0]["type"], "resource", "{vendor}");
        let blob = base64::engine::general_purpose::STANDARD
            .decode(
                vendor["content"][0]["resource"]["blob"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(blob, FILE, "the media type the API answered picked its own declaration");
        tasks.shutdown().await;
    }

    #[tokio::test]
    async fn utf8_bodies_stay_text_whatever_their_content_type() {
        use axum::response::IntoResponse;

        let typed = |content_type: &'static str, body: &'static str| {
            axum::routing::get(move || async move { ([("content-type", content_type)], body).into_response() })
        };
        let app = axum::Router::new()
            .route("/octet-json", typed("application/octet-stream", r#"{"ok":true}"#))
            .route("/amz-json", typed("application/x-amz-json-1.1", r#"{"ok":true}"#))
            .route("/ascii-pdf", typed("application/pdf", "%PDF-1.4 plain"))
            .route("/empty-pdf", typed("application/pdf", ""))
            .route("/empty-png", typed("image/png", ""));
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
        let limits = McpHttpConfig::default();
        let fetch = |tool: ToolMetadata| {
            let base = base.clone();
            let limits = limits.clone();
            async move {
                call(
                    &base,
                    &tool,
                    None,
                    &json!({}),
                    &HeaderMap::new(),
                    &limits,
                    "application/json",
                    Some(base.as_str()),
                    None,
                )
                .await
                .unwrap()
            }
        };
        for path in ["/octet-json", "/amz-json"] {
            let mut tool = metadata(path);
            tool.output_schema = Some(json!({"type": "object", "properties": {"body": {"type": "object"}}}));
            let result = fetch(tool).await;
            assert_eq!(result.is_error, Some(false), "{path}");
            assert_eq!(result.structured_content, Some(json!({"status": 200, "body": {"ok": true}})), "{path}");
        }
        for (path, text) in
            [("/ascii-pdf", "%PDF-1.4 plain"), ("/empty-pdf", "Status: 200 OK"), ("/empty-png", "Status: 200 OK")]
        {
            let result = serde_json::to_value(fetch(metadata(path)).await).unwrap();
            assert_eq!(result["isError"], false, "{path}");
            assert_eq!(result["content"][0]["type"], "text", "{path}");
            assert!(
                result["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains(text),
                "{path}: {result}"
            );
        }
        tasks.shutdown().await;
    }

    #[tokio::test]
    async fn the_rest_client_bounds_file_and_image_bytes_before_encoding() {
        use axum::response::IntoResponse;

        let sized = |content_type: &'static str, byte: u8, len: usize| {
            axum::routing::get(
                move || async move { ([("content-type", content_type)], vec![byte; len]).into_response() },
            )
        };
        let app = axum::Router::new()
            .route("/file-fits", sized("application/octet-stream", 0xff, 400))
            .route("/file-over", sized("application/octet-stream", 0xff, 401))
            .route("/image-fits", sized("image/png", 0xff, 400))
            .route("/image-over", sized("image/png", 0xff, 401))
            .route("/text-over", sized("text/plain", b'a', 401));
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
        let limits: McpHttpConfig = serde_json::from_value(json!({"max_response_bytes": 400})).unwrap();
        for (path, fits) in [
            ("/file-fits", true),
            ("/file-over", false),
            ("/image-fits", true),
            ("/image-over", false),
            ("/text-over", false),
        ] {
            let result = call(
                &base,
                &metadata(path),
                None,
                &json!({}),
                &HeaderMap::new(),
                &limits,
                "application/json",
                Some(base.as_str()),
                None,
            )
            .await;
            assert_eq!(result.is_ok(), fits, "{path}");
            if !fits {
                assert!(matches!(result, Err(RestError::Limit)), "{path}");
            }
        }
        tasks.shutdown().await;
    }

    #[test]
    fn a_resource_names_its_backend_url_without_query_or_fragment() {
        let url = Url::parse("https://www.example.com/download/files/abc?alt=media&key=k#part").unwrap();
        assert_eq!(resource_uri(&url), "https://www.example.com/download/files/abc");
        let root = Url::parse("https://www.example.com/?q=1").unwrap();
        assert_eq!(resource_uri(&root), "https://www.example.com/");
    }

    /// A tool call that carries a grant goes only to the grant's origin,
    /// through Strict egress, which admits the loopback fixture only from the
    /// test allow-list. An answer that refuses the grant comes back as its
    /// status and challenges, never its body; any other answer, a `403` that
    /// is not about the grant's scope among them, is the tool's result. Only
    /// a call that went out is reported sent.
    #[tokio::test]
    async fn a_call_with_a_grant_goes_only_to_its_origin_and_reports_a_refused_grant() {
        use crate::delegation_vault::revocation::tests::{Answer, RecordingServer};
        let challenge = r#"Bearer error="invalid_token""#;
        let vendor = RecordingServer::start_answering(vec![
            Answer::json(200, json!({"files": []})),
            Answer::json(401, json!({"error": "vendor-words"})).with_header("WWW-Authenticate", challenge),
            Answer::json(403, json!({"error": "not shared with you"})),
        ])
        .await;
        let origin = vendor.origin();
        let destination = Url::parse(&origin)
            .unwrap()
            .origin();
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::AUTHORIZATION, HeaderValue::from_static("Bearer granted"));
        let limits = McpHttpConfig::default();
        let sent = |destination: &url::Origin, exact_allowlist: Option<&str>| {
            let (base, headers, limits, destination, exact_allowlist) = (
                origin.clone(),
                headers.clone(),
                limits.clone(),
                destination.clone(),
                exact_allowlist.map(str::to_string),
            );
            async move {
                let progress = crate::mcp_proxies::handlers::TransitCallProgress::default();
                let answer = call_through_transit_point(
                    &base,
                    &metadata("/files"),
                    None,
                    &json!({}),
                    &headers,
                    &limits,
                    "application/json",
                    Some(&destination),
                    exact_allowlist.as_deref(),
                    &progress,
                )
                .await;
                (answer, progress.sent(), progress.answered())
            }
        };

        let (answered, went_out, status) = sent(&destination, Some(&origin)).await;
        assert_eq!(answered.unwrap().is_error, Some(false));
        assert!(went_out);
        assert_eq!(status.map(|status| status.as_u16()), Some(200));
        match sent(&destination, Some(&origin)).await {
            (Err(RestError::GrantRefused { status, challenges }), true, _) => {
                assert_eq!(status, 401);
                assert_eq!(challenges, [HeaderValue::from_static(challenge)]);
            }
            other => panic!("expected the refused grant, got {other:?}"),
        }
        let (forbidden, went_out, status) = sent(&destination, Some(&origin)).await;
        assert_eq!(forbidden.unwrap().is_error, Some(true), "a 403 that is not about scope is the tool's own error");
        assert!(went_out);
        assert_eq!(status.map(|status| status.as_u16()), Some(403), "with the backend's status");

        let elsewhere = Url::parse("http://127.0.0.1:9")
            .unwrap()
            .origin();
        assert!(
            matches!(sent(&elsewhere, Some(&origin)).await, (Err(RestError::Target), false, None)),
            "another origin, never sent"
        );
        assert!(
            matches!(sent(&destination, None).await, (Err(RestError::Target), false, None)),
            "Strict egress refuses the loopback fixture without the test allow-list, and it is never sent"
        );
        let requests = vendor.requests();
        assert_eq!(requests.len(), 3, "only the permitted calls reach the backend");
        assert!(
            requests
                .iter()
                .all(|(head, _)| head.starts_with("GET /files ") && head.contains("authorization: Bearer granted")),
            "{requests:?}"
        );
    }

    /// A Transit Point's tool call reads the file its answer declares, as a
    /// call sent by the gateway's own REST client does.
    #[tokio::test]
    async fn a_transit_point_call_answers_the_file_inside_its_json_as_an_embedded_resource() {
        use crate::delegation_vault::revocation::tests::{Answer, RecordingServer};
        const FILE: &[u8] = b"%PDF-1.7\n\xfb\xff\xbf\x00\x01";
        let encoded = base64::engine::general_purpose::URL_SAFE.encode(FILE);
        let vendor =
            RecordingServer::start_answering(vec![Answer::json(200, json!({"size": FILE.len(), "data": encoded}))])
                .await;
        let origin = vendor.origin();
        let destination = Url::parse(&origin)
            .unwrap()
            .origin();
        let files = declared_on(SuccessStatus::Exact(200), "application/json", "/data", "base64url");
        let progress = crate::mcp_proxies::handlers::TransitCallProgress::default();
        let answer = call_through_transit_point(
            &origin,
            &metadata("/files"),
            Some(&files),
            &json!({}),
            &HeaderMap::new(),
            &McpHttpConfig::default(),
            "application/json",
            Some(&destination),
            Some(&origin),
            &progress,
        )
        .await
        .unwrap();
        assert!(
            answer
                .structured_content
                .is_none()
        );
        let answer = serde_json::to_value(answer).unwrap();
        assert_eq!(answer["isError"], false, "{answer}");
        assert_eq!(answer["content"][0]["type"], "resource", "{answer}");
        assert_eq!(answer["content"][0]["resource"]["mimeType"], "application/octet-stream", "{answer}");
        let blob = base64::engine::general_purpose::STANDARD
            .decode(
                answer["content"][0]["resource"]["blob"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(blob, FILE, "the file's bytes arrive decoded");
    }

    /// A Transit Point's tool call without a grant goes through the same
    /// Strict egress as one with a grant: a backend whose host resolves to an
    /// internal address, as a rebinding host would, is never reached, nor is
    /// one only the test allow-list admits without it; a redirect is never
    /// followed; and a backend's own refusal is the tool's result, not a
    /// refused grant.
    #[tokio::test]
    async fn a_transit_point_call_without_a_grant_reaches_no_internal_address_and_follows_no_redirect() {
        use crate::delegation_vault::revocation::tests::{Answer, RecordingServer};
        let backend = RecordingServer::start_answering(vec![
            Answer::json(200, json!({"files": []})),
            Answer::json(401, json!({"error": "no key"})).with_header("WWW-Authenticate", "Bearer"),
        ])
        .await;
        let elsewhere = RecordingServer::start_answering(vec![Answer::json(200, json!({"stolen": true}))]).await;
        let redirecting = RecordingServer::start_answering(vec![
            Answer::status(302).with_header("Location", &format!("{}/files", elsewhere.origin())),
        ])
        .await;
        let limits = McpHttpConfig::default();
        let call = |base: String, exact_allowlist: Option<String>| {
            let limits = limits.clone();
            async move {
                let progress = crate::mcp_proxies::handlers::TransitCallProgress::default();
                let answer = call_through_transit_point(
                    &base,
                    &metadata("/files"),
                    None,
                    &json!({}),
                    &HeaderMap::new(),
                    &limits,
                    "application/json",
                    None,
                    exact_allowlist.as_deref(),
                    &progress,
                )
                .await;
                (answer, progress.answered())
            }
        };
        let allowlist = Some(format!("{},{},{}", backend.origin(), elsewhere.origin(), redirecting.origin()));

        let (answered, _) = call(backend.origin(), allowlist.clone()).await;
        assert_eq!(answered.unwrap().is_error, Some(false));
        let (refused, _) = call(backend.origin(), allowlist.clone()).await;
        assert_eq!(refused.unwrap().is_error, Some(true), "with no grant, a 401 is the tool's own error");

        let rebound = backend
            .origin()
            .replacen("http://127.0.0.1", "https://localhost", 1);
        assert!(
            matches!(call(rebound, allowlist.clone()).await, (Err(RestError::Target), None)),
            "a host that resolves to loopback is refused"
        );
        assert!(
            matches!(call(backend.origin(), None).await, (Err(RestError::Target), None)),
            "Strict egress refuses a loopback backend the test allow-list does not admit"
        );
        let (redirected, status) = call(redirecting.origin(), allowlist).await;
        assert!(matches!(redirected, Err(RestError::Redirect)), "a redirect is refused, not followed");
        assert_eq!(
            status.map(|status| status.as_u16()),
            Some(302),
            "the backend's status is kept though its answer is refused"
        );
        assert_eq!(backend.requests().len(), 2);
        assert_eq!(redirecting.requests().len(), 1);
        assert!(
            elsewhere
                .requests()
                .is_empty(),
            "{:?}",
            elsewhere.requests()
        );
    }

    /// A tool call that carries a grant is refused, never sent, when its body
    /// has a top-level key that asks for another HTTP method, whether the
    /// spec declares it or not, form-encoded or JSON; any other key is sent,
    /// and a call without a grant is not checked.
    #[tokio::test]
    async fn a_call_with_a_grant_whose_body_asks_for_another_method_is_never_sent() {
        use crate::delegation_vault::revocation::tests::{Answer, RecordingServer};
        let vendor = RecordingServer::start_answering(vec![
            Answer::json(200, json!({"id": "1"})),
            Answer::json(200, json!({"id": "2"})),
        ])
        .await;
        let origin = vendor.origin();
        let destination = Url::parse(&origin)
            .unwrap()
            .origin();
        let mut post = metadata("/files");
        post.method = "post".into();
        post.parameters = json!({"type": "object", "properties": {"request_body": {"type": "object",
            "properties": {"name": {"type": "string"}}, "additionalProperties": true}}});
        post.parameter_mappings
            .insert(
                "request_body".into(),
                rmcp_openapi::tool::ParameterMapping {
                    sanitized_name: "request_body".into(),
                    original_name: "request_body".into(),
                    location: "body".into(),
                    explode: false,
                },
            );
        let limits = McpHttpConfig::default();
        let call = |body: Value, content_type: &'static str, grant: bool| {
            let (origin, post, limits, destination) =
                (origin.clone(), post.clone(), limits.clone(), destination.clone());
            async move {
                let progress = crate::mcp_proxies::handlers::TransitCallProgress::default();
                let answer = call_through_transit_point(
                    &origin,
                    &post,
                    None,
                    &json!({"request_body": body}),
                    &HeaderMap::new(),
                    &limits,
                    content_type,
                    grant.then_some(&destination),
                    Some(origin.as_str()),
                    &progress,
                )
                .await;
                (answer, progress.sent())
            }
        };
        for (body, content_type) in [
            (json!({"name": "a", "_method": "DELETE"}), "application/x-www-form-urlencoded"),
            (json!({"name": "a", "_METHOD": "DELETE"}), "application/json"),
            (json!({"X-HTTP-Method-Override": "DELETE"}), "application/json"),
        ] {
            let answer = call(body.clone(), content_type, true).await;
            assert!(matches!(answer, (Err(RestError::MethodOverride), false)), "{body} as {content_type}: {answer:?}");
        }
        assert!(vendor.requests().is_empty(), "{:?}", vendor.requests());
        let (sent, went_out) = call(json!({"name": "a", "method": "x"}), "application/json", true).await;
        assert!(sent.is_ok() && went_out, "another key is sent");
        let (sent, went_out) = call(json!({"_method": "DELETE"}), "application/json", false).await;
        assert!(sent.is_ok() && went_out, "without a grant, nothing is checked");
    }
}
