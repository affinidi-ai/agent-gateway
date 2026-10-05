//! `{{path.to.field}}` template resolver for Trust Check element queries.
//!
//! Trust Check reuses the OPA `input.*` keyspace through
//! a minimal `{{dotted.path}}` substitution. The resolver runs over each
//! field of `TrqpQueryParams` before TRQP dispatch; an unresolved or
//! non-scalar reference short-circuits the element to
//! `{ ok: false, error: Some(TEMPLATE_RESOLUTION_FAILED) }` without firing a
//! network call.
//!
//! Scope, v1:
//! - Dotted paths (`{{input.caller.did}}`) plus quoted object keys for
//!   metadata namespaces (`{{ input.a2a.message.metadata["https://example/v1"].tenant_id }}`).
//! - Scalar values only (string/number/bool); object/array/null → error.
//! - No escape sequence — a literal `{{` cannot be expressed.
//! - Whitespace inside the braces is tolerated (`{{ input.caller.did }}`).
//! - Multiple substitutions in a single template are supported.
//! - A single marker may chain alternative paths with `||`:
//!   `{{ input.agent.did || input.extension_identity.did }}` resolves to
//!   the first branch that yields a scalar. Only a missing/null leaf
//!   (`Unresolved`) falls through to the next branch; a `NonScalar` or
//!   `Malformed` branch short-circuits so a real misconfiguration still
//!   surfaces as `TEMPLATE_RESOLUTION_FAILED` instead of being silently
//!   swallowed by a downstream fallback.

use serde_json::Value;
use thiserror::Error;

/// Reasons a template string could not be resolved against a context.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TemplateError {
    /// The template string is syntactically invalid (unclosed `{{`, empty
    /// path, empty path segment, …).
    #[error("malformed template: {reason}")]
    Malformed { reason: String },

    /// A `{{path}}` references a value not present in the context, or the
    /// value at that path is JSON `null`.
    #[error("template path not found in context: {path}")]
    Unresolved { path: String },

    /// A `{{path}}` resolves to an object or array; only scalar values can
    /// be substituted into a query parameter.
    #[error("template path resolved to non-scalar value: {path}")]
    NonScalar { path: String },
}

/// Resolve every `{{dotted.path}}` substitution marker in `template`
/// against `ctx`. Literal text is copied through unchanged.
///
/// Returns the fully substituted string on success. On the first
/// unresolvable / non-scalar / malformed marker the function short-circuits
/// with the corresponding [`TemplateError`].
pub fn resolve(
    template: &str,
    ctx: &Value,
) -> Result<String, TemplateError> {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            let start = i + 2;
            let end = find_close(template, start)?;
            let raw = &template[start..end];
            let body = raw.trim();
            if body.is_empty() {
                return Err(TemplateError::Malformed {
                    reason: "empty path between '{{' and '}}'".to_string(),
                });
            }
            let resolved = resolve_marker(body, ctx)?;
            out.push_str(&resolved);
            i = end + 2;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }

    Ok(out)
}

/// Resolve a single `{{ … }}` marker body, honouring `||` fallback
/// between alternative paths. The body is split on `||`; each branch is
/// trimmed and resolved in order. Only an `Unresolved` outcome falls
/// through to the next branch; `NonScalar` and `Malformed` short-circuit.
/// If every branch is `Unresolved`, the original body (verbatim) is
/// returned as the `path` so the error log shows the operator-authored
/// chain rather than just the last branch.
fn resolve_marker(
    body: &str,
    ctx: &Value,
) -> Result<String, TemplateError> {
    let branches: Vec<&str> = body
        .split("||")
        .map(str::trim)
        .collect();
    for branch in &branches {
        if branch.is_empty() {
            return Err(TemplateError::Malformed {
                reason: format!("empty branch in fallback chain '{}'", body),
            });
        }
    }
    if branches.len() == 1 {
        return resolve_path(branches[0], ctx);
    }
    for branch in &branches {
        match resolve_path(branch, ctx) {
            Ok(value) => return Ok(value),
            Err(TemplateError::Unresolved { .. }) => continue,
            Err(other) => return Err(other),
        }
    }
    Err(TemplateError::Unresolved { path: body.to_string() })
}

/// Locate the byte index of the `}}` closer for a `{{` that opened at
/// `start - 2`. Returns the index of the first `}` in the pair.
fn find_close(
    template: &str,
    start: usize,
) -> Result<usize, TemplateError> {
    let bytes = template.as_bytes();
    let mut i = start;
    while i + 1 < bytes.len() {
        if bytes[i] == b'}' && bytes[i + 1] == b'}' {
            return Ok(i);
        }
        if bytes[i] == b'{' && bytes[i + 1] == b'{' {
            return Err(TemplateError::Malformed {
                reason: "nested '{{' before matching '}}'".to_string(),
            });
        }
        i += 1;
    }
    Err(TemplateError::Malformed {
        reason: "unclosed '{{' marker".to_string(),
    })
}

/// Walk a dotted/bracketed object path against `ctx` and stringify the leaf scalar.
fn resolve_path(
    path: &str,
    ctx: &Value,
) -> Result<String, TemplateError> {
    let segments = parse_path_segments(path)?;
    let mut node = ctx;
    for segment in segments {
        match node {
            Value::Object(map) => match map.get(&segment) {
                Some(next) => node = next,
                None => {
                    return Err(TemplateError::Unresolved { path: path.to_string() });
                }
            },
            _ => {
                return Err(TemplateError::Unresolved { path: path.to_string() });
            }
        }
    }

    match node {
        Value::Null => Err(TemplateError::Unresolved { path: path.to_string() }),
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Array(_) | Value::Object(_) => Err(TemplateError::NonScalar { path: path.to_string() }),
    }
}

fn parse_path_segments(path: &str) -> Result<Vec<String>, TemplateError> {
    let chars: Vec<char> = path.chars().collect();
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '.' => {
                if current.is_empty() {
                    return Err(TemplateError::Malformed {
                        reason: format!("empty segment in path '{}'", path),
                    });
                }
                segments.push(std::mem::take(&mut current));
                i += 1;
            }
            '[' => {
                if !current.is_empty() {
                    segments.push(std::mem::take(&mut current));
                }
                i += 1;
                let Some(quote) = chars
                    .get(i)
                    .copied()
                    .filter(|c| *c == '\'' || *c == '"')
                else {
                    return Err(TemplateError::Malformed {
                        reason: format!("bracket segment in path '{}' must start with a quote", path),
                    });
                };
                i += 1;
                let mut segment = String::new();
                while i < chars.len() && chars[i] != quote {
                    segment.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err(TemplateError::Malformed {
                        reason: format!("unclosed quoted bracket segment in path '{}'", path),
                    });
                }
                i += 1;
                if chars.get(i) != Some(&']') {
                    return Err(TemplateError::Malformed {
                        reason: format!("bracket segment in path '{}' must close with ']'", path),
                    });
                }
                if segment.is_empty() {
                    return Err(TemplateError::Malformed {
                        reason: format!("empty bracket segment in path '{}'", path),
                    });
                }
                segments.push(segment);
                i += 1;
                if i < chars.len() && chars[i] == '.' {
                    i += 1;
                }
            }
            c => {
                current.push(c);
                i += 1;
            }
        }
    }

    if !current.is_empty() {
        segments.push(current);
    }
    if segments.is_empty()
        || segments
            .iter()
            .any(|segment| segment.is_empty())
    {
        return Err(TemplateError::Malformed {
            reason: format!("empty segment in path '{}'", path),
        });
    }
    Ok(segments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> Value {
        json!({
            "input": {
                "caller":  { "did": "did:web:caller", "auth_method": "did_auth" },
                "target":  { "did": "did:web:target" },
                "http":    { "path": "/v1/items/42", "method": "POST" },
                "request": { "count": 7, "secure": true, "trailing_null": null },
                "extension": { "object_field": { "k": "v" } },
                "a2a": {
                    "message": {
                        "metadata": {
                            "https://fabric.affinidi.io/extensions/header-metadata/v1": {
                                "tenant_id": "tenant-456"
                            }
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn plain_literal_passes_through_unchanged() {
        assert_eq!(resolve("invoke", &ctx()).unwrap(), "invoke");
        assert_eq!(resolve("", &ctx()).unwrap(), "");
        assert_eq!(resolve("no markers here {single brace}", &ctx()).unwrap(), "no markers here {single brace}");
    }

    #[test]
    fn single_substitution_pulls_string_without_quotes() {
        assert_eq!(resolve("{{input.caller.did}}", &ctx()).unwrap(), "did:web:caller");
    }

    #[test]
    fn whitespace_inside_markers_is_trimmed() {
        assert_eq!(resolve("{{  input.caller.did  }}", &ctx()).unwrap(), "did:web:caller");
    }

    #[test]
    fn multiple_substitutions_in_one_template() {
        let out = resolve("{{input.http.method}} {{input.http.path}} for {{input.caller.did}}", &ctx()).unwrap();
        assert_eq!(out, "POST /v1/items/42 for did:web:caller");
    }

    #[test]
    fn bracket_quoted_segments_allow_uri_metadata_keys() {
        assert_eq!(
            resolve(
                "{{ input.a2a.message.metadata[\"https://fabric.affinidi.io/extensions/header-metadata/v1\"].tenant_id }}",
                &ctx(),
            )
            .unwrap(),
            "tenant-456"
        );
    }

    #[test]
    fn number_and_bool_scalars_are_stringified() {
        assert_eq!(resolve("{{input.request.count}}", &ctx()).unwrap(), "7");
        assert_eq!(resolve("{{input.request.secure}}", &ctx()).unwrap(), "true");
    }

    #[test]
    fn missing_path_is_unresolved() {
        let err = resolve("{{input.caller.unknown}}", &ctx()).unwrap_err();
        assert_eq!(
            err,
            TemplateError::Unresolved {
                path: "input.caller.unknown".to_string()
            }
        );
    }

    #[test]
    fn null_leaf_is_unresolved() {
        let err = resolve("{{input.request.trailing_null}}", &ctx()).unwrap_err();
        assert!(matches!(err, TemplateError::Unresolved { .. }));
    }

    #[test]
    fn descending_through_non_object_is_unresolved() {
        let err = resolve("{{input.caller.did.length}}", &ctx()).unwrap_err();
        assert!(matches!(err, TemplateError::Unresolved { .. }));
    }

    #[test]
    fn object_leaf_is_non_scalar() {
        let err = resolve("{{input.extension.object_field}}", &ctx()).unwrap_err();
        assert_eq!(
            err,
            TemplateError::NonScalar {
                path: "input.extension.object_field".to_string()
            }
        );
    }

    #[test]
    fn unclosed_marker_is_malformed() {
        let err = resolve("prefix {{input.caller.did suffix", &ctx()).unwrap_err();
        assert!(matches!(err, TemplateError::Malformed { .. }));
    }

    #[test]
    fn empty_path_is_malformed() {
        assert!(matches!(resolve("{{}}", &ctx()).unwrap_err(), TemplateError::Malformed { .. }));
        assert!(matches!(resolve("{{   }}", &ctx()).unwrap_err(), TemplateError::Malformed { .. }));
    }

    #[test]
    fn empty_path_segment_is_malformed() {
        assert!(matches!(resolve("{{input..did}}", &ctx()).unwrap_err(), TemplateError::Malformed { .. }));
    }

    #[test]
    fn nested_open_marker_is_malformed() {
        assert!(matches!(resolve("{{ {{input.caller.did}} }}", &ctx()).unwrap_err(), TemplateError::Malformed { .. }));
    }

    #[test]
    fn first_failure_short_circuits() {
        let err = resolve("{{input.caller.did}} {{input.missing}} {{input.target.did}}", &ctx()).unwrap_err();
        assert_eq!(
            err,
            TemplateError::Unresolved {
                path: "input.missing".to_string()
            }
        );
    }

    #[test]
    fn fallback_uses_first_resolvable_branch() {
        assert_eq!(resolve("{{ input.caller.did || input.target.did }}", &ctx()).unwrap(), "did:web:caller");
    }

    #[test]
    fn fallback_skips_unresolved_first_branch() {
        assert_eq!(resolve("{{ input.missing || input.target.did }}", &ctx()).unwrap(), "did:web:target");
    }

    #[test]
    fn fallback_skips_null_leaf() {
        assert_eq!(resolve("{{ input.request.trailing_null || input.caller.did }}", &ctx()).unwrap(), "did:web:caller");
    }

    #[test]
    fn fallback_all_unresolved_surfaces_original_chain() {
        let err = resolve("{{ input.missing.a || input.also.missing }}", &ctx()).unwrap_err();
        assert_eq!(
            err,
            TemplateError::Unresolved {
                path: "input.missing.a || input.also.missing".to_string()
            }
        );
    }

    #[test]
    fn fallback_non_scalar_short_circuits_not_skipped() {
        let err = resolve("{{ input.extension.object_field || input.caller.did }}", &ctx()).unwrap_err();
        assert_eq!(
            err,
            TemplateError::NonScalar {
                path: "input.extension.object_field".to_string()
            }
        );
    }

    #[test]
    fn fallback_empty_branch_is_malformed() {
        assert!(matches!(resolve("{{ input.caller.did || }}", &ctx()).unwrap_err(), TemplateError::Malformed { .. }));
        assert!(matches!(resolve("{{ || input.caller.did }}", &ctx()).unwrap_err(), TemplateError::Malformed { .. }));
    }

    #[test]
    fn fallback_three_branches_picks_last_resolvable() {
        assert_eq!(
            resolve("{{ input.missing || input.also.missing || input.caller.did }}", &ctx()).unwrap(),
            "did:web:caller"
        );
    }
}
