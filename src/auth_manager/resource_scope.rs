use std::collections::{HashMap, HashSet};
use std::sync::{Arc, LazyLock};

use axum::http::HeaderMap;
use dashmap::DashMap;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

pub const MAX_PATTERN_LEN: usize = 512;
pub const MAX_HEADER_PATTERN_LEN: usize = 256;
pub const MAX_HEADER_NAME_LEN: usize = 64;
pub const MAX_HEADER_VALUE_LEN: usize = 512;
pub const MAX_REQUIRED_HEADERS: usize = 8;
const MAX_EFFECTIVE_CACHE: usize = 512;
const REGEX_SIZE_LIMIT: usize = 1 << 20;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequiredHeader {
    pub name: String,
    pub pattern: String,
}

/// Classification of a PAT's tenant-selector header pattern.
///
/// A tenant selector is *single-valued* only when its validation regex admits
/// exactly one matchable value (an exact literal). Such a token is bound to one
/// tenant regardless of what the caller sends. Anything else — `\d+`, `.*`,
/// `[a-z0-9-]+`, `\d{12}`, `alpha|beta`, or a pattern we cannot prove
/// single-valued — is *broad*: the bearer picks the tenant per request via the
/// header, so it is only safe behind a trusted, header-stripping edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSelector {
    /// Display name of the header that supplies the tenant id.
    pub header_name: String,
    /// True when the selector admits more than one value (fail-closed default).
    pub broad: bool,
}

/// Classify a raw tenant-selector regex as single-valued (exact literal) vs
/// broad (multi-valued). **Fails closed:** anything not *provably* a single
/// exact literal is treated as broad.
///
/// Uses `regex-syntax` HIR literal extraction: the pattern is parsed to HIR and
/// run through `hir::literal::Extractor`. A sequence of exactly one exact
/// literal ⇒ single-valued; an inexact literal, more than one literal, an
/// unbounded/None sequence, or a parse error ⇒ broad.
///
/// The extractor's default `limit_literal_len` is 100 bytes (regex-syntax
/// 0.8.11): past that length it truncates the literal to an *inexact* one,
/// which would misclassify a genuine single exact literal as broad. Raised to
/// `MAX_HEADER_PATTERN_LEN` — the largest a raw header pattern (and thus any
/// literal extracted from it) can possibly be — so every literal this
/// classifier is ever asked to judge is extracted whole.
pub fn selector_is_broad(raw_pattern: &str) -> bool {
    use regex_syntax::hir::literal::Extractor;

    // An empty/degenerate pattern is not a genuine tenant literal, even though
    // it parses to a single exact (empty) literal — fail closed as broad.
    if raw_pattern.trim().is_empty() {
        return true;
    }

    let Ok(hir) = regex_syntax::parse(raw_pattern) else {
        // Unparseable here means the compiled anchored form would also have
        // been rejected, but classify defensively as broad regardless.
        return true;
    };
    let seq = Extractor::new()
        .limit_literal_len(MAX_HEADER_PATTERN_LEN)
        .extract(&hir);
    match seq.literals() {
        // Exactly one literal that represents the complete match ⇒ the anchored
        // header regex accepts exactly one value ⇒ single-valued / bindable.
        // An empty literal is degenerate, not a genuine tenant id ⇒ broad.
        Some([only]) => !only.is_exact() || only.as_bytes().is_empty(),
        // Zero, many, or an unbounded sequence ⇒ broad.
        _ => true,
    }
}

static PLACEHOLDER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{([A-Za-z0-9_-]+)\}").expect("valid placeholder regex"));

#[derive(Debug, Clone)]
enum Segment {
    Literal(String),
    Placeholder(String),
}

struct HeaderValidator {
    name_lower: String,
    display_name: String,
    regex: Regex,
}

pub struct CompiledResourceScope {
    has_pattern: bool,
    segments: Vec<Segment>,
    validators: Vec<HeaderValidator>,
    tenant_header_index: Option<usize>,
    tenant_selector: Option<TenantSelector>,
    cache: DashMap<Vec<String>, Arc<Regex>>,
}

pub struct ScopeEvaluation {
    pub pattern: Option<Arc<Regex>>,
    pub tenant_id: Option<String>,
}

#[derive(Debug)]
pub enum ScopeRejection {
    MissingHeader(String),
    InvalidHeader(String),
    Internal,
}

impl ScopeRejection {
    pub fn message(&self) -> String {
        match self {
            ScopeRejection::MissingHeader(header) | ScopeRejection::InvalidHeader(header) => {
                format!("required header '{header}' is missing or invalid")
            }
            ScopeRejection::Internal => "resource scope could not be evaluated".into(),
        }
    }
}

fn compile_anchored(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(&format!(r"\A(?:{pattern})\z"))
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|error| error.to_string())
}

fn validate_header_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_HEADER_NAME_LEN {
        return Err(format!("header name '{name}' has an invalid length (1..={MAX_HEADER_NAME_LEN})"));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(format!("header name '{name}' has invalid characters (allowed: A-Z a-z 0-9 -)"));
    }
    Ok(())
}

fn parse_segments(template: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut last = 0;
    for captures in PLACEHOLDER_RE.captures_iter(template) {
        let whole = captures
            .get(0)
            .expect("placeholder match");
        if whole.start() > last {
            segments.push(Segment::Literal(template[last..whole.start()].into()));
        }
        segments.push(Segment::Placeholder(
            captures
                .get(1)
                .expect("placeholder name")
                .as_str()
                .to_ascii_lowercase(),
        ));
        last = whole.end();
    }
    if last < template.len() {
        segments.push(Segment::Literal(template[last..].into()));
    }
    segments
}

fn build_effective(
    segments: &[Segment],
    values: &HashMap<String, String>,
) -> String {
    let mut output = String::new();
    for segment in segments {
        match segment {
            Segment::Literal(value) => output.push_str(value),
            Segment::Placeholder(name) => {
                if let Some(value) = values.get(name) {
                    output.push_str(&regex::escape(value));
                }
            }
        }
    }
    output
}

fn split_top_level_alternatives(selector: &str) -> Vec<&str> {
    let mut alternatives = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    let mut in_class = false;
    let mut escaped = false;

    for (index, character) in selector.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '(' if !in_class => depth += 1,
            ')' if !in_class => depth = depth.saturating_sub(1),
            '|' if !in_class && depth == 0 => {
                alternatives.push(&selector[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    alternatives.push(&selector[start..]);
    alternatives
}

fn outer_noncapturing_group(selector: &str) -> Option<&str> {
    if !selector.starts_with("(?:") {
        return None;
    }
    let mut depth = 0usize;
    let mut in_class = false;
    let mut escaped = false;

    for (index, character) in selector.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '(' if !in_class => depth += 1,
            ')' if !in_class => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return (index + character.len_utf8() == selector.len()).then_some(&selector[3..index]);
                }
            }
            _ => {}
        }
    }
    None
}

fn branch_has_known_resource_kind(branch: &str) -> bool {
    let Some((kind, _resource_pattern)) = branch.split_once(':') else {
        return false;
    };
    crate::tenancy::ResourceKind::from_path_family(kind).is_some_and(|parsed| parsed.as_str() == kind)
}

fn validate_canonical_resource_pattern(segments: &[Segment]) -> Result<(), String> {
    let selector = match segments {
        [Segment::Literal(prefix), Segment::Placeholder(_), Segment::Literal(suffix)]
            if prefix == "TENANT:" && suffix.starts_with(':') =>
        {
            &suffix[1..]
        }
        _ => {
            return Err("non-empty resource pattern must use TENANT:${header}:<resource-kind>:<resource-id-pattern>"
                .to_string());
        }
    };
    if selector.is_empty() {
        return Err("resource pattern must include a bounded resource selector".to_string());
    }

    let alternatives = if let Some(body) = outer_noncapturing_group(selector) {
        split_top_level_alternatives(body)
    } else {
        let alternatives = split_top_level_alternatives(selector);
        if alternatives.len() != 1 {
            return Err("multiple resource selectors must be wrapped in a single noncapturing group".to_string());
        }
        alternatives
    };
    if alternatives
        .iter()
        .any(|branch| branch.is_empty() || !branch_has_known_resource_kind(branch))
    {
        return Err("every resource selector must start with a known resource kind followed by ':'".to_string());
    }
    Ok(())
}

pub fn compile(
    pattern: Option<&str>,
    headers: &[RequiredHeader],
) -> Result<CompiledResourceScope, String> {
    if headers.len() > MAX_REQUIRED_HEADERS {
        return Err(format!("too many required headers (max {MAX_REQUIRED_HEADERS})"));
    }

    let mut validators = Vec::with_capacity(headers.len());
    let mut seen = HashSet::new();
    for header in headers {
        let name = header.name.trim();
        validate_header_name(name)?;
        let name_lower = name.to_ascii_lowercase();
        if !seen.insert(name_lower.clone()) {
            return Err(format!("duplicate required header '{name}'"));
        }
        if header.pattern.is_empty() {
            return Err(format!("required header '{name}' must declare a validation pattern"));
        }
        if header.pattern.len() > MAX_HEADER_PATTERN_LEN {
            return Err(format!("required header '{name}' pattern is too long (max {MAX_HEADER_PATTERN_LEN})"));
        }
        let regex = compile_anchored(&header.pattern)
            .map_err(|error| format!("required header '{name}' has an invalid pattern: {error}"))?;
        validators.push(HeaderValidator {
            name_lower,
            display_name: name.into(),
            regex,
        });
    }

    let (has_pattern, segments, tenant_header_index) = match pattern.map(str::trim) {
        Some(pattern) if !pattern.is_empty() => {
            if pattern.len() > MAX_PATTERN_LEN {
                return Err(format!("resource pattern is too long (max {MAX_PATTERN_LEN})"));
            }
            let segments = parse_segments(pattern);
            let placeholders: HashSet<_> = segments
                .iter()
                .filter_map(|segment| match segment {
                    Segment::Placeholder(name) => Some(name.clone()),
                    Segment::Literal(_) => None,
                })
                .collect();
            for placeholder in &placeholders {
                if !validators
                    .iter()
                    .any(|validator| &validator.name_lower == placeholder)
                {
                    return Err(format!("resource pattern references undeclared header '${{{placeholder}}}'"));
                }
            }
            if placeholders.len() > 1 {
                return Err("resource pattern may reference at most one distinct header for tenant selection".into());
            }
            let sample = validators
                .iter()
                .map(|validator| (validator.name_lower.clone(), "x".into()))
                .collect();
            compile_anchored(&build_effective(&segments, &sample))
                .map_err(|error| format!("invalid resource pattern: {error}"))?;
            validate_canonical_resource_pattern(&segments)?;
            let tenant_header_index = placeholders
                .iter()
                .next()
                .and_then(|placeholder| {
                    validators
                        .iter()
                        .position(|validator| &validator.name_lower == placeholder)
                });
            (true, segments, tenant_header_index)
        }
        _ => (false, Vec::new(), None),
    };

    // Classify the tenant selector once, on the raw header pattern, at compile
    // time (issue *and* auth both funnel through here). `validators` is 1:1 and
    // in order with `headers`, so the index aligns with the raw pattern.
    let tenant_selector = tenant_header_index.map(|index| TenantSelector {
        header_name: validators[index]
            .display_name
            .clone(),
        broad: selector_is_broad(&headers[index].pattern),
    });

    Ok(CompiledResourceScope {
        has_pattern,
        segments,
        validators,
        tenant_header_index,
        tenant_selector,
        cache: DashMap::new(),
    })
}

impl CompiledResourceScope {
    /// The tenant selector classification for this scope, or `None` when the
    /// scope selects no tenant (blank pattern / no placeholder).
    pub fn tenant_selector(&self) -> Option<&TenantSelector> {
        self.tenant_selector.as_ref()
    }

    pub fn evaluate(
        &self,
        headers: &HeaderMap,
    ) -> Result<ScopeEvaluation, ScopeRejection> {
        let mut key = Vec::with_capacity(self.validators.len());
        for validator in &self.validators {
            let mut present = headers
                .get_all(validator.name_lower.as_str())
                .iter();
            let Some(raw) = present.next() else {
                return Err(ScopeRejection::MissingHeader(validator.display_name.clone()));
            };
            if present.next().is_some() {
                return Err(ScopeRejection::InvalidHeader(validator.display_name.clone()));
            }
            let value = raw
                .to_str()
                .map_err(|_| ScopeRejection::InvalidHeader(validator.display_name.clone()))?;
            if value.len() > MAX_HEADER_VALUE_LEN
                || !validator
                    .regex
                    .is_match(value)
            {
                return Err(ScopeRejection::InvalidHeader(validator.display_name.clone()));
            }
            if self.has_pattern {
                key.push(value.to_string());
            }
        }

        if !self.has_pattern {
            return Ok(ScopeEvaluation { pattern: None, tenant_id: None });
        }
        let tenant_id = self
            .tenant_header_index
            .and_then(|index| key.get(index).cloned());
        if let Some(existing) = self.cache.get(&key) {
            return Ok(ScopeEvaluation {
                pattern: Some(existing.clone()),
                tenant_id,
            });
        }
        let values = self
            .validators
            .iter()
            .map(|validator| validator.name_lower.clone())
            .zip(key.iter().cloned())
            .collect();
        let effective = build_effective(&self.segments, &values);
        let regex = Arc::new(compile_anchored(&effective).map_err(|_| ScopeRejection::Internal)?);
        if self.cache.len() < MAX_EFFECTIVE_CACHE {
            self.cache
                .insert(key, regex.clone());
        }
        Ok(ScopeEvaluation {
            pattern: Some(regex),
            tenant_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn header(
        name: &str,
        pattern: &str,
    ) -> RequiredHeader {
        RequiredHeader {
            name: name.into(),
            pattern: pattern.into(),
        }
    }

    fn headers(values: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in values {
            headers.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn interpolates_validated_header_and_anchors_scope() {
        let scope =
            compile(Some("TENANT:${x-external-account}:gateways:.*"), &[header("x-external-account", r"\d{12}")])
                .unwrap();
        let regex = scope
            .evaluate(&headers(&[("x-external-account", "123456789012")]))
            .unwrap()
            .pattern
            .unwrap();
        assert!(regex.is_match("TENANT:123456789012:gateways:gateway-1"));
        assert!(!regex.is_match("TENANT:999999999999:gateways:gateway-1"));
        assert!(!regex.is_match("EVIL:TENANT:123456789012:gateways:gateway-1"));
    }

    #[test]
    fn rejects_missing_invalid_and_ambiguous_headers() {
        let scope = compile(Some("TENANT:${account}:gateways:.*"), &[header("account", r"\d+")]).unwrap();
        assert!(matches!(scope.evaluate(&HeaderMap::new()), Err(ScopeRejection::MissingHeader(_))));
        assert!(matches!(scope.evaluate(&headers(&[("account", "abc")])), Err(ScopeRejection::InvalidHeader(_))));
        assert!(matches!(
            scope.evaluate(&headers(&[("account", "1"), ("account", "2")])),
            Err(ScopeRejection::InvalidHeader(_))
        ));
    }

    #[test]
    fn escapes_header_values_and_enforces_header_only_gates() {
        let scoped = compile(Some("TENANT:${account}:secrets:.*"), &[header("account", r".+")]).unwrap();
        let regex = scoped
            .evaluate(&headers(&[("account", ".*")]))
            .unwrap()
            .pattern
            .unwrap();
        assert!(regex.is_match("TENANT:.*:secrets:item"));
        assert!(!regex.is_match("TENANT:anything:secrets:item"));

        let gate = compile(None, &[header("account", r"\d+")]).unwrap();
        assert!(
            gate.evaluate(&headers(&[("account", "12")]))
                .unwrap()
                .pattern
                .is_none()
        );
        assert!(
            gate.evaluate(&HeaderMap::new())
                .is_err()
        );
    }

    #[test]
    fn infers_one_distinct_placeholder_and_rejects_multiple() {
        let scope = compile(Some("TENANT:${Account}:gateways:.*"), &[header("account", r"[a-z0-9-]+")]).unwrap();
        let evaluation = scope
            .evaluate(&headers(&[("account", "tenant-a")]))
            .unwrap();
        assert_eq!(
            evaluation
                .tenant_id
                .as_deref(),
            Some("tenant-a")
        );

        let error = compile(
            Some("TENANT:${account}:${environment}:.*"),
            &[header("account", r"[a-z0-9-]+"), header("environment", r"[a-z]+")],
        )
        .err()
        .unwrap();
        assert!(error.contains("at most one distinct header"));
    }

    #[test]
    fn classifies_exact_literal_selector_as_single_valued() {
        // A concrete tenant id: exactly one matchable value ⇒ bindable.
        assert!(!selector_is_broad("123456789012"));
        assert!(!selector_is_broad("tenant-a"));
        // Escaped metacharacters still describe a single literal value.
        assert!(!selector_is_broad(r"tenant\.a"));
        // A redundant single-branch group is still one literal.
        assert!(!selector_is_broad("(?:tenant-a)"));
    }

    #[test]
    fn classifies_multi_valued_selectors_as_broad_failing_closed() {
        for pattern in [
            r"\d+",
            r"\d{12}",
            "[a-z0-9-]+",
            ".*",
            ".+",
            "alpha|beta",
            r"tenant-\d+",
            "(?i)tenant-a",
            "a?",
            "", // empty / unparseable-as-single-value ⇒ broad
        ] {
            assert!(selector_is_broad(pattern), "pattern should be broad: {pattern:?}");
        }
    }

    #[test]
    fn classifies_long_exact_literal_as_single_valued_past_extractor_default_limit() {
        // regex-syntax's `Extractor` truncates literals past its default
        // `limit_literal_len` of 100 bytes into an *inexact* literal, which
        // would misclassify a genuine single exact literal as broad. Both the
        // largest allowed tenant id (128 ASCII chars, `validate_tenant_id`) and
        // the largest allowed header pattern (`MAX_HEADER_PATTERN_LEN`) must
        // still classify as single-valued.
        let exactly_at_default_limit = "a".repeat(100);
        let past_default_limit = "a".repeat(101);
        let max_tenant_id_len = "a".repeat(128);

        assert!(!selector_is_broad(&exactly_at_default_limit));
        assert!(!selector_is_broad(&past_default_limit));
        assert!(!selector_is_broad(&max_tenant_id_len));
    }

    #[test]
    fn duplicate_branches_resolving_to_the_same_literal_are_not_broad() {
        // An alternation whose every branch is the identical literal still
        // admits exactly one value — this is not the multi-valued case an
        // alternation like `alpha|beta` represents.
        assert!(!selector_is_broad("tenant-a|tenant-a"));
    }

    #[test]
    fn compiled_scope_exposes_tenant_selector_classification() {
        let exact =
            compile(Some("TENANT:${x-external-account}:gateways:.*"), &[header("x-external-account", "123456789012")])
                .unwrap();
        let selector = exact
            .tenant_selector()
            .expect("tenant selector present");
        assert_eq!(selector.header_name, "x-external-account");
        assert!(!selector.broad);

        let broad = compile(Some("TENANT:${account}:gateways:.*"), &[header("account", "[a-z0-9-]+")]).unwrap();
        assert!(
            broad
                .tenant_selector()
                .expect("tenant selector present")
                .broad
        );

        // No placeholder ⇒ no tenant selector at all.
        let gate = compile(None, &[header("account", r"\d+")]).unwrap();
        assert!(
            gate.tenant_selector()
                .is_none()
        );
    }

    #[test]
    fn accepts_bounded_resource_alternatives_and_rejects_unconstrained_patterns() {
        let headers = [header("account", r"[a-z0-9-]+")];
        assert!(compile(Some("TENANT:${account}:(?:secrets:demo-.*|sts-clients:.*)"), &headers,).is_ok());
        assert!(compile(None, &[]).is_ok());

        for pattern in [
            ".*",
            "TENANT:.*",
            "TENANT:${account}:.*",
            "prod-.*",
            "TENANT:${account}:unknown-kind:.*",
            "TENANT:${account}:(?:secrets:.*|.*)",
            "TENANT:${account}:secrets:.*|sts-clients:.*",
            "TENANT:${account}:${account}:secrets:.*",
        ] {
            assert!(compile(Some(pattern), &headers).is_err(), "pattern should be rejected: {pattern}");
        }
    }
}
