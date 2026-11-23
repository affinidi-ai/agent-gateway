//! Compiles and evaluates the dashboard's built-in policy templates with the gateway's Regorus
//! setup, so a template the dashboard offers is one the gateway loads and decides as described.
//! The modules are the ones the dashboard renders, written by its `renderedTemplates.test.ts`.

use serde_json::{Map, Value, json};

const CATALOGUE: &str =
    include_str!("../../www/default/src/pages/SettingsPage/policyTemplates/builtinPolicyTemplates.json");

const RENDERED_PATH: &str = "www/default/src/pages/SettingsPage/policyTemplates/__fixtures__/renderedTemplates.json";
const RENDERED: &str =
    include_str!("../../www/default/src/pages/SettingsPage/policyTemplates/__fixtures__/renderedTemplates.json");

const NOW_NS_CALL: &str = "time.now_ns()";

fn catalogue() -> Vec<Value> {
    serde_json::from_str(CATALOGUE).expect("the template catalogue is a JSON array")
}

fn policy_types(template: &Value) -> Vec<&str> {
    template["policy_types"]
        .as_array()
        .expect("policy_types is a list")
        .iter()
        .map(|t| {
            t.as_str()
                .expect("a policy type is a string")
        })
        .collect()
}

fn package_for(policy_type: &str) -> &'static str {
    match policy_type {
        "gateway" => super::GATEWAY_POLICY_PACKAGE,
        "agent_surface" => super::SURFACE_POLICY_PACKAGE,
        other => panic!("unknown policy type {other}"),
    }
}

/// The modules the dashboard renders, keyed `<id>:<type>` for a template with its defaults and
/// `<id>:<variant>:<type>` for one with the settings its Jest test names.
fn rendered_templates() -> Map<String, Value> {
    serde_json::from_str(RENDERED).expect("the rendered templates are a JSON object")
}

fn rendered(key: &str) -> String {
    rendered_templates()
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("no rendered template {key}; regenerate {RENDERED_PATH}"))
        .to_string()
}

/// The gateway's decision for `rego` on `input`, compiled and queried as the gateway does for
/// a policy of `policy_type`.
fn decide(
    policy_type: &str,
    rego: &str,
    input: &Value,
) -> Result<bool, String> {
    match policy_type {
        "gateway" => {
            let mut engine = regorus::Engine::new();
            engine
                .add_policy("template".to_string(), rego.to_string())
                .map_err(|e| format!("compile: {e}"))?;
            engine
                .set_input_json(&input.to_string())
                .map_err(|e| format!("input: {e}"))?;
            engine
                .eval_bool_query(format!("data.{}.allow", super::GATEWAY_POLICY_PACKAGE), false)
                .map_err(|e| format!("evaluate: {e}"))
        }
        "agent_surface" => {
            let engine = super::opa::OpaEngine::new();
            engine.load_policy("template", rego)?;
            engine
                .evaluate_borrowed(input)
                .map(|decision| decision.allow)
        }
        other => panic!("unknown policy type {other}"),
    }
}

fn expected_allow(example: &Value) -> bool {
    match example["expected"].as_str() {
        Some("allow") => true,
        Some("deny") => false,
        other => panic!("example expects {other:?}"),
    }
}

#[test]
fn every_builtin_template_compiles_and_decides_its_examples() {
    let templates = catalogue();
    assert!(!templates.is_empty(), "the catalogue lists no templates");
    let mut failures = Vec::new();
    let mut checked = 0;
    for template in &templates {
        let id = template["id"]
            .as_str()
            .unwrap_or_default();
        for policy_type in policy_types(template) {
            let rego = rendered(&format!("{id}:{policy_type}"));
            for example in template["examples"]
                .as_array()
                .expect("examples is a list")
            {
                checked += 1;
                let name = example["name"]
                    .as_str()
                    .unwrap_or_default();
                match decide(policy_type, &rego, &example["input"]) {
                    Ok(allow) if allow == expected_allow(example) => {}
                    Ok(allow) => failures.push(format!("{id} ({policy_type}) {name}: allow was {allow}")),
                    Err(e) => failures.push(format!("{id} ({policy_type}) {name}: {e}")),
                }
            }
            if let Err(e) = decide(policy_type, &rego, &json!({})) {
                failures.push(format!("{id} ({policy_type}) on an empty input: {e}"));
            }
        }
    }
    assert!(failures.is_empty(), "templates disagree with their examples:\n{}", failures.join("\n"));
    assert!(checked > 0, "no template example was evaluated");
}

#[test]
fn every_catalogue_template_has_a_rendered_module_under_its_package() {
    let rendered = rendered_templates();
    let mut missing = Vec::new();
    for template in catalogue() {
        let id = template["id"]
            .as_str()
            .unwrap_or_default();
        for policy_type in policy_types(&template) {
            let key = format!("{id}:{policy_type}");
            match rendered
                .get(&key)
                .and_then(Value::as_str)
            {
                Some(rego) => assert!(
                    rego.starts_with(&format!("package {}\n\n", package_for(policy_type))),
                    "{key} is not under the {policy_type} package: {rego}"
                ),
                None => missing.push(key),
            }
        }
    }
    assert!(missing.is_empty(), "{RENDERED_PATH} has no module for {}; regenerate it", missing.join(", "));
}

#[test]
fn a_rendered_template_decides_only_under_its_own_package() {
    let rego = rendered("allow-http-methods:gateway");

    assert_eq!(decide("gateway", &rego, &json!({"http": {"method": "GET"}})), Ok(true));
    assert_eq!(decide("gateway", &rego, &json!({"http": {"method": "DELETE"}})), Ok(false));
    assert_eq!(decide("agent_surface", &rego, &json!({"http": {"method": "GET"}})), Ok(false));
}

/// Nanoseconds since the epoch of an RFC 3339 instant.
fn instant_ns(rfc3339: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .expect("an RFC 3339 instant")
        .timestamp_nanos_opt()
        .expect("an instant in range")
}

/// The business-hours template's decision at `instant`, rendered with the settings the Jest
/// test names `variant`, or with its defaults (Monday to Friday, 09:00 to 17:00, UTC, allow
/// inside) for `None`.
fn business_hours_allow(
    policy_type: &str,
    variant: Option<&str>,
    instant: &str,
) -> bool {
    let key = match variant {
        Some(variant) => format!("business-hours-access-window:{variant}:{policy_type}"),
        None => format!("business-hours-access-window:{policy_type}"),
    };
    let rego = rendered(&key);
    assert!(rego.contains(NOW_NS_CALL), "{key} no longer reads the clock: {rego}");
    let pinned = rego.replace(NOW_NS_CALL, &instant_ns(instant).to_string());
    decide(policy_type, &pinned, &json!({})).unwrap_or_else(|e| panic!("{key} at {instant}: {e}"))
}

#[test]
fn business_hours_test_instants_fall_on_the_named_days() {
    use chrono::{Datelike, Weekday};
    let weekday = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .weekday()
    };
    assert_eq!(weekday("2026-11-16T12:00:00Z"), Weekday::Mon);
    assert_eq!(weekday("2026-11-20T12:00:00Z"), Weekday::Fri);
    assert_eq!(weekday("2026-11-21T12:00:00Z"), Weekday::Sat);
    assert_eq!(weekday("2026-11-22T12:00:00Z"), Weekday::Sun);
    assert_eq!(weekday("2026-03-28T12:00:00Z"), Weekday::Sat);
    assert_eq!(weekday("2026-03-29T12:00:00Z"), Weekday::Sun);
}

#[test]
fn business_hours_same_day_window_includes_its_start_and_excludes_its_end() {
    for policy_type in ["gateway", "agent_surface"] {
        let at = |instant| business_hours_allow(policy_type, None, instant);
        assert!(!at("2026-11-16T08:59:59Z"), "{policy_type}: Monday before the window");
        assert!(at("2026-11-16T09:00:00Z"), "{policy_type}: Monday at the start");
        assert!(at("2026-11-16T16:59:59Z"), "{policy_type}: Monday before the end");
        assert!(!at("2026-11-16T17:00:00Z"), "{policy_type}: Monday at the end");
        assert!(at("2026-11-20T12:00:00Z"), "{policy_type}: Friday midday");
        assert!(!at("2026-11-21T12:00:00Z"), "{policy_type}: Saturday is not listed");
        assert!(!at("2026-11-22T12:00:00Z"), "{policy_type}: Sunday is not listed");
    }
}

#[test]
fn business_hours_overnight_window_spans_midnight_on_the_listed_dates() {
    let at = |instant| business_hours_allow("gateway", Some("overnight"), instant);
    assert!(!at("2026-11-16T12:00:00Z"), "Monday midday is outside");
    assert!(!at("2026-11-16T21:59:59Z"), "Monday before 22:00");
    assert!(at("2026-11-16T22:00:00Z"), "Monday at 22:00");
    assert!(at("2026-11-16T23:59:59Z"), "Monday before midnight");
    assert!(at("2026-11-17T00:00:00Z"), "Tuesday at midnight");
    assert!(at("2026-11-17T05:59:59Z"), "Tuesday before 06:00");
    assert!(!at("2026-11-17T06:00:00Z"), "Tuesday at 06:00");
    assert!(at("2026-11-20T23:00:00Z"), "Friday night");
    assert!(
        !at("2026-11-21T02:00:00Z"),
        "Saturday 02:00 is outside: a day is the request's date, and Saturday is not listed"
    );
    assert!(at("2026-11-16T02:00:00Z"), "Monday 02:00 is inside: its date is a listed day");
}

#[test]
fn business_hours_empty_days_list_means_every_day() {
    assert!(business_hours_allow("gateway", Some("every-day"), "2026-11-21T12:00:00Z"), "Saturday midday");
    assert!(business_hours_allow("agent_surface", Some("every-day"), "2026-11-22T09:00:00Z"), "Sunday at the start");
    assert!(!business_hours_allow("gateway", Some("every-day"), "2026-11-22T08:00:00Z"), "Sunday before the window");
    assert!(!business_hours_allow("gateway", Some("every-day"), "2026-11-22T17:00:00Z"), "Sunday at the end");
    assert!(business_hours_allow("gateway", Some("every-day-overnight"), "2026-11-22T03:00:00Z"), "Sunday night");
}

#[test]
fn business_hours_deny_mode_inverts_the_decision() {
    for policy_type in ["gateway", "agent_surface"] {
        let at = |instant| business_hours_allow(policy_type, Some("deny"), instant);
        assert!(!at("2026-11-16T09:00:00Z"), "{policy_type}: Monday at the start");
        assert!(!at("2026-11-16T16:59:59Z"), "{policy_type}: Monday before the end");
        assert!(at("2026-11-16T08:59:59Z"), "{policy_type}: Monday before the window");
        assert!(at("2026-11-16T17:00:00Z"), "{policy_type}: Monday at the end");
        assert!(at("2026-11-21T12:00:00Z"), "{policy_type}: Saturday is outside the window");
    }
    assert!(!business_hours_allow("gateway", Some("overnight-deny"), "2026-11-17T03:00:00Z"), "Tuesday night");
    assert!(business_hours_allow("gateway", Some("overnight-deny"), "2026-11-17T12:00:00Z"), "Tuesday midday");
}

#[test]
fn business_hours_never_allows_when_the_time_zone_cannot_be_read() {
    for policy_type in ["gateway", "agent_surface"] {
        for key in [
            format!("business-hours-access-window:{policy_type}"),
            format!("business-hours-access-window:deny:{policy_type}"),
        ] {
            let rego = rendered(&key).replace("\"UTC\"", "\"Mars/Olympus_Mons\"");
            let decision = decide(policy_type, &rego, &json!({}));
            assert!(decision != Ok(true), "{key} allowed a request whose time zone is unknown: {decision:?}");
        }
    }
}

#[test]
fn business_hours_access_minute_guard_denies_on_an_engine_that_reads_a_failed_builtin_as_undefined() {
    for variant in ["business-hours-access-window:gateway", "business-hours-access-window:deny:gateway"] {
        let rego = rendered(variant).replace("\"UTC\"", "\"Mars/Olympus_Mons\"");
        let mut engine = regorus::Engine::new();
        engine.set_strict_builtin_errors(false);
        engine
            .add_policy("template".to_string(), rego)
            .expect("compiles");
        engine
            .set_input_json("{}")
            .expect("input");
        let allow = engine
            .eval_bool_query(format!("data.{}.allow", super::GATEWAY_POLICY_PACKAGE), false)
            .expect("evaluates");
        assert!(!allow, "{variant} allowed a request whose time zone is unknown");
    }
}

#[test]
fn business_hours_follows_the_time_zone_across_a_daylight_saving_change() {
    let at = |instant| business_hours_allow("gateway", Some("weekend-berlin"), instant);
    assert!(!at("2026-03-28T07:59:59Z"), "Saturday 08:59:59 CET");
    assert!(at("2026-03-28T08:00:00Z"), "Saturday 09:00 CET");
    assert!(at("2026-03-28T15:59:59Z"), "Saturday 16:59:59 CET");
    assert!(!at("2026-03-28T16:00:00Z"), "Saturday 17:00 CET");
    assert!(!at("2026-03-29T06:59:59Z"), "Sunday 08:59:59 CEST");
    assert!(at("2026-03-29T07:00:00Z"), "Sunday 09:00 CEST, 08:00 in CET");
    assert!(at("2026-03-29T14:59:59Z"), "Sunday 16:59:59 CEST");
    assert!(!at("2026-03-29T15:00:00Z"), "Sunday 17:00 CEST, 16:00 in CET");
}

#[test]
fn business_hours_takes_the_day_from_the_time_zone() {
    let friday_night_utc = "2026-11-20T23:30:00Z";
    assert!(
        !business_hours_allow("gateway", Some("friday-first-hour-berlin"), friday_night_utc),
        "00:30 Saturday in Berlin"
    );
    assert!(
        business_hours_allow("gateway", Some("saturday-first-hour-berlin"), friday_night_utc),
        "00:30 Saturday in Berlin"
    );
}

#[test]
fn business_hours_decides_settings_as_typed() {
    let at = |instant| business_hours_allow("gateway", Some("typed-settings"), instant);
    assert!(!at("2026-11-21T21:00:00Z"), "Saturday 22:00 in Berlin, typed as \" saturday\"");
    assert!(!at("2026-11-22T05:29:59Z"), "Sunday 06:29:59 in Berlin, before Until typed as 6:30");
    assert!(at("2026-11-22T05:30:00Z"), "Sunday 06:30 in Berlin, Until typed as 6:30");
    assert!(at("2026-11-21T12:00:00Z"), "Saturday 13:00 in Berlin is outside the window");
    assert!(at("2026-11-20T21:00:00Z"), "Friday 22:00 in Berlin: Friday is not listed");
}
