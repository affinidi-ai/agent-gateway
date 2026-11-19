//! Compiles and evaluates the dashboard's built-in policy templates with the gateway's Regorus
//! setup, so a template the dashboard offers is one the gateway loads and decides as described.

use serde_json::{Map, Value, json};

const CATALOGUE: &str =
    include_str!("../../www/default/src/pages/SettingsPage/policyTemplates/builtinPolicyTemplates.json");

const NOW_NS_CALL: &str = "time.now_ns()";

fn catalogue() -> Vec<Value> {
    serde_json::from_str(CATALOGUE).expect("the template catalogue is a JSON array")
}

fn template(id: &str) -> Value {
    catalogue()
        .into_iter()
        .find(|t| t["id"] == id)
        .unwrap_or_else(|| panic!("no template {id} in the catalogue"))
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

/// The Rego literal for one parameter value, as `regoTemplate.ts` writes it.
fn rego_literal(
    param: &Value,
    value: &Value,
) -> String {
    let key = param["key"]
        .as_str()
        .unwrap_or_default();
    match param["kind"].as_str() {
        Some("integer") => {
            let n = value
                .as_i64()
                .unwrap_or_else(|| panic!("{key}: not a whole number: {value}"));
            assert!(param["min"].as_i64() <= Some(n) && Some(n) <= param["max"].as_i64(), "{key}: {n} out of range");
            n.to_string()
        }
        Some("string") => {
            let text = value
                .as_str()
                .map(str::trim)
                .unwrap_or_default();
            assert!(!text.is_empty(), "{key}: empty string");
            Value::from(text).to_string()
        }
        Some("choice") => param["options"]
            .as_array()
            .and_then(|options| {
                options
                    .iter()
                    .find(|o| o["value"] == *value)
            })
            .and_then(|o| o["rego"].as_str())
            .unwrap_or_else(|| panic!("{key}: {value} is not an option"))
            .to_string(),
        Some("time_of_day") => {
            let text = value
                .as_str()
                .unwrap_or_default()
                .trim();
            let (hours, minutes) = text
                .split_once(':')
                .and_then(|(h, m)| Some((h.parse::<u32>().ok()?, m.parse::<u32>().ok()?)))
                .filter(|(h, m)| *h < 24 && *m < 60)
                .unwrap_or_else(|| panic!("{key}: {value} is not HH:MM"));
            (hours * 60 + minutes).to_string()
        }
        Some("string_list") => {
            let allowed: Option<Vec<&str>> = param["allowed"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect()
                });
            let mut items: Vec<String> = Vec::new();
            for item in value
                .as_array()
                .unwrap_or_else(|| panic!("{key}: not a list"))
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|v| !v.is_empty())
            {
                let item = match &allowed {
                    Some(allowed) => allowed
                        .iter()
                        .find(|a| a.eq_ignore_ascii_case(item))
                        .unwrap_or_else(|| panic!("{key}: {item} is not accepted"))
                        .to_string(),
                    None => item.to_string(),
                };
                if !items.contains(&item) {
                    items.push(item);
                }
            }
            if items.is_empty() {
                assert!(param["optional"] == true, "{key}: needs at least one value");
                return "set()".to_string();
            }
            let literals: Vec<String> = items
                .into_iter()
                .map(|v| Value::from(v).to_string())
                .collect();
            format!("{{{}}}", literals.join(", "))
        }
        other => panic!("{key}: unknown parameter kind {other:?}"),
    }
}

/// The module the dashboard builds from a catalogue entry for `policy_type`, each parameter
/// taken from `overrides` or else its default.
fn render(
    template: &Value,
    policy_type: &str,
    overrides: &Map<String, Value>,
) -> String {
    let mut rules = template["rules"]
        .as_str()
        .expect("rules is a string")
        .to_string();
    for param in template["parameters"]
        .as_array()
        .expect("parameters is a list")
    {
        let key = param["key"]
            .as_str()
            .expect("a parameter has a key");
        let value = overrides
            .get(key)
            .unwrap_or(&param["default"]);
        rules = rules.replace(&format!("{{{{{key}}}}}"), &rego_literal(param, value));
    }
    assert!(!rules.contains("{{"), "{}: a placeholder has no parameter: {rules}", template["id"]);
    format!("package {}\n\n{rules}\n", package_for(policy_type))
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
            let rego = render(template, policy_type, &Map::new());
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
fn a_rendered_template_decides_only_under_its_own_package() {
    let template = template("allow-http-methods");
    let rego = render(&template, "gateway", &Map::new());

    assert_eq!(decide("gateway", &rego, &json!({"http": {"method": "GET"}})), Ok(true));
    assert_eq!(decide("gateway", &rego, &json!({"http": {"method": "DELETE"}})), Ok(false));
    assert_eq!(decide("agent_surface", &rego, &json!({"http": {"method": "GET"}})), Ok(false));
}

#[test]
fn rendering_writes_parameters_as_rego_literals() {
    let template = template("business-hours-access-window");
    let overrides = json!({
        "mode": "deny",
        "days": [" saturday", "Sunday", "SUNDAY"],
        "start_time": "22:00",
        "end_time": "6:30",
        "time_zone": " Europe/Berlin ",
    });
    let rego = render(&template, "gateway", overrides.as_object().unwrap());

    assert!(rego.starts_with("package gateway.policy\n\n"), "{rego}");
    assert!(rego.contains("allow if not in_access_window"), "{rego}");
    assert!(rego.contains("access_minute >= 1320"), "{rego}");
    assert!(rego.contains("access_minute < 390"), "{rego}");
    assert!(rego.contains("1320 > 390"), "{rego}");
    assert!(rego.contains(r#"in {"Saturday", "Sunday"}"#), "{rego}");
    assert!(rego.contains(r#"time.clock([time.now_ns(), "Europe/Berlin"])"#), "{rego}");

    let empty_days = render(
        &template,
        "gateway",
        json!({"days": []})
            .as_object()
            .unwrap(),
    );
    assert!(empty_days.contains("count(set()) == 0"), "{empty_days}");
}

/// Nanoseconds since the epoch of an RFC 3339 instant.
fn instant_ns(rfc3339: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .expect("an RFC 3339 instant")
        .timestamp_nanos_opt()
        .expect("an instant in range")
}

/// The business-hours template's decision at `instant`, with `settings` over the defaults
/// (Monday to Friday, 09:00 to 17:00, UTC, allow inside).
fn business_hours_allow(
    policy_type: &str,
    settings: Value,
    instant: &str,
) -> bool {
    let template = template("business-hours-access-window");
    let rego = render(
        &template,
        policy_type,
        settings
            .as_object()
            .expect("settings is an object"),
    );
    assert!(rego.contains(NOW_NS_CALL), "the template no longer reads the clock: {rego}");
    let pinned = rego.replace(NOW_NS_CALL, &instant_ns(instant).to_string());
    decide(policy_type, &pinned, &json!({})).unwrap_or_else(|e| panic!("{instant}: {e}"))
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
        let at = |instant| business_hours_allow(policy_type, json!({}), instant);
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
    let overnight = || json!({"start_time": "22:00", "end_time": "06:00"});
    let at = |instant| business_hours_allow("gateway", overnight(), instant);
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
    let every_day = || json!({"days": []});
    assert!(business_hours_allow("gateway", every_day(), "2026-11-21T12:00:00Z"), "Saturday midday");
    assert!(business_hours_allow("agent_surface", every_day(), "2026-11-22T09:00:00Z"), "Sunday at the start");
    assert!(!business_hours_allow("gateway", every_day(), "2026-11-22T08:00:00Z"), "Sunday before the window");
    assert!(!business_hours_allow("gateway", every_day(), "2026-11-22T17:00:00Z"), "Sunday at the end");
    let overnight_every_day = json!({"days": [], "start_time": "22:00", "end_time": "06:00"});
    assert!(business_hours_allow("gateway", overnight_every_day, "2026-11-22T03:00:00Z"), "Sunday night");
}

#[test]
fn business_hours_deny_mode_inverts_the_decision() {
    for policy_type in ["gateway", "agent_surface"] {
        let at = |instant| business_hours_allow(policy_type, json!({"mode": "deny"}), instant);
        assert!(!at("2026-11-16T09:00:00Z"), "{policy_type}: Monday at the start");
        assert!(!at("2026-11-16T16:59:59Z"), "{policy_type}: Monday before the end");
        assert!(at("2026-11-16T08:59:59Z"), "{policy_type}: Monday before the window");
        assert!(at("2026-11-16T17:00:00Z"), "{policy_type}: Monday at the end");
        assert!(at("2026-11-21T12:00:00Z"), "{policy_type}: Saturday is outside the window");
    }
    let overnight_deny = || json!({"mode": "deny", "start_time": "22:00", "end_time": "06:00"});
    assert!(!business_hours_allow("gateway", overnight_deny(), "2026-11-17T03:00:00Z"), "Tuesday night");
    assert!(business_hours_allow("gateway", overnight_deny(), "2026-11-17T12:00:00Z"), "Tuesday midday");
}

#[test]
fn business_hours_follows_the_time_zone_across_a_daylight_saving_change() {
    let weekend_berlin = || json!({"days": ["Saturday", "Sunday"], "time_zone": "Europe/Berlin"});
    let at = |instant| business_hours_allow("gateway", weekend_berlin(), instant);
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
    let friday_berlin =
        json!({"days": ["Friday"], "start_time": "00:00", "end_time": "01:00", "time_zone": "Europe/Berlin"});
    let saturday_berlin =
        json!({"days": ["Saturday"], "start_time": "00:00", "end_time": "01:00", "time_zone": "Europe/Berlin"});
    let friday_night_utc = "2026-11-20T23:30:00Z";
    assert!(!business_hours_allow("gateway", friday_berlin, friday_night_utc), "00:30 Saturday in Berlin");
    assert!(business_hours_allow("gateway", saturday_berlin, friday_night_utc), "00:30 Saturday in Berlin");
}
