//! Fills an integration's template with one event's values.

use std::collections::HashMap;

use serde_json::Value as JsonValue;

use crate::integrations::runtime_variables::patterns;

/// Variables whose value is JSON text. A template string that is exactly one of these
/// placeholders (`"data": "${EVENT_DATA}"`) embeds the value as JSON instead of a string.
const JSON_VALUED_VARIABLES: &[&str] = &["EVENT_DATA", "AUDIT_RECORD"];

/// How values are escaped before they enter the message, so caller-supplied text cannot
/// change what the transport makes of it. The template itself is never escaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escaping {
    None,
    /// Slack mrkdwn: `&`, `<` and `>`, so values cannot form mentions or links.
    SlackMrkdwn,
    /// HTML email bodies: `&`, `<`, `>`, `"` and `'`.
    Html,
}

/// `template` with every placeholder filled from `values` in one pass: a placeholder without
/// a value becomes empty, and a filled value is never scanned for placeholders again.
pub fn render(
    template: &JsonValue,
    values: &HashMap<String, String>,
    escaping: Escaping,
) -> JsonValue {
    match template {
        JsonValue::String(text) => {
            embedded_json(text, values).unwrap_or_else(|| JsonValue::String(fill(text, values, escaping)))
        }
        JsonValue::Array(items) => JsonValue::Array(
            items
                .iter()
                .map(|item| render(item, values, escaping))
                .collect(),
        ),
        JsonValue::Object(fields) => JsonValue::Object(
            fields
                .iter()
                .map(|(name, field)| (name.clone(), render(field, values, escaping)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn fill(
    text: &str,
    values: &HashMap<String, String>,
    escaping: Escaping,
) -> String {
    patterns()
        .regex
        .replace_all(text, |capture: &regex::Captures| {
            values
                .get(capture[1].trim())
                .map(|value| escape(value, escaping))
                .unwrap_or_default()
        })
        .into_owned()
}

/// The JSON value of `text` when it is exactly one JSON-valued placeholder holding JSON.
fn embedded_json(
    text: &str,
    values: &HashMap<String, String>,
) -> Option<JsonValue> {
    let capture = patterns()
        .regex
        .captures(text)?;
    if capture.get(0)?.as_str() != text {
        return None;
    }
    let name = capture[1].trim();
    if !JSON_VALUED_VARIABLES.contains(&name) {
        return None;
    }
    serde_json::from_str(values.get(name)?).ok()
}

fn escape(
    value: &str,
    escaping: Escaping,
) -> String {
    match escaping {
        Escaping::None => value.to_string(),
        Escaping::SlackMrkdwn => value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;"),
        Escaping::Html => value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn values(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn fills_placeholders_in_every_string_of_the_template() {
        let template = json!({
            "subject": "${EVENT_NAME:Event}: ${GATEWAY_NAME}",
            "lines": ["${GATEWAY_ID}", {"nested": "at ${TIMESTAMP}"}],
            "count": 3,
            "flag": true
        });

        let rendered = render(
            &template,
            &values(&[
                ("EVENT_NAME", "Gateway Created"),
                ("GATEWAY_NAME", "edge"),
                ("GATEWAY_ID", "gw-1"),
                ("TIMESTAMP", "2026-10-15T00:00:00Z"),
            ]),
            Escaping::None,
        );

        assert_eq!(
            rendered,
            json!({
                "subject": "Gateway Created: edge",
                "lines": ["gw-1", {"nested": "at 2026-10-15T00:00:00Z"}],
                "count": 3,
                "flag": true
            })
        );
    }

    #[test]
    fn a_placeholder_without_a_value_becomes_empty() {
        let rendered = render(&json!({"text": "by ${USERNAME}."}), &values(&[]), Escaping::None);

        assert_eq!(rendered, json!({"text": "by ."}));
    }

    #[test]
    fn a_filled_value_is_never_filled_again() {
        let rendered = render(
            &json!({"text": "${USERNAME}"}),
            &values(&[("USERNAME", "${SECRET_VALUE}"), ("SECRET_VALUE", "leak")]),
            Escaping::None,
        );

        assert_eq!(rendered, json!({"text": "${SECRET_VALUE}"}));
    }

    #[test]
    fn a_json_valued_placeholder_alone_in_a_string_is_embedded_as_json() {
        let data = values(&[("EVENT_DATA", r#"{"gateway_id":"gw-1","old_state":null}"#)]);

        let embedded = render(&json!({"data": "${EVENT_DATA}"}), &data, Escaping::None);
        let in_text = render(&json!({"text": "data: ${EVENT_DATA}"}), &data, Escaping::None);
        let not_json =
            render(&json!({"data": "${EVENT_DATA}"}), &values(&[("EVENT_DATA", "not json")]), Escaping::None);

        assert_eq!(embedded, json!({"data": {"gateway_id": "gw-1", "old_state": null}}));
        assert_eq!(in_text, json!({"text": r#"data: {"gateway_id":"gw-1","old_state":null}"#}));
        assert_eq!(not_json, json!({"data": "not json"}));
    }

    #[test]
    fn escapes_values_but_not_the_template() {
        let caller = values(&[("USERNAME", "<!channel> & <a href=\"x\">'hi'</a>")]);
        let template = json!({"text": "<b>${USERNAME}</b>"});

        assert_eq!(
            render(&template, &caller, Escaping::SlackMrkdwn),
            json!({"text": "<b>&lt;!channel&gt; &amp; &lt;a href=\"x\"&gt;'hi'&lt;/a&gt;</b>"})
        );
        assert_eq!(
            render(&template, &caller, Escaping::Html),
            json!({"text": "<b>&lt;!channel&gt; &amp; &lt;a href=&quot;x&quot;&gt;&#39;hi&#39;&lt;/a&gt;</b>"})
        );
        assert_eq!(
            render(&template, &caller, Escaping::None),
            json!({"text": "<b><!channel> & <a href=\"x\">'hi'</a></b>"})
        );
    }

    #[test]
    fn embedded_json_is_not_escaped() {
        let rendered =
            render(&json!({"data": "${EVENT_DATA}"}), &values(&[("EVENT_DATA", r#"{"name":"<b>"}"#)]), Escaping::Html);

        assert_eq!(rendered, json!({"data": {"name": "<b>"}}));
    }
}
