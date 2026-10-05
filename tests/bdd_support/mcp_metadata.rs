use serde_json::{Map, Value};

pub fn metadata_at<'a>(
    body: &'a Value,
    location: &str,
) -> Option<&'a Map<String, Value>> {
    match location {
        "params._meta" => body
            .get("params")?
            .get("_meta")?
            .as_object(),
        "result._meta" => body
            .get("result")?
            .get("_meta")?
            .as_object(),
        "top-level" => body.get("_meta")?.as_object(),
        _ => panic!("unsupported metadata location '{location}'"),
    }
}

pub fn assert_key_only_at(
    body: &Value,
    key: &str,
    location: &str,
) {
    assert!(
        metadata_at(body, location).is_some_and(|metadata| metadata.contains_key(key)),
        "expected metadata key '{key}' in {location}"
    );
    for other in ["params._meta", "result._meta", "top-level"] {
        if other != location {
            assert!(
                !metadata_at(body, other).is_some_and(|metadata| metadata.contains_key(key)),
                "metadata key '{key}' unexpectedly duplicated in {other}"
            );
        }
    }
}

pub fn assert_key_absent(
    body: &Value,
    key: &str,
) {
    for location in ["params._meta", "result._meta", "top-level"] {
        assert!(
            !metadata_at(body, location).is_some_and(|metadata| metadata.contains_key(key)),
            "metadata key '{key}' unexpectedly present in {location}"
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn exact_location_assertion_rejects_root_only_or_duplicate_metadata() {
        use super::*;
        use serde_json::json;
        let canonical = json!({"params": {"_meta": {"io.affinidi.fabric/agent-identity-binding": "proof"}}});
        assert_key_only_at(&canonical, "io.affinidi.fabric/agent-identity-binding", "params._meta");
        for body in [
            json!({"_meta": {"tenant": "one"}}),
            json!({"params": {"_meta": {"tenant": "one"}}, "_meta": {"tenant": "one"}}),
        ] {
            assert!(std::panic::catch_unwind(|| assert_key_only_at(&body, "tenant", "params._meta")).is_err());
        }
        assert_key_absent(&canonical, "old-key");
    }
}
