//! Lists a DID's signing Multikey under the verification relationships its proofs claim, by
//! appending a `did:webvh` log version signed with that same key, so the DID does not change.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::{Value, json};
use ssi::jwk::JWK;

/// Longest wait for a DID log version's `versionTime` to pass before a new version is appended
/// after it.
const MAX_VERSION_TIME_WAIT_SECS: i64 = 2;

const MULTIKEY_CONTEXT: &str = "https://w3id.org/security/multikey/v1";

const DID_CONTEXT: &str = "https://www.w3.org/ns/did/v1";

/// Verification relationships a signing key is listed under: credentials and presentations it
/// signs claim one of them as their proof purpose.
pub(crate) const SIGNING_KEY_RELATIONSHIPS: [&str; 2] = ["assertionMethod", "authentication"];

/// How long to wait before appending a log version after one dated `previous_time`: a
/// version's `versionTime`, in whole seconds, must be later than the previous one's, which a
/// log published earlier in the same startup can share. A `versionTime` further ahead comes
/// from a clock that is off and is refused rather than waited out.
pub(crate) fn wait_before_next_version(
    previous_time: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<std::time::Duration>> {
    let wait = (previous_time + chrono::Duration::seconds(1)).signed_duration_since(now);
    if wait > chrono::Duration::seconds(MAX_VERSION_TIME_WAIT_SECS) {
        anyhow::bail!("the latest DID log version is dated {previous_time}, ahead of this node's clock");
    }
    Ok(wait.to_std().ok())
}

/// Adds `multikey_id` to each of [`SIGNING_KEY_RELATIONSHIPS`] that does not list it yet;
/// returns false when all of them already do. Refuses, changing nothing, a document that does
/// not publish `multikey_id` as the Multikey of `signing_key`, so only the DID's own signing key
/// is ever authorized, or that lacks one of those relationships.
pub(crate) fn add_signing_key_to_relationships(
    document: &mut Value,
    multikey_id: &str,
    signing_key: &JWK,
) -> Result<bool> {
    let expected_key = crate::identity::ssi::did_utils::jwk_to_multibase_ed25519(signing_key)?;
    let mut matching = document["verificationMethod"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|method| method["id"] == multikey_id);
    let published = matching
        .next()
        .with_context(|| format!("DID document does not publish {multikey_id}"))?;
    anyhow::ensure!(matching.next().is_none(), "DID document publishes {multikey_id} more than once");
    anyhow::ensure!(
        published["type"] == "Multikey" && published["publicKeyMultibase"] == expected_key.as_str(),
        "DID document publishes a key other than the signing key as {multikey_id}"
    );
    for relationship in SIGNING_KEY_RELATIONSHIPS {
        anyhow::ensure!(document[relationship].is_array(), "DID document has no {relationship}");
    }

    let mut changed = false;
    for relationship in SIGNING_KEY_RELATIONSHIPS {
        let ids = document
            .get_mut(relationship)
            .and_then(Value::as_array_mut)
            .with_context(|| format!("DID document has no {relationship}"))?;
        if !ids
            .iter()
            .any(|id| *id == multikey_id)
        {
            ids.push(json!(multikey_id));
            changed = true;
        }
    }
    Ok(changed)
}

/// Like [`add_signing_key_to_relationships`], but first publishes `signing_key` as the Multikey
/// `multikey_id`, controlled by `did`, when the document has no method by that id, absolute or
/// relative, and creates a missing relationship. A method by that id holding another key, or
/// published only by its relative id, is still refused, changing nothing.
pub(crate) fn publish_signing_key(
    document: &mut Value,
    did: &str,
    multikey_id: &str,
    signing_key: &JWK,
) -> Result<bool> {
    let mut published = document.clone();
    let changed = publish_signing_key_into(&mut published, did, multikey_id, signing_key)?;
    *document = published;
    Ok(changed)
}

fn publish_signing_key_into(
    document: &mut Value,
    did: &str,
    multikey_id: &str,
    signing_key: &JWK,
) -> Result<bool> {
    let object = document
        .as_object_mut()
        .context("DID document is not an object")?;
    let mut changed = false;
    let methods = object
        .entry("verificationMethod")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .context("DID document verificationMethod is not a list")?;
    let relative_id = multikey_id
        .rfind('#')
        .map(|fragment| &multikey_id[fragment..]);
    if !methods
        .iter()
        .any(|method| method["id"] == multikey_id || relative_id.is_some_and(|relative| method["id"] == relative))
    {
        methods.push(json!({
            "id": multikey_id,
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": crate::identity::ssi::did_utils::jwk_to_multibase_ed25519(signing_key)?,
        }));
        add_multikey_context(object)?;
        changed = true;
    }
    for relationship in SIGNING_KEY_RELATIONSHIPS {
        if !object.contains_key(relationship) {
            object.insert(relationship.to_string(), json!([]));
            changed = true;
        }
    }
    Ok(add_signing_key_to_relationships(document, multikey_id, signing_key)? || changed)
}

fn add_multikey_context(document: &mut serde_json::Map<String, Value>) -> Result<()> {
    let context = document
        .entry("@context")
        .or_insert_with(|| json!([DID_CONTEXT]));
    if let Value::String(single) = context {
        *context = json!([single.clone()]);
    }
    let contexts = context
        .as_array_mut()
        .context("DID document @context is not a list")?;
    if !contexts
        .iter()
        .any(|entry| entry == MULTIKEY_CONTEXT)
    {
        contexts.push(json!(MULTIKEY_CONTEXT));
    }
    Ok(())
}

pub(crate) fn log_entries(log: &str) -> Vec<String> {
    log.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

pub(crate) fn latest_entry(log: &str) -> Result<Value> {
    let entries = log_entries(log);
    Ok(serde_json::from_str(
        entries
            .last()
            .context("DID log has no entries")?,
    )?)
}

/// Whether the latest version of `log` lists `{did}#key-2` as the Multikey of `signing_key`
/// under every one of [`SIGNING_KEY_RELATIONSHIPS`]. Only reads; the log is not verified.
pub(crate) fn lists_signing_key(
    log: &str,
    did: &str,
    signing_key: &JWK,
) -> bool {
    let multikey_id = signing_key_id(did);
    latest_entry(log)
        .ok()
        .and_then(|latest| {
            let mut document = latest.get("state")?.clone();
            add_signing_key_to_relationships(&mut document, &multikey_id, signing_key).ok()
        })
        == Some(false)
}

/// Whether presentations held by `did` may claim `authentication` at `now`: the latest version of
/// `log` publishes `signing_key` as the DID's signing Multikey and lists it under every one of
/// [`SIGNING_KEY_RELATIONSHIPS`], and it has been listed under `authentication` either since the
/// first version or for at least `grace`. A peer may hold a copy of the document cached before the
/// key was listed for as long as its resolver keeps documents; within `grace` the holder keeps
/// claiming `assertionMethod`, which that copy also accepts. A log with an entry that does not
/// parse never qualifies. Only reads; the log is not verified.
pub(crate) fn signs_for_authentication(
    log: &str,
    did: &str,
    signing_key: &JWK,
    grace: chrono::Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if !lists_signing_key(log, did, signing_key) {
        return false;
    }
    let multikey_id = signing_key_id(did);
    let Ok(entries) = log_entries(log)
        .iter()
        .map(|entry| serde_json::from_str::<Value>(entry))
        .collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    let listed_from = entries
        .iter()
        .rposition(|entry| {
            !entry["state"]["authentication"]
                .as_array()
                .is_some_and(|ids| {
                    ids.iter()
                        .any(|id| *id == multikey_id.as_str())
                })
        })
        .map_or(0, |unlisted| unlisted + 1);
    if listed_from == 0 {
        return true;
    }
    entries[listed_from]["versionTime"]
        .as_str()
        .and_then(|time| chrono::DateTime::parse_from_rfc3339(time).ok())
        .is_some_and(|listed_at| now.signed_duration_since(listed_at.to_utc()) >= grace)
}

pub(crate) fn signing_key_id(did: &str) -> String {
    format!("{did}#{}", crate::identity::ssi::vp_issuer::DEFAULT_SIGNING_KEY_ID)
}

/// What [`append_signing_key_version`] did.
#[derive(Debug)]
pub(crate) enum Repair {
    /// The latest version already lists the key; its document is `state`.
    Unchanged { state: Value },
    /// A version listing the key was appended; its document is `state`.
    Appended { state: Value },
    /// The node stepped down before the version was appended, so nothing was written.
    SteppedDown,
}

/// Appends to `log`, the `did.jsonl` in `log_dir`, a version whose document lists the signing
/// Multikey of `signing_key` under [`SIGNING_KEY_RELATIONSHIPS`], signed with `signing_key`, which
/// must be the log's update key. With `publish_if_missing` the key is first published when the
/// document has none. The whole log, and the new version with it, must verify. The version is
/// appended only while `still_active` holds once it is ready, and only if the file still holds
/// `log`.
pub(crate) async fn append_signing_key_version(
    log_dir: &Path,
    log: &str,
    did: &str,
    signing_key: &JWK,
    publish_if_missing: bool,
    still_active: &(dyn Fn() -> bool + Sync),
) -> Result<Repair> {
    use crate::identity::didwebvh::handlers::{build_signing_secret, build_webvh_state};

    let mut entries = log_entries(log);
    let state = build_webvh_state(did, &entries)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let latest = latest_entry(log)?;
    let mut document = latest
        .get("state")
        .cloned()
        .context("DID log entry has no state")?;
    let multikey_id = signing_key_id(did);
    let changed = if publish_if_missing {
        publish_signing_key(&mut document, did, &multikey_id, signing_key)?
    } else {
        add_signing_key_to_relationships(&mut document, &multikey_id, signing_key)?
    };
    if !changed {
        return Ok(Repair::Unchanged { state: latest["state"].clone() });
    }

    let previous_time = chrono::DateTime::parse_from_rfc3339(
        latest["versionTime"]
            .as_str()
            .context("DID log entry has no versionTime")?,
    )?;
    if let Some(wait) = wait_before_next_version(previous_time.to_utc(), chrono::Utc::now())
        .context("the repair runs again on the next start")?
    {
        tokio::time::sleep(wait).await;
    }

    let secret = build_signing_secret(&serde_json::to_value(signing_key)?).map_err(|e| anyhow::anyhow!(e))?;
    let update = didwebvh_rs::prelude::update_did(
        didwebvh_rs::prelude::UpdateDIDConfig::builder()
            .state(state)
            .signing_key(secret)
            .document(document)
            .build()?,
    )
    .await?;
    let entry_json = serde_json::to_string(update.log_entry())?;
    entries.push(entry_json.clone());
    build_webvh_state(did, &entries)
        .await
        .map_err(|e| anyhow::anyhow!("the new DID log version does not verify: {e}"))?;
    if !still_active() {
        return Ok(Repair::SteppedDown);
    }
    crate::storage::did_artifacts::append_did_log_raw(log_dir, log, &entry_json).await?;
    let entry: Value = serde_json::from_str(&entry_json)?;
    Ok(Repair::Appended { state: entry["state"].clone() })
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::Path;

    use serde_json::json;
    use ssi::jwk::JWK;

    /// Writes `{dir}/did.jsonl`: the birth log of an agent DID, whose last segment is `dir`'s
    /// name, signed and updatable by a new key. Its document lists `#key-1` under
    /// `authentication`, and publishes the Multikey `#key-2` under `assertionMethod` only when
    /// `with_key_2`. Returns the DID and its key.
    pub(crate) async fn agent_log(
        dir: &Path,
        with_key_2: bool,
    ) -> (String, JWK) {
        let key = JWK::generate_ed25519().unwrap();
        let id = dir
            .file_name()
            .unwrap()
            .to_string_lossy()
            .trim_start_matches('.')
            .to_string();
        let placeholder = format!("did:webvh:{{SCID}}:localhost%3A8080:surface:{id}");
        let key_1 = format!("{placeholder}#key-1");
        let key_2 = format!("{placeholder}#key-2");
        let mut methods = vec![json!({
            "id": key_1, "type": "JsonWebKey2020", "controller": placeholder, "publicKeyJwk": key.to_public(),
        })];
        let mut assertion = vec![json!(key_1)];
        if with_key_2 {
            methods.push(json!({
                "id": key_2, "type": "Multikey", "controller": placeholder,
                "publicKeyMultibase": crate::identity::ssi::did_utils::jwk_to_multibase_ed25519(&key).unwrap(),
            }));
            assertion.push(json!(key_2));
        }
        let document = json!({
            "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
            "id": placeholder,
            "verificationMethod": methods,
            "authentication": [key_1],
            "assertionMethod": assertion,
        });
        let created = crate::identity::didwebvh::create::create_webvh_did(
            &serde_json::to_value(&key).unwrap(),
            document,
            "http://localhost:8080/",
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(dir)
            .await
            .unwrap();
        crate::storage::did_artifacts::write_did_log_raw(dir, &created.log_entry_json)
            .await
            .unwrap();
        (created.final_did, key)
    }

    /// Stores a local agent identity in `store`, under the store's folder, with a birth log made
    /// by [`agent_log`]. Returns the DID and its key.
    pub(crate) async fn seed_agent_identity(
        store: &dyn crate::identity::IdentityStore,
        with_key_2: bool,
    ) -> (String, JWK) {
        let id = uuid::Uuid::new_v4().to_string();
        let (did, key) = agent_log(
            &store
                .base_path()
                .unwrap()
                .join(&id),
            with_key_2,
        )
        .await;
        let record = serde_json::from_value(json!({
            "did": did,
            "identity_hash": format!("hash-{id}"),
            "created_at": chrono::Utc::now(),
            "identity_fields": {},
            "private_key": key,
        }))
        .unwrap();
        store
            .create(record)
            .await
            .unwrap();
        (did, key)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::agent_log;
    use super::*;
    use crate::storage::did_artifacts::read_did_log_raw;

    async fn read_log(dir: &Path) -> String {
        read_did_log_raw(dir)
            .await
            .unwrap()
            .unwrap()
    }

    async fn repair(
        dir: &Path,
        did: &str,
        key: &JWK,
    ) -> Result<Repair> {
        let log = read_log(dir).await;
        append_signing_key_version(dir, &log, did, key, true, &|| true).await
    }

    #[tokio::test]
    async fn agent_log_gets_one_version_listing_its_signing_key_under_both_relationships() {
        let dir = tempfile::tempdir().unwrap();
        let (did, key) = agent_log(dir.path(), true).await;

        let outcome = repair(dir.path(), &did, &key)
            .await
            .unwrap();

        let Repair::Appended { state } = outcome else { panic!("expected a new version, got {outcome:?}") };
        assert_eq!(state["id"], did.as_str());
        let log = read_log(dir.path()).await;
        assert_eq!(log_entries(&log).len(), 2);
        crate::identity::didwebvh::handlers::build_webvh_state(&did, &log_entries(&log))
            .await
            .expect("the repaired log verifies");
        assert!(lists_signing_key(&log, &did, &key));
        assert_eq!(state["authentication"], json!([format!("{did}#key-1"), signing_key_id(&did)]));
    }

    #[tokio::test]
    async fn agent_log_without_key_2_gets_it_published_and_listed() {
        let dir = tempfile::tempdir().unwrap();
        let (did, key) = agent_log(dir.path(), false).await;

        let outcome = repair(dir.path(), &did, &key)
            .await
            .unwrap();

        let Repair::Appended { state } = outcome else { panic!("expected a new version, got {outcome:?}") };
        let published: Vec<&Value> = state["verificationMethod"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|method| method["id"] == signing_key_id(&did).as_str())
            .collect();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0]["type"], "Multikey");
        assert_eq!(published[0]["controller"], did.as_str());
        assert_eq!(
            published[0]["publicKeyMultibase"],
            crate::identity::ssi::did_utils::jwk_to_multibase_ed25519(&key)
                .unwrap()
                .as_str()
        );
        assert!(
            state["@context"]
                .as_array()
                .unwrap()
                .contains(&json!(MULTIKEY_CONTEXT))
        );
        assert!(lists_signing_key(&read_log(dir.path()).await, &did, &key));
    }

    fn log_states(log: &str) -> Vec<Value> {
        log_entries(log)
            .iter()
            .map(|entry| serde_json::from_str::<Value>(entry).unwrap())
            .collect()
    }

    fn without_relationships(state: &Value) -> Value {
        let mut state = state.clone();
        for relationship in SIGNING_KEY_RELATIONSHIPS {
            state
                .as_object_mut()
                .unwrap()
                .remove(relationship);
        }
        state
    }

    #[tokio::test]
    async fn repair_changes_only_the_signing_key_relationships_and_keeps_the_update_key() {
        let dir = tempfile::tempdir().unwrap();
        let (did, key) = agent_log(dir.path(), true).await;

        repair(dir.path(), &did, &key)
            .await
            .unwrap();

        let entries = log_states(&read_log(dir.path()).await);
        let (before, after) = (&entries[0], &entries[1]);
        assert_eq!(without_relationships(&after["state"]), without_relationships(&before["state"]));
        assert_eq!(after["state"]["assertionMethod"], before["state"]["assertionMethod"]);
        assert_eq!(after["state"]["authentication"], json!([format!("{did}#key-1"), signing_key_id(&did)]));
        assert!(
            after["parameters"]
                .get("updateKeys")
                .is_none_or(|keys| *keys == before["parameters"]["updateKeys"]),
            "the update key must not change: {}",
            after["parameters"]
        );
    }

    #[tokio::test]
    async fn publishing_a_missing_signing_key_adds_it_and_keeps_every_other_method() {
        let dir = tempfile::tempdir().unwrap();
        let (did, key) = agent_log(dir.path(), false).await;

        repair(dir.path(), &did, &key)
            .await
            .unwrap();

        let entries = log_states(&read_log(dir.path()).await);
        let (before, after) = (&entries[0]["state"], &entries[1]["state"]);
        let mut methods_after = after["verificationMethod"]
            .as_array()
            .unwrap()
            .clone();
        let added = methods_after.pop().unwrap();
        assert_eq!(
            methods_after,
            *before["verificationMethod"]
                .as_array()
                .unwrap()
        );
        assert_eq!(added["id"], signing_key_id(&did).as_str());
        assert_eq!(
            added["publicKeyMultibase"],
            crate::identity::ssi::did_utils::jwk_to_multibase_ed25519(&key)
                .unwrap()
                .as_str()
        );
        assert_eq!(
            before["verificationMethod"][0]["publicKeyJwk"]["x"],
            added_key_x(&key),
            "#key-2 is the key already published as #key-1"
        );
    }

    fn added_key_x(key: &JWK) -> Value {
        serde_json::to_value(key.to_public()).unwrap()["x"].clone()
    }

    fn version_time_of_latest(log: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(
            latest_entry(log).unwrap()["versionTime"]
                .as_str()
                .unwrap(),
        )
        .unwrap()
        .to_utc()
    }

    #[tokio::test]
    async fn a_repaired_holder_claims_authentication_only_after_the_grace_period() {
        let dir = tempfile::tempdir().unwrap();
        let (did, key) = agent_log(dir.path(), true).await;
        let grace = chrono::Duration::hours(1);
        repair(dir.path(), &did, &key)
            .await
            .unwrap();
        let log = read_log(dir.path()).await;
        let repaired_at = version_time_of_latest(&log);

        assert!(!signs_for_authentication(&log, &did, &key, grace, repaired_at + chrono::Duration::minutes(59)));
        assert!(signs_for_authentication(&log, &did, &key, grace, repaired_at + grace));
    }

    #[tokio::test]
    async fn a_holder_listed_from_its_first_version_claims_authentication_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let (did, key) = agent_log(dir.path(), true).await;
        let mut first = latest_entry(&read_log(dir.path()).await).unwrap();
        first["state"]["authentication"] = json!([format!("{did}#key-1"), signing_key_id(&did)]);

        assert!(signs_for_authentication(
            &first.to_string(),
            &did,
            &key,
            chrono::Duration::hours(1),
            version_time_of_latest(&first.to_string())
        ));
    }

    #[tokio::test]
    async fn a_log_with_an_unparseable_entry_never_claims_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let (did, key) = agent_log(dir.path(), true).await;
        repair(dir.path(), &did, &key)
            .await
            .unwrap();
        let log = read_log(dir.path()).await;
        let at = version_time_of_latest(&log) + chrono::Duration::days(1);
        let lines: Vec<&str> = log.lines().collect();
        let broken = format!("{}\nnot json\n{}", lines[0], lines[1]);

        assert!(signs_for_authentication(&log, &did, &key, chrono::Duration::hours(1), at));
        assert!(!signs_for_authentication(&broken, &did, &key, chrono::Duration::hours(1), at));
    }

    #[tokio::test]
    async fn a_holder_that_does_not_list_the_key_never_claims_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let (did, key) = agent_log(dir.path(), true).await;
        let log = read_log(dir.path()).await;

        assert!(!signs_for_authentication(
            &log,
            &did,
            &key,
            chrono::Duration::zero(),
            version_time_of_latest(&log) + chrono::Duration::days(1)
        ));
    }

    #[tokio::test]
    async fn repair_runs_once() {
        let dir = tempfile::tempdir().unwrap();
        let (did, key) = agent_log(dir.path(), true).await;
        repair(dir.path(), &did, &key)
            .await
            .unwrap();

        let again = repair(dir.path(), &did, &key)
            .await
            .unwrap();

        assert!(matches!(again, Repair::Unchanged { .. }), "{again:?}");
        assert_eq!(log_entries(&read_log(dir.path()).await).len(), 2);
    }

    #[tokio::test]
    async fn key_that_is_not_the_update_key_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (did, _) = agent_log(dir.path(), false).await;
        let before = read_log(dir.path()).await;

        repair(dir.path(), &did, &JWK::generate_ed25519().unwrap())
            .await
            .expect_err("only the log's update key may sign a new version");

        assert_eq!(read_log(dir.path()).await, before);
    }

    #[tokio::test]
    async fn key_2_published_as_another_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (did, _) = agent_log(dir.path(), true).await;
        let mut document = latest_entry(&read_log(dir.path()).await).unwrap()["state"].clone();

        let err = publish_signing_key(&mut document, &did, &signing_key_id(&did), &JWK::generate_ed25519().unwrap())
            .unwrap_err();

        assert!(format!("{err:#}").contains("a key other than the signing key"), "{err:#}");
    }

    #[test]
    fn signing_key_published_by_its_relative_id_is_refused_rather_than_published_twice() {
        let did = "did:webvh:scid:example.com:surface:a";
        let key = JWK::generate_ed25519().unwrap();
        let mut document = json!({
            "id": did,
            "verificationMethod": [{ "id": "#key-2", "type": "Multikey", "controller": did }],
        });

        let before = document.clone();

        publish_signing_key(&mut document, did, &signing_key_id(did), &key).expect_err("the relative #key-2 is kept");

        assert_eq!(document, before, "a refused document is left unchanged");
    }

    #[test]
    fn document_without_a_context_gets_the_did_and_multikey_contexts() {
        let did = "did:webvh:scid:example.com:surface:a";
        let mut document = json!({ "id": did });

        publish_signing_key(&mut document, did, &signing_key_id(did), &JWK::generate_ed25519().unwrap()).unwrap();

        assert_eq!(document["@context"], json!([DID_CONTEXT, MULTIKEY_CONTEXT]));
    }

    #[tokio::test]
    async fn log_that_does_not_verify_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (did, key) = agent_log(dir.path(), true).await;
        let mut entry = latest_entry(&read_log(dir.path()).await).unwrap();
        entry["state"]["service"] = json!([{ "id": "#x", "type": "Other", "serviceEndpoint": "https://example.com" }]);
        let tampered = serde_json::to_string(&entry).unwrap();
        crate::storage::did_artifacts::write_did_log_raw(dir.path(), &tampered)
            .await
            .unwrap();

        repair(dir.path(), &did, &key)
            .await
            .expect_err("a log that does not verify must be left alone");

        assert_eq!(
            read_log(dir.path())
                .await
                .trim(),
            tampered
        );
    }

    #[tokio::test]
    async fn node_that_stepped_down_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (did, key) = agent_log(dir.path(), true).await;
        let log = read_log(dir.path()).await;

        let outcome = append_signing_key_version(dir.path(), &log, &did, &key, true, &|| false)
            .await
            .unwrap();

        assert!(matches!(outcome, Repair::SteppedDown), "{outcome:?}");
        assert_eq!(read_log(dir.path()).await, log);
    }
}
