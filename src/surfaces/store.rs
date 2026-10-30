//! Agent Surface Store Trait

use anyhow::Context;
use async_trait::async_trait;
use tracing::{error, info, warn};

use crate::config::agent_surface::{A2aAccessPointSettings, A2aValidation, AgentSurface};

/// Trait for storing and retrieving Agent Surface configurations
#[async_trait]
pub trait AgentSurfaceStore: Send + Sync {
    /// Create or update an Agent Surface
    async fn save(
        &self,
        surface: &AgentSurface,
    ) -> anyhow::Result<()>;

    /// Get an Agent Surface by surface_id
    async fn get(
        &self,
        surface_id: &str,
    ) -> anyhow::Result<Option<AgentSurface>>;

    /// List all Agent Surfaces
    async fn list_all(&self) -> anyhow::Result<Vec<AgentSurface>>;

    /// Delete an Agent Surface by surface_id
    async fn delete(
        &self,
        surface_id: &str,
    ) -> anyhow::Result<()>;
}

/// Auto-clear `header_metadata_mapping` config that targets a protocol other
/// than A2A/AP2, persisting the correction to storage.
///
/// Save-time validation (`AgentSurface::validate`) rejects this combination,
/// but a hand-edited or restored surface file can still reach storage with
/// it — same class of problem as the duplicate access-point route/port check
/// in `main.rs::disable_duplicate_route_surfaces`, but remediated by clearing
/// the specific invalid field (`AgentSurface::clear_unsupported_header_metadata_mappings`)
/// rather than disabling the whole surface, since a bad mapping doesn't make
/// an otherwise-valid MCP/DIDComm surface unroutable. Re-adding a mapping
/// goes through full save-time validation, so the invalid combination cannot
/// be reintroduced silently.
///
/// Called from both surface load paths that read directly from storage:
/// gateway startup (`main.rs::load_surfaces`) and the local-source config
/// reload (`identity/handlers/config.rs::load_base_gateway_config`).
pub async fn strip_unsupported_header_metadata_mappings<S: AgentSurfaceStore + ?Sized>(
    store: &S,
    channels: &mut [AgentSurface],
) -> anyhow::Result<()> {
    for surface in channels.iter_mut() {
        let cleared = surface.clear_unsupported_header_metadata_mappings();
        if cleared.is_empty() {
            continue;
        }
        for reason in &cleared {
            error!(
                surface = %surface.name,
                surface_id = %surface.surface_id,
                "header_metadata_mapping found on an unsupported protocol in storage — clearing {reason} so the gateway can boot; \
                 resolve via the UI or API"
            );
        }
        store
            .save(surface)
            .await
            .with_context(|| {
                format!("Failed to persist header_metadata_mapping cleanup for surface '{}'", surface.surface_id)
            })?;
    }
    Ok(())
}

/// Keep only the first source authentication method of a stored surface whose
/// methods break the rules for several methods, persisting the correction.
///
/// Before those rules the gateway enforced only the first method and ignored
/// the rest, so a surface stored then can hold methods that now refuse it.
/// Refusing to boot over them would take every surface down; keeping the
/// first method serves the surface as it was served before.
///
/// Called from gateway startup (`main.rs::load_surfaces`), before the
/// resolved-surface cache is seeded and the listeners are built.
pub async fn fall_back_to_first_source_auth_methods<S: AgentSurfaceStore + ?Sized>(
    store: &S,
    channels: &mut [AgentSurface],
) -> anyhow::Result<()> {
    for surface in channels.iter_mut() {
        let Some(reason) = crate::config::fall_back_to_first_source_auth_method(surface) else {
            continue;
        };
        error!(
            surface = %surface.name,
            surface_id = %surface.surface_id,
            "source authentication methods found in storage that the gateway refuses ({reason}) — keeping only the \
             first method so the gateway can boot; resolve via the UI or API"
        );
        store
            .save(surface)
            .await
            .with_context(|| {
                format!("Failed to persist the source authentication fallback for surface '{}'", surface.surface_id)
            })?;
    }
    Ok(())
}

/// Drop the `default_variant_id` of a surface with no variants, persisting the
/// correction to storage.
///
/// Save-time validation (`AgentSurface::validate_variants`) refuses one, but a
/// surface stored before that check, or restored from a backup holding one,
/// still has it, and every request to it would be refused as a misconfigured
/// default. Without the default its base surface serves alias-less requests.
/// A surface with variants keeps its default: the resolver stays strict.
///
/// Called from gateway startup (`main.rs::load_surfaces`), before the
/// resolved-surface cache is seeded and the listeners are built.
pub async fn clear_dangling_default_variants<S: AgentSurfaceStore + ?Sized>(
    store: &S,
    channels: &mut [AgentSurface],
) -> anyhow::Result<()> {
    for surface in channels
        .iter_mut()
        .filter(|surface| surface.variants.is_empty())
    {
        let Some(dropped) = surface
            .default_variant_id
            .take()
        else {
            continue;
        };
        warn!(
            surface = %surface.name,
            config_id = %surface.surface_id,
            default_variant_id = %dropped,
            "Surface has a default_variant_id but no variants — dropping it so its base surface serves its requests"
        );
        store
            .save(surface)
            .await
            .with_context(|| {
                format!("Failed to persist the dropped default variant of surface '{}'", surface.surface_id)
            })?;
    }
    Ok(())
}

/// The retired dashboard feature flag that once turned A2A 0.3 off gateway-wide.
const RETIRED_A2A_LEGACY_COMPATIBILITY_FLAG: &str = "a2a_legacy_compatibility";

/// The gateway-wide A2A switches that per-surface A2A settings replaced, read
/// so that a surface stored before those settings existed keeps what it was
/// served with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetiredA2aSwitches {
    /// `[a2a] validate_messages` from the bootstrap configuration, when set.
    pub validate_messages: Option<bool>,
    /// The retired `a2a_legacy_compatibility` flag, when stored in settings.
    pub legacy_compatibility: Option<bool>,
}

impl RetiredA2aSwitches {
    /// Read both switches: the TOML value from `bootstrap`, the flag from the
    /// settings file in `bootstrap.storage_paths.settings`. See [`Self::read_from`].
    pub fn read(bootstrap: &crate::config::BootstrapConfig) -> Result<Self, String> {
        Self::read_from(
            std::path::Path::new(
                &bootstrap
                    .storage_paths
                    .settings,
            ),
            bootstrap
                .a2a
                .validate_messages,
        )
    }

    /// Read the retired flag from the settings file in `settings_dir`, without
    /// writing anything. A missing file means the flag was never set. A file that
    /// exists but cannot be read or parsed, which a concurrent dashboard write can
    /// cause, is an `Err`, so the caller can skip and retry rather than treat the
    /// flag as unset.
    pub fn read_from(
        settings_dir: &std::path::Path,
        validate_messages: Option<bool>,
    ) -> Result<Self, String> {
        let path = settings_dir.join(crate::storage::settings_store::SETTINGS_FILE_NAME);
        let legacy_compatibility = match std::fs::read_to_string(&path) {
            Ok(content) => serde_json::from_str::<serde_json::Value>(&content)
                .map_err(|e| format!("{}: {e}", path.display()))?
                .pointer(&format!("/feature_flags/{RETIRED_A2A_LEGACY_COMPATIBILITY_FLAG}"))
                .and_then(serde_json::Value::as_bool),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        Ok(Self {
            validate_messages,
            legacy_compatibility,
        })
    }

    /// The startup warnings about the retired switches. With the `local`
    /// configuration source they give surfaces without settings their settings
    /// (see [`carry_over_a2a_settings`]); any other source serves such surfaces
    /// with the defaults, so a switch that would have changed them is reported
    /// as not applied.
    pub fn startup_warnings(
        &self,
        config_source: &str,
    ) -> Vec<String> {
        let mut warnings = Vec::new();
        let local = config_source == "local";
        if self
            .validate_messages
            .is_some()
        {
            warnings.push(if local {
                "[a2a] validate_messages is deprecated: validation is set per A2A surface \
                 (access_point.a2a.validation). It is only applied to A2A surfaces loaded without their own \
                 settings, as \"off\" when false and \"envelope\" otherwise. Remove it from the config file once \
                 every surface has its own settings."
                    .to_string()
            } else {
                format!(
                    "[a2a] validate_messages is deprecated and is not applied with the {config_source:?} \
                     configuration source: A2A surfaces from it without their own settings are served with \
                     validation=envelope. Set access_point.a2a.validation on each surface instead."
                )
            });
        }
        if !local && self.legacy_compatibility == Some(false) {
            warnings.push(format!(
                "The retired a2a_legacy_compatibility setting is off but is not applied with the {config_source:?} \
                 configuration source: A2A surfaces from it without their own settings accept A2A 0.3 and 1.0. Set \
                 access_point.a2a.accepted_versions on each surface instead."
            ));
        }
        warnings
    }

    /// The settings a surface without its own takes from the retired switches:
    /// A2A 1.0 only when the flag is off, and both versions otherwise;
    /// validation `off` when `[a2a] validate_messages` is `false`, and
    /// `envelope` otherwise. It is never `full`: the request-shape check can
    /// refuse lenient callers, so a surface opts into it.
    pub fn settings(&self) -> A2aAccessPointSettings {
        let defaults = A2aAccessPointSettings::default();
        A2aAccessPointSettings {
            accepted_versions: if self.legacy_compatibility == Some(false) {
                vec![crate::a2a::version::VERSION_1_0.to_string()]
            } else {
                defaults.accepted_versions
            },
            validation: if self.validate_messages == Some(false) {
                A2aValidation::Off
            } else {
                A2aValidation::Envelope
            },
            accepted_versions_sent: false,
        }
    }
}

/// Most surfaces a log line names before summarising the rest as a count.
const MAX_NAMED_SURFACES: usize = 20;

/// Whether the A2A request-shape check ran on `surface` before per-surface
/// settings existed: it did on a Target that is neither an A2A proxy nor
/// `fabric://`, the surface's own or a variant's, while `[a2a] validate_messages`
/// was on (the default).
fn had_request_shape_check(surface: &AgentSurface) -> bool {
    let checked = |surface: &AgentSurface| {
        !surface.is_a2a_proxy_target()
            && !surface
                .target
                .endpoint
                .starts_with("fabric://")
    };
    checked(surface)
        || surface
            .variants
            .iter()
            .any(|variant| {
                surface
                    .resolve_variant(Some(&variant.alias))
                    .is_ok_and(|resolved| checked(&resolved))
            })
}

/// The names of the surfaces being given settings that had the request-shape
/// check and now check only the JSON-RPC envelope.
fn names_losing_request_shape_check<'a>(
    retired: &RetiredA2aSwitches,
    carried: impl IntoIterator<Item = &'a AgentSurface>,
) -> Vec<&'a str> {
    if retired.validate_messages == Some(false) {
        return Vec::new();
    }
    carried
        .into_iter()
        .filter(|surface| had_request_shape_check(surface))
        .map(|surface| surface.name.as_str())
        .collect()
}

/// Surface names for a log line: at most [`MAX_NAMED_SURFACES`], each quoted
/// and escaped, then a count of the rest.
fn named_list(names: &[&str]) -> String {
    let mut list = names
        .iter()
        .take(MAX_NAMED_SURFACES)
        .map(|name| format!("{:?}", crate::a2a::clip_for_log(name)))
        .collect::<Vec<_>>()
        .join(", ");
    if names.len() > MAX_NAMED_SURFACES {
        list.push_str(&format!(" and {} more", names.len() - MAX_NAMED_SURFACES));
    }
    list
}

/// Whether `surface` sends over the fabric: its Target, or a variant's, is
/// `fabric://`.
fn has_fabric_target(surface: &AgentSurface) -> bool {
    let fabric = |surface: &AgentSurface| {
        surface
            .target
            .endpoint
            .starts_with("fabric://")
    };
    fabric(surface)
        || surface
            .variants
            .iter()
            .any(|variant| {
                surface
                    .resolve_variant(Some(&variant.alias))
                    .is_ok_and(|resolved| fabric(&resolved))
            })
}

/// The names of the surfaces being given settings whose Targets are all A2A
/// proxies, when `[a2a] validate_messages` is `false`: they are given
/// `envelope`, which an A2A-proxy Target always checks, rather than `off`.
fn names_given_envelope_despite_validation_off<'a>(
    retired: &RetiredA2aSwitches,
    carried: impl IntoIterator<Item = &'a AgentSurface>,
) -> Vec<&'a str> {
    if retired.validate_messages != Some(false) {
        return Vec::new();
    }
    carried
        .into_iter()
        .filter(|surface| !surface.a2a_validation_applies())
        .map(|surface| surface.name.as_str())
        .collect()
}

/// The warning naming A2A-proxy surfaces given `envelope` although
/// `[a2a] validate_messages` is `false`, or `None` when there are none.
fn envelope_despite_validation_off_warning(names: &[&str]) -> Option<String> {
    (!names.is_empty()).then(|| {
        format!(
            "{} A2A surface(s) whose Targets are all A2A proxies were given validation=envelope although [a2a] \
             validate_messages is false, because an A2A proxy Target always checks the JSON-RPC envelope: {}. \
             Their callers must send a single, well-formed JSON-RPC 2.0 request",
            names.len(),
            named_list(names)
        )
    })
}

/// The warning naming `fabric://` surfaces given settings, which this gateway
/// applies before sending a request over the fabric, or `None` when there are none.
fn fabric_settings_warning(
    names: &[&str],
    settings: &A2aAccessPointSettings,
) -> Option<String> {
    (!names.is_empty()).then(|| {
        let refused = if settings
            .validation
            .checks_envelope()
        {
            "an A2A-Version they do not accept or an invalid JSON-RPC envelope"
        } else {
            "an A2A-Version they do not accept"
        };
        format!(
            "{} fabric:// surface(s) apply their A2A settings on this gateway before sending a request over the \
             fabric (accepted versions {}, validation={}): {}. A request with {refused} is refused here instead \
             of being forwarded",
            names.len(),
            settings
                .accepted_versions
                .join(", "),
            settings.validation.as_str(),
            named_list(names)
        )
    })
}

/// The warning naming the surfaces that lost the request-shape check, or
/// `None` when none did. At most [`MAX_NAMED_SURFACES`] names are listed, each
/// quoted and escaped.
fn request_shape_check_warning(names: &[&str]) -> Option<String> {
    if names.is_empty() {
        return None;
    }
    let list = named_list(names);
    Some(format!(
        "{} A2A surface(s) checked the A2A request shape before ([a2a] validate_messages, on by default) and now \
         check only the JSON-RPC envelope: {list}. Set Message validation to \"Envelope + A2A fields\" \
         (access_point.a2a.validation = \"full\") on any that should keep refusing malformed A2A messages",
        names.len()
    ))
}

/// Store `access_point.a2a` on every A2A or AP2 surface loaded without one,
/// taken from the retired gateway-wide switches, and warn about a stored block
/// that is invalid. A2A-proxy surfaces are included, so one created before
/// these settings keeps accepting A2A 0.3; where its validation level would
/// apply to no request (no URL variant), it is given `envelope`, which is what
/// an A2A-proxy Target checks.
///
/// `retired` is only called when some surface needs a block, so once every
/// surface has its own, a load does not touch the settings file. When it fails
/// (the file exists but cannot be read or parsed), nothing is stored, a warning
/// is logged, and the next load tries again; until then those surfaces are
/// served with the defaults. A block that cannot be saved is kept on the
/// surface passed in, with a warning, and the next load tries again; startup
/// seeds the resolved-surface cache from storage, so until then that surface is
/// served with the defaults.
///
/// With `persist` false (a Standby node, so it cannot overwrite an Active node's edit,
/// or a storage event being applied, so applying it raises no further event),
/// the blocks are set on the surfaces passed in only; the next load on an
/// Active node stores them.
///
/// With `persist`, each surface is read from `store` again just before its
/// block is saved, and the block is set on the stored copy, which replaces the
/// one passed in. A stored copy that has a block (an API edit stored it
/// meanwhile) or no longer uses A2A settings is kept as it is; a surface that is
/// gone is removed from `surfaces`, and one that cannot be read is skipped. An
/// API save that lands between the re-read and the save is still overwritten.
/// The re-read sees what `store` has, so at startup it is the snapshot the
/// surfaces were listed from.
///
/// Returns the ids of the surfaces that now carry settings, so a caller can
/// refresh what it serves from.
///
/// An invalid stored block (only reachable by editing storage by hand) is not
/// refused: the surface keeps being served, accepting both versions when its
/// version list is unusable, and the warning says so.
///
/// Warnings name the surfaces whose behaviour the carried settings change: those
/// that lose the request-shape check ([`request_shape_check_warning`]), A2A-proxy
/// surfaces given `envelope` although `validate_messages` is `false`, and
/// `fabric://` surfaces, which now apply their settings before dispatch. Since
/// those surfaces are stored with settings, each warning is logged once, on the
/// first load after the upgrade.
///
/// Called from the same load paths as [`strip_unsupported_header_metadata_mappings`],
/// and without `persist` when a storage event is applied.
pub async fn carry_over_a2a_settings<S: AgentSurfaceStore + ?Sized>(
    store: &S,
    surfaces: &mut Vec<AgentSurface>,
    persist: bool,
    retired: impl FnOnce() -> Result<RetiredA2aSwitches, String>,
) -> Vec<String> {
    let mut gone = Vec::new();
    let given = give_a2a_settings(store, surfaces, persist, retired, &mut gone).await;
    surfaces.retain(|surface| !gone.contains(&surface.surface_id));
    given
}

async fn give_a2a_settings<S: AgentSurfaceStore + ?Sized>(
    store: &S,
    surfaces: &mut [AgentSurface],
    persist: bool,
    retired: impl FnOnce() -> Result<RetiredA2aSwitches, String>,
    gone: &mut Vec<String>,
) -> Vec<String> {
    let mut needing = Vec::new();
    for (index, surface) in surfaces.iter().enumerate() {
        if !surface.uses_a2a_settings() {
            continue;
        }
        if surface
            .access_point
            .a2a
            .is_some()
        {
            if let Err(reason) = surface.validate_a2a_settings() {
                let served = surface.a2a_settings();
                warn!(
                    surface = %surface.name,
                    surface_id = %surface.surface_id,
                    "access_point.a2a in storage is invalid: {reason}. The surface is served with A2A {} and \
                     validation={} until it is corrected through the dashboard or API",
                    served.accepted_versions.join(", "),
                    served.validation.as_str()
                );
            }
        } else {
            needing.push(index);
        }
    }
    if needing.is_empty() {
        return Vec::new();
    }

    let retired = match retired() {
        Ok(retired) => retired,
        Err(reason) => {
            warn!(
                "Could not read the settings file for the retired a2a_legacy_compatibility flag ({reason}); {} A2A \
                 surface(s) without their own settings are served with the defaults and will be given settings on \
                 a later load",
                needing.len()
            );
            return Vec::new();
        }
    };
    let carried = retired.settings();
    let mut given = Vec::new();
    let mut carried_indices = Vec::new();
    for index in &needing {
        let surface = &mut surfaces[*index];
        if persist {
            match store
                .get(&surface.surface_id)
                .await
            {
                Ok(Some(stored)) => {
                    let has_block = stored
                        .access_point
                        .a2a
                        .is_some();
                    let uses_settings = stored.uses_a2a_settings();
                    *surface = stored;
                    if has_block {
                        given.push(surface.surface_id.clone());
                    }
                    if has_block || !uses_settings {
                        continue;
                    }
                }
                Ok(None) => {
                    gone.push(surface.surface_id.clone());
                    continue;
                }
                Err(error) => {
                    warn!(
                        surface = %surface.name,
                        surface_id = %surface.surface_id,
                        error = %error,
                        "Could not read the surface again before storing carried-over A2A settings; it is given them \
                         on a later load"
                    );
                    continue;
                }
            }
        }
        let mut settings = carried.clone();
        if !surface.a2a_validation_applies() {
            settings.validation = A2aValidation::Envelope;
        }
        surface.access_point.a2a = Some(settings);
        if persist && let Err(error) = store.save(surface).await {
            warn!(
                surface = %surface.name,
                surface_id = %surface.surface_id,
                error = %error,
                "Could not store the carried-over A2A settings; they will be stored on a later load or save"
            );
        }
        given.push(surface.surface_id.clone());
        carried_indices.push(*index);
    }
    if carried_indices.is_empty() {
        return given;
    }
    let proxy_envelope = if carried.validation == A2aValidation::Envelope {
        0
    } else {
        carried_indices
            .iter()
            .filter(|index| !surfaces[**index].a2a_validation_applies())
            .count()
    };
    let overridden = if proxy_envelope > 0 {
        format!(
            "; {proxy_envelope} of them, whose Targets are all A2A proxies, were given validation=envelope, which an \
             A2A proxy Target always checks"
        )
    } else {
        String::new()
    };
    info!(
        "Gave A2A settings to {} A2A surface(s) that had none: accepted versions {}, validation={}{overridden}",
        carried_indices.len(),
        carried
            .accepted_versions
            .join(", "),
        carried.validation.as_str()
    );
    if retired.legacy_compatibility == Some(false) {
        warn!(
            "The a2a_legacy_compatibility setting is retired. It was off, so {} A2A surface(s) were given A2A 1.0 \
             only; accepted A2A versions are now set per surface",
            carried_indices.len()
        );
    }
    let carried_surfaces = || {
        carried_indices
            .iter()
            .map(|index| &surfaces[*index])
    };
    let warnings = [
        request_shape_check_warning(&names_losing_request_shape_check(&retired, carried_surfaces())),
        envelope_despite_validation_off_warning(&names_given_envelope_despite_validation_off(
            &retired,
            carried_surfaces(),
        )),
        fabric_settings_warning(
            &carried_surfaces()
                .filter(|surface| has_fabric_target(surface))
                .map(|surface| surface.name.as_str())
                .collect::<Vec<_>>(),
            &carried,
        ),
    ];
    for warning in warnings.into_iter().flatten() {
        warn!("{warning}");
    }
    given
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surfaces::FileSystemAgentSurfaceStore;

    fn mcp_surface_with_mapping(id: &str) -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": id,
            "name": id,
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": format!("/agents/{id}"),
                "protocol": "mcp",
                "header_metadata_mapping": {
                    "headers": [{ "header": "x-agent-id", "field": "agent_id" }]
                }
            },
            "target": { "endpoint": "https://mcp.internal/mcp" }
        }))
        .expect("test surface should deserialize")
    }

    fn a2a_surface_with_mapping(id: &str) -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": id,
            "name": id,
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": format!("/agents/{id}"),
                "protocol": "a2a",
                "header_metadata_mapping": {
                    "headers": [{ "header": "x-agent-id", "field": "agent_id" }]
                }
            },
            "target": { "endpoint": "https://a2a.internal/a2a" }
        }))
        .expect("test surface should deserialize")
    }

    async fn test_store(dir: &std::path::Path) -> FileSystemAgentSurfaceStore {
        FileSystemAgentSurfaceStore::new(dir.to_path_buf())
            .await
            .expect("test store should initialize")
    }

    #[tokio::test]
    async fn strips_and_persists_mapping_on_unsupported_protocol() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut channels = vec![mcp_surface_with_mapping("s-mcp")];

        strip_unsupported_header_metadata_mappings(&store, &mut channels)
            .await
            .expect("cleanup should succeed");

        assert!(
            channels[0]
                .access_point
                .header_metadata_mapping
                .is_none()
        );

        // Persisted: re-reading from storage reflects the cleared mapping.
        let reloaded = store
            .get("s-mcp")
            .await
            .expect("get should succeed")
            .expect("surface should exist");
        assert!(
            reloaded
                .access_point
                .header_metadata_mapping
                .is_none()
        );
    }

    #[tokio::test]
    async fn leaves_valid_mapping_untouched_and_does_not_rewrite_storage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let surface = a2a_surface_with_mapping("s-a2a");
        store
            .save(&surface)
            .await
            .expect("save should succeed");
        let mut channels = vec![surface];

        strip_unsupported_header_metadata_mappings(&store, &mut channels)
            .await
            .expect("cleanup should succeed");

        assert!(
            channels[0]
                .access_point
                .header_metadata_mapping
                .is_some()
        );
    }

    #[tokio::test]
    async fn handles_multiple_surfaces_independently() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut channels = vec![mcp_surface_with_mapping("s-mcp"), a2a_surface_with_mapping("s-a2a")];

        strip_unsupported_header_metadata_mappings(&store, &mut channels)
            .await
            .expect("cleanup should succeed");

        assert!(
            channels[0]
                .access_point
                .header_metadata_mapping
                .is_none()
        );
        assert!(
            channels[1]
                .access_point
                .header_metadata_mapping
                .is_some()
        );
    }

    fn surface_with_default(
        id: &str,
        variants: serde_json::Value,
        default_variant_id: &str,
    ) -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": id,
            "name": format!("{id}-name"),
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": format!("/agents/{id}"),
                "protocol": "a2a"
            },
            "target": { "endpoint": "https://a2a.internal/a2a" },
            "variants": variants,
            "default_variant_id": default_variant_id
        }))
        .expect("test surface should deserialize")
    }

    fn surface_with_methods(
        id: &str,
        methods: serde_json::Value,
    ) -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": id,
            "name": format!("{id}-name"),
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": format!("/agents/{id}"),
                "protocol": "a2a",
                "caller_authentication": { "methods": methods }
            },
            "target": { "endpoint": "https://a2a.internal/a2a" }
        }))
        .expect("test surface should deserialize")
    }

    #[tokio::test]
    async fn a_stored_surface_breaking_the_method_rules_keeps_its_first_method() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let jwt = serde_json::json!({"type": "jwt_bearer", "jwt_verification_strategy_id": "idp", "audiences": []});
        let shared_header = serde_json::json!({
            "type": "api_key", "extraction": {"source": "http_header", "field": "authorization"}, "secret_id": "keys"
        });
        let partner_key = serde_json::json!({
            "type": "api_key", "extraction": {"source": "http_header", "field": "x-api-key"}, "secret_id": "keys"
        });
        let mut channels = vec![
            surface_with_methods("s-legacy", serde_json::json!([jwt.clone(), shared_header])),
            surface_with_methods("s-valid", serde_json::json!([jwt.clone(), partner_key])),
        ];

        fall_back_to_first_source_auth_methods(&store, &mut channels)
            .await
            .expect("fallback should succeed");

        assert_eq!(
            channels[0]
                .source_auth_methods()
                .len(),
            1
        );
        assert_eq!(channels[0].source_auth_methods()[0].method_tag(), "jwt_bearer");
        let reloaded = store
            .get("s-legacy")
            .await
            .expect("get should succeed")
            .expect("surface should exist");
        assert_eq!(
            reloaded
                .source_auth_methods()
                .len(),
            1
        );

        assert_eq!(
            channels[1]
                .source_auth_methods()
                .len(),
            2
        );
        assert!(
            store
                .get("s-valid")
                .await
                .expect("get should succeed")
                .is_none(),
            "a valid surface is not rewritten"
        );
    }

    #[test]
    fn a_surface_whose_first_method_is_invalid_does_not_fall_back() {
        let mut surface = surface_with_methods(
            "s-bad-first",
            serde_json::json!([
                {"type": "did_auth", "extraction": {"source": "http_header", "field": "X-Session"}, "challenge_ttl_seconds": 0},
                {"type": "did_auth", "extraction": {"source": "http_header", "field": "X-Other"}}
            ]),
        );
        assert!(crate::config::fall_back_to_first_source_auth_method(&mut surface).is_none());
        assert_eq!(
            surface
                .source_auth_methods()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn drops_and_persists_the_default_of_a_surface_without_variants() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut channels = vec![surface_with_default("s-none", serde_json::json!([]), "removed")];

        clear_dangling_default_variants(&store, &mut channels)
            .await
            .expect("cleanup should succeed");

        assert_eq!(channels[0].default_variant_id, None);
        let served = channels[0]
            .serve_variant(None)
            .expect("the base surface serves an alias-less request");
        assert_eq!(served.recorded, crate::config::agent_surface_variants::SurfaceVariant::BASE);
        let reloaded = store
            .get("s-none")
            .await
            .expect("get should succeed")
            .expect("surface should exist");
        assert_eq!(reloaded.default_variant_id, None);
    }

    #[tokio::test]
    async fn keeps_the_default_of_a_surface_with_variants() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let variants = serde_json::json!([{ "id": "v-1", "alias": "beta", "name": "Beta" }]);
        let mut channels = vec![
            surface_with_default("s-valid", variants.clone(), "v-1"),
            surface_with_default("s-dangling", variants, "removed"),
        ];

        clear_dangling_default_variants(&store, &mut channels)
            .await
            .expect("cleanup should succeed");

        assert_eq!(
            channels[0]
                .default_variant_id
                .as_deref(),
            Some("v-1")
        );
        assert_eq!(
            channels[1]
                .default_variant_id
                .as_deref(),
            Some("removed")
        );
        assert!(
            store
                .get("s-dangling")
                .await
                .expect("get should succeed")
                .is_none(),
            "a surface left as it is is not rewritten"
        );
    }

    fn a2a_surface(
        id: &str,
        endpoint: &str,
        a2a: Option<serde_json::Value>,
    ) -> AgentSurface {
        let mut access_point = serde_json::json!({
            "listen_address": "0.0.0.0:8443",
            "route": format!("/agents/{id}"),
            "protocol": "a2a"
        });
        if let Some(a2a) = a2a {
            access_point["a2a"] = a2a;
        }
        serde_json::from_value(serde_json::json!({
            "surface_id": id,
            "name": id,
            "access_point": access_point,
            "target": { "endpoint": endpoint }
        }))
        .expect("test surface should deserialize")
    }

    /// Store `surfaces`, as the load that lists them would have found them.
    async fn listed(
        store: &FileSystemAgentSurfaceStore,
        surfaces: Vec<AgentSurface>,
    ) -> Vec<AgentSurface> {
        for surface in &surfaces {
            store
                .save(surface)
                .await
                .expect("save");
        }
        surfaces
    }

    fn settings(
        versions: &[&str],
        validation: A2aValidation,
    ) -> A2aAccessPointSettings {
        A2aAccessPointSettings {
            accepted_versions: versions
                .iter()
                .map(|v| v.to_string())
                .collect(),
            validation,
            accepted_versions_sent: false,
        }
    }

    #[test]
    fn retired_switches_map_to_surface_settings() {
        let switches = |validate_messages, legacy_compatibility| RetiredA2aSwitches {
            validate_messages,
            legacy_compatibility,
        };
        assert_eq!(
            switches(None, None).settings(),
            settings(&["0.3", "1.0"], A2aValidation::Envelope),
            "unset means both versions with envelope validation, the defaults"
        );
        assert_eq!(
            switches(Some(true), Some(true)).settings(),
            settings(&["0.3", "1.0"], A2aValidation::Envelope),
            "true carries over as envelope, never full"
        );
        assert_eq!(switches(Some(false), None).settings(), settings(&["0.3", "1.0"], A2aValidation::Off));
        assert_eq!(switches(None, Some(false)).settings(), settings(&["1.0"], A2aValidation::Envelope));
        assert_eq!(switches(Some(false), Some(false)).settings(), settings(&["1.0"], A2aValidation::Off));
    }

    #[tokio::test]
    async fn an_a2a_surface_without_settings_takes_the_retired_switches_and_is_stored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut surfaces = listed(&store, vec![a2a_surface("s-old", "https://a2a.internal/a2a", None)]).await;
        let retired = RetiredA2aSwitches {
            validate_messages: Some(false),
            legacy_compatibility: Some(false),
        };

        carry_over_a2a_settings(&store, &mut surfaces, true, || Ok(retired)).await;

        let expected = settings(&["1.0"], A2aValidation::Off);
        assert_eq!(surfaces[0].access_point.a2a, Some(expected.clone()));
        let stored = store
            .get("s-old")
            .await
            .expect("get")
            .expect("stored surface");
        assert_eq!(stored.access_point.a2a, Some(expected), "the carried settings are persisted");
        assert_eq!(
            stored
                .a2a_settings()
                .accepted_versions,
            crate::a2a::version::VERSIONS_1_0_ONLY
        );
        assert_eq!(
            stored
                .a2a_settings()
                .validation,
            A2aValidation::Off
        );
    }

    #[tokio::test]
    async fn own_settings_and_non_a2a_surfaces_are_left_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let own = settings(&["0.3"], A2aValidation::Full);
        let mut surfaces = vec![
            a2a_surface("s-own", "https://a2a.internal/a2a", Some(serde_json::to_value(&own).unwrap())),
            mcp_surface_with_mapping("s-mcp"),
        ];

        carry_over_a2a_settings(&store, &mut surfaces, true, || panic!("the settings file must not be read")).await;

        assert_eq!(surfaces[0].access_point.a2a, Some(own), "a surface's own settings are kept");
        assert_eq!(surfaces[1].access_point.a2a, None, "an MCP surface gets no block");
        for id in ["s-own", "s-mcp"] {
            assert!(
                store
                    .get(id)
                    .await
                    .expect("get")
                    .is_none(),
                "{id} must not be rewritten"
            );
        }
    }

    /// An A2A-proxy surface created before per-surface settings keeps accepting
    /// A2A 0.3, so its existing callers keep working, and is given `envelope`,
    /// the only level an A2A-proxy Target checks, whatever the retired TOML said.
    #[tokio::test]
    async fn an_existing_a2a_proxy_surface_keeps_a2a_0_3_with_envelope_validation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut surfaces = listed(&store, vec![a2a_surface("s-proxy", "a2a-proxy://worker", None)]).await;
        let retired = RetiredA2aSwitches {
            validate_messages: Some(false),
            legacy_compatibility: None,
        };

        carry_over_a2a_settings(&store, &mut surfaces, true, || Ok(retired)).await;

        let expected = settings(&["0.3", "1.0"], A2aValidation::Envelope);
        assert_eq!(surfaces[0].access_point.a2a, Some(expected.clone()));
        let stored = store
            .get("s-proxy")
            .await
            .expect("get")
            .expect("the carried settings are persisted");
        assert_eq!(stored.access_point.a2a, Some(expected));
        assert_eq!(
            stored
                .a2a_settings()
                .accepted_versions,
            crate::a2a::version::SUPPORTED_VERSIONS
        );
    }

    #[tokio::test]
    async fn an_existing_a2a_proxy_surface_follows_the_retired_flag_turning_0_3_off() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut surfaces = listed(&store, vec![a2a_surface("s-proxy", "a2a-proxy://worker", None)]).await;
        let retired = RetiredA2aSwitches {
            validate_messages: None,
            legacy_compatibility: Some(false),
        };

        carry_over_a2a_settings(&store, &mut surfaces, true, || Ok(retired)).await;

        assert_eq!(surfaces[0].access_point.a2a, Some(settings(&["1.0"], A2aValidation::Envelope)));
    }

    #[tokio::test]
    async fn an_invalid_stored_version_list_is_kept_and_served_with_both_versions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut surfaces = vec![
            a2a_surface(
                "s-empty",
                "https://a2a.internal/a2a",
                Some(serde_json::json!({ "accepted_versions": [], "validation": "full" })),
            ),
            a2a_surface(
                "s-unknown",
                "https://a2a.internal/a2a",
                Some(serde_json::json!({ "accepted_versions": ["2.0"] })),
            ),
        ];

        carry_over_a2a_settings(&store, &mut surfaces, true, || Ok(RetiredA2aSwitches::default())).await;

        assert_eq!(surfaces[0].access_point.a2a, Some(settings(&[], A2aValidation::Full)), "left as stored");
        assert_eq!(
            surfaces[0]
                .a2a_settings()
                .accepted_versions,
            crate::a2a::version::SUPPORTED_VERSIONS
        );
        assert_eq!(
            surfaces[0]
                .a2a_settings()
                .validation,
            A2aValidation::Full
        );
        assert_eq!(
            surfaces[1]
                .a2a_settings()
                .accepted_versions,
            crate::a2a::version::SUPPORTED_VERSIONS
        );
    }

    #[test]
    fn the_retired_flag_is_read_without_writing_the_settings_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir
            .path()
            .join(crate::storage::settings_store::SETTINGS_FILE_NAME);

        let missing = RetiredA2aSwitches::read_from(dir.path(), Some(false)).expect("a missing file is fine");
        assert_eq!(
            missing,
            RetiredA2aSwitches {
                validate_messages: Some(false),
                legacy_compatibility: None
            }
        );
        assert!(!file.exists(), "reading must not create the file");

        std::fs::write(&file, r#"{"feature_flags":{"a2a_legacy_compatibility":false},"other":1}"#).unwrap();
        assert_eq!(
            RetiredA2aSwitches::read_from(dir.path(), None)
                .unwrap()
                .legacy_compatibility,
            Some(false)
        );

        let half_written = r#"{"feature_flags":{"a2a_legacy_compat"#;
        std::fs::write(&file, half_written).unwrap();
        assert!(RetiredA2aSwitches::read_from(dir.path(), None).is_err(), "an unparseable file is an error");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), half_written, "the file is left exactly as it was");
    }

    #[tokio::test]
    async fn the_settings_file_is_not_read_when_every_surface_has_its_settings() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut surfaces = vec![
            a2a_surface(
                "s-own",
                "https://a2a.internal/a2a",
                Some(serde_json::to_value(settings(&["1.0"], A2aValidation::Full)).unwrap()),
            ),
            a2a_surface(
                "s-proxy",
                "a2a-proxy://worker",
                Some(serde_json::to_value(settings(&["1.0"], A2aValidation::Envelope)).unwrap()),
            ),
            mcp_surface_with_mapping("s-mcp"),
        ];

        carry_over_a2a_settings(&store, &mut surfaces, true, || panic!("the settings file must not be read")).await;
    }

    #[tokio::test]
    async fn an_unreadable_settings_file_stores_nothing_so_a_later_load_retries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut surfaces = vec![a2a_surface("s-old", "https://a2a.internal/a2a", None)];

        carry_over_a2a_settings(&store, &mut surfaces, true, || Err("settings.json: EOF while parsing".to_string()))
            .await;

        assert_eq!(surfaces[0].access_point.a2a, None, "nothing is carried over");
        assert!(
            store
                .get("s-old")
                .await
                .expect("get")
                .is_none(),
            "nothing is written"
        );
        assert_eq!(
            surfaces[0]
                .a2a_settings()
                .accepted_versions,
            crate::a2a::version::SUPPORTED_VERSIONS,
            "served with the defaults meanwhile"
        );
    }

    struct FailingStore(Vec<AgentSurface>);

    #[async_trait]
    impl AgentSurfaceStore for FailingStore {
        async fn save(
            &self,
            _surface: &AgentSurface,
        ) -> anyhow::Result<()> {
            anyhow::bail!("disk full")
        }

        async fn get(
            &self,
            surface_id: &str,
        ) -> anyhow::Result<Option<AgentSurface>> {
            Ok(self
                .0
                .iter()
                .find(|surface| surface.surface_id == surface_id)
                .cloned())
        }

        async fn list_all(&self) -> anyhow::Result<Vec<AgentSurface>> {
            Ok(self.0.clone())
        }

        async fn delete(
            &self,
            _surface_id: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_failed_save_keeps_the_carried_settings_in_memory() {
        let mut surfaces = vec![
            a2a_surface("s-one", "https://a2a.internal/a2a", None),
            a2a_surface("s-two", "https://a2a.internal/b", None),
        ];
        let retired = RetiredA2aSwitches {
            validate_messages: None,
            legacy_compatibility: Some(false),
        };

        carry_over_a2a_settings(&FailingStore(surfaces.clone()), &mut surfaces, true, || Ok(retired)).await;

        for surface in &surfaces {
            assert_eq!(
                surface.access_point.a2a,
                Some(settings(&["1.0"], A2aValidation::Envelope)),
                "{} still gets its settings",
                surface.surface_id
            );
        }
    }

    fn with_variant_target(
        surface: AgentSurface,
        endpoint: &str,
    ) -> AgentSurface {
        let mut value = serde_json::to_value(surface).unwrap();
        value["variants"] = serde_json::json!([{
            "id": "v", "alias": "other", "name": "other", "enabled": true,
            "overrides": {"target": {"endpoint": endpoint}}
        }]);
        serde_json::from_value(value).unwrap()
    }

    /// The request-shape check ran on a URL Target, the surface's own or a
    /// variant's, and never on an A2A-proxy or `fabric://` Target.
    #[test]
    fn the_request_shape_check_ran_on_url_targets_only() {
        assert!(had_request_shape_check(&a2a_surface("url", "https://a2a.internal/a2a", None)));
        assert!(!had_request_shape_check(&a2a_surface("proxy", "a2a-proxy://worker", None)));
        assert!(!had_request_shape_check(&a2a_surface("fabric", "fabric://peer/agent", None)));
        assert!(had_request_shape_check(&with_variant_target(
            a2a_surface("proxy-with-url", "a2a-proxy://worker", None),
            "https://a2a.internal/a2a"
        )));
        assert!(!had_request_shape_check(&with_variant_target(
            a2a_surface("proxy-with-fabric", "a2a-proxy://worker", None),
            "fabric://peer/agent"
        )));
    }

    #[test]
    fn surfaces_lose_the_request_shape_check_unless_validate_messages_was_off() {
        let surfaces = [
            a2a_surface("alpha", "https://a2a.internal/a", None),
            a2a_surface("proxy", "a2a-proxy://worker", None),
            a2a_surface("fabric", "fabric://peer/agent", None),
            a2a_surface("beta", "https://a2a.internal/b", None),
        ];
        for validate_messages in [None, Some(true)] {
            let retired = RetiredA2aSwitches {
                validate_messages,
                legacy_compatibility: None,
            };
            assert_eq!(names_losing_request_shape_check(&retired, &surfaces), vec!["alpha", "beta"]);
        }
        let off = RetiredA2aSwitches {
            validate_messages: Some(false),
            legacy_compatibility: None,
        };
        assert!(
            names_losing_request_shape_check(&off, &surfaces).is_empty(),
            "with validate_messages off nothing was checked, so nothing is lost"
        );
    }

    #[test]
    fn the_request_shape_warning_names_the_surfaces_and_the_fix() {
        assert_eq!(request_shape_check_warning(&[]), None);
        assert_eq!(
            request_shape_check_warning(&["alpha", "beta"]).unwrap(),
            "2 A2A surface(s) checked the A2A request shape before ([a2a] validate_messages, on by default) and now \
             check only the JSON-RPC envelope: \"alpha\", \"beta\". Set Message validation to \"Envelope + A2A \
             fields\" (access_point.a2a.validation = \"full\") on any that should keep refusing malformed A2A \
             messages"
        );
    }

    #[test]
    fn the_request_shape_warning_caps_and_escapes_the_names() {
        let names: Vec<String> = (1..=25)
            .map(|n| format!("s{n}"))
            .collect();
        let names: Vec<&str> = names
            .iter()
            .map(String::as_str)
            .collect();
        let warning = request_shape_check_warning(&names).unwrap();
        assert!(warning.starts_with("25 A2A surface(s)"), "{warning}");
        assert!(warning.contains("\"s20\" and 5 more."), "{warning}");
        assert!(!warning.contains("\"s21\""), "{warning}");

        let escaped = request_shape_check_warning(&["line\nbreak"]).unwrap();
        assert!(escaped.contains("\"line\\nbreak\""), "{escaped}");
        assert!(!escaped.contains('\n'), "a surface name cannot break the log line: {escaped}");
    }

    /// The surfaces named are stored with settings, so a later load has none to
    /// give settings to and the warning is not repeated.
    #[tokio::test]
    async fn surfaces_that_lost_the_request_shape_check_are_stored_so_the_warning_is_logged_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut surfaces = listed(&store, vec![a2a_surface("alpha", "https://a2a.internal/a2a", None)]).await;
        let retired = RetiredA2aSwitches::default();
        assert_eq!(names_losing_request_shape_check(&retired, &surfaces), vec!["alpha"]);

        carry_over_a2a_settings(&store, &mut surfaces, true, || Ok(retired)).await;

        let stored = store
            .get("alpha")
            .await
            .expect("get")
            .expect("the carried settings are stored");
        assert!(
            stored
                .access_point
                .a2a
                .is_some()
        );
        let mut reloaded = vec![stored];
        carry_over_a2a_settings(&store, &mut reloaded, true, || panic!("a later load gives no surface settings")).await;
    }

    #[test]
    fn a2a_proxy_surfaces_given_envelope_despite_validation_off_are_named() {
        let surfaces = [
            a2a_surface("proxy", "a2a-proxy://worker", None),
            a2a_surface("url", "https://a2a.internal/a", None),
            with_variant_target(a2a_surface("proxy-url", "a2a-proxy://worker", None), "https://a2a.internal/b"),
        ];
        let off = RetiredA2aSwitches {
            validate_messages: Some(false),
            legacy_compatibility: None,
        };
        let names = names_given_envelope_despite_validation_off(&off, &surfaces);
        assert_eq!(names, vec!["proxy"], "only surfaces whose Targets are all A2A proxies");
        assert_eq!(
            envelope_despite_validation_off_warning(&names).unwrap(),
            "1 A2A surface(s) whose Targets are all A2A proxies were given validation=envelope although [a2a] \
             validate_messages is false, because an A2A proxy Target always checks the JSON-RPC envelope: \
             \"proxy\". Their callers must send a single, well-formed JSON-RPC 2.0 request"
        );
        for validate_messages in [None, Some(true)] {
            let retired = RetiredA2aSwitches {
                validate_messages,
                legacy_compatibility: None,
            };
            assert!(names_given_envelope_despite_validation_off(&retired, &surfaces).is_empty());
        }
        assert_eq!(envelope_despite_validation_off_warning(&[]), None);
    }

    #[test]
    fn fabric_surfaces_given_settings_are_named_with_what_they_now_refuse() {
        assert!(has_fabric_target(&a2a_surface("fabric", "fabric://peer/agent", None)));
        assert!(has_fabric_target(&with_variant_target(
            a2a_surface("url-fabric", "https://a2a.internal/a", None),
            "fabric://peer/agent"
        )));
        assert!(!has_fabric_target(&a2a_surface("url", "https://a2a.internal/a", None)));

        let envelope = settings(&["0.3", "1.0"], A2aValidation::Envelope);
        assert_eq!(
            fabric_settings_warning(&["fabric"], &envelope).unwrap(),
            "1 fabric:// surface(s) apply their A2A settings on this gateway before sending a request over the \
             fabric (accepted versions 0.3, 1.0, validation=envelope): \"fabric\". A request with an A2A-Version \
             they do not accept or an invalid JSON-RPC envelope is refused here instead of being forwarded"
        );
        let off = settings(&["0.3", "1.0"], A2aValidation::Off);
        assert!(
            fabric_settings_warning(&["fabric"], &off)
                .unwrap()
                .contains("A request with an A2A-Version they do not accept is refused here")
        );
        assert_eq!(fabric_settings_warning(&[], &envelope), None);
    }

    /// A block an API edit stored while the load ran is kept, with the rest of
    /// that edit, rather than replaced by the copy listed at the start.
    #[tokio::test]
    async fn a_block_stored_meanwhile_is_kept_and_the_ids_given_settings_are_returned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let edited = a2a_surface(
            "s-edited",
            "https://a2a.internal/edited",
            Some(serde_json::to_value(settings(&["1.0"], A2aValidation::Full)).unwrap()),
        );
        store
            .save(&edited)
            .await
            .unwrap();
        let mut surfaces = vec![
            a2a_surface("s-edited", "https://a2a.internal/listed", None),
            a2a_surface("s-old", "https://a2a.internal/old", None),
            mcp_surface_with_mapping("s-mcp"),
        ];
        listed(&store, vec![surfaces[1].clone()]).await;

        let given = carry_over_a2a_settings(&store, &mut surfaces, true, || Ok(RetiredA2aSwitches::default())).await;

        assert_eq!(given, vec!["s-edited".to_string(), "s-old".to_string()]);
        assert_eq!(surfaces[0].access_point.a2a, Some(settings(&["1.0"], A2aValidation::Full)));
        assert_eq!(surfaces[0].target.endpoint, "https://a2a.internal/edited", "the stored edit is kept whole");
        let stored = store
            .get("s-edited")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.access_point.a2a, Some(settings(&["1.0"], A2aValidation::Full)), "not overwritten");
        assert_eq!(surfaces[1].access_point.a2a, Some(settings(&["0.3", "1.0"], A2aValidation::Envelope)));
    }

    /// A surface deleted, or moved to another protocol, after it was listed is
    /// not stored again from the listed copy.
    #[tokio::test]
    async fn a_surface_deleted_or_moved_to_another_protocol_meanwhile_is_not_stored_again() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut moved = mcp_surface_with_mapping("s-moved");
        moved
            .access_point
            .header_metadata_mapping = None;
        store
            .save(&moved)
            .await
            .unwrap();
        let mut surfaces = vec![
            a2a_surface("s-deleted", "https://a2a.internal/deleted", None),
            a2a_surface("s-moved", "https://a2a.internal/moved", None),
        ];

        let given = carry_over_a2a_settings(&store, &mut surfaces, true, || Ok(RetiredA2aSwitches::default())).await;

        assert!(given.is_empty(), "{given:?}");
        assert_eq!(surfaces.len(), 1, "the deleted surface is dropped from the list");
        assert!(
            store
                .get("s-deleted")
                .await
                .unwrap()
                .is_none(),
            "a deleted surface is not stored again"
        );
        let stored = store
            .get("s-moved")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.access_point.a2a, None, "the stored MCP surface is left as it is");
        assert_eq!(stored.access_point.protocol, moved.access_point.protocol);
        assert_eq!(
            surfaces[0]
                .access_point
                .protocol,
            moved.access_point.protocol,
            "the listed copy is replaced by the stored one"
        );
    }

    /// A Standby node gives the settings in memory and writes nothing.
    #[tokio::test]
    async fn without_persist_the_settings_are_given_in_memory_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut surfaces = listed(&store, vec![a2a_surface("s-old", "https://a2a.internal/a2a", None)]).await;

        let given = carry_over_a2a_settings(&store, &mut surfaces, false, || Ok(RetiredA2aSwitches::default())).await;

        assert_eq!(given, vec!["s-old".to_string()]);
        assert_eq!(surfaces[0].access_point.a2a, Some(settings(&["0.3", "1.0"], A2aValidation::Envelope)));
        let stored = store
            .get("s-old")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.access_point.a2a, None, "nothing is written");
    }

    #[tokio::test]
    async fn nothing_is_returned_when_every_surface_has_settings_or_the_settings_file_is_unreadable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut unreadable = vec![a2a_surface("s-old", "https://a2a.internal/a", None)];
        assert!(
            carry_over_a2a_settings(&store, &mut unreadable, true, || Err("settings.json: EOF".to_string()))
                .await
                .is_empty()
        );
        let mut own = vec![a2a_surface(
            "s-own",
            "https://a2a.internal/a",
            Some(serde_json::to_value(settings(&["1.0"], A2aValidation::Envelope)).unwrap()),
        )];
        assert!(
            carry_over_a2a_settings(&store, &mut own, true, || panic!("not read"))
                .await
                .is_empty()
        );
    }

    /// With the `local` source the retired switches are carried over; any other
    /// source serves surfaces without settings with the defaults, so a switch
    /// that would have changed them is reported as not applied.
    #[test]
    fn startup_warnings_say_whether_the_retired_switches_apply() {
        let off = RetiredA2aSwitches {
            validate_messages: Some(false),
            legacy_compatibility: Some(false),
        };
        let local = off.startup_warnings("local");
        assert_eq!(local.len(), 1);
        assert!(local[0].starts_with("[a2a] validate_messages is deprecated: validation is set per A2A surface"));

        let dynamodb = off.startup_warnings("dynamodb");
        assert_eq!(dynamodb.len(), 2);
        assert!(
            dynamodb[0].starts_with(
                "[a2a] validate_messages is deprecated and is not applied with the \"dynamodb\" configuration source"
            ),
            "{}",
            dynamodb[0]
        );
        assert!(
            dynamodb[1].starts_with(
                "The retired a2a_legacy_compatibility setting is off but is not applied with the \"dynamodb\""
            ),
            "{}",
            dynamodb[1]
        );

        assert!(
            RetiredA2aSwitches::default()
                .startup_warnings("dynamodb")
                .is_empty()
        );
        let flag_on = RetiredA2aSwitches {
            validate_messages: None,
            legacy_compatibility: Some(true),
        };
        assert!(
            flag_on
                .startup_warnings("dynamodb")
                .is_empty(),
            "a flag that changes nothing is not reported"
        );
    }
}
