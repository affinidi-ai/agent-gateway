use crate::identity::state::IdentityApiState;
use axum::{Json, extract::State, http::StatusCode};

/// (DID, agent_identity_fields, channel_config_id, channel_name, is_local, verified)
type IdentityInfo = (String, serde_json::Value, Option<String>, Option<String>, bool, bool);

/// (channel_stats_entries, identity_hash, agent_identity_fields, channel_config_id, is_local, verified)
type DidStatsEntry =
    (Vec<(String, String, usize, usize, usize, usize)>, String, serde_json::Value, Option<String>, bool, bool);

/// Get agents for visualization - returns identity_channel_stats plus last_payload for each identity
pub async fn get_agents(
    State(state): State<IdentityApiState>
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Get identity_channel_stats from metrics store
    let identity_stats = state
        .metrics_store
        .get_identity_channel_stats()
        .await;

    // Get all identities from the identity store to enrich with DIDs and payloads
    let identities = state
        .vc_issuer
        .get_identity_store()
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list identities: {}", e)))?;

    // Get channel configuration to resolve channel names
    let current_config = state
        .channel_manager
        .get_config()
        .await;
    let config_id_to_name: std::collections::HashMap<String, String> = current_config
        .surfaces
        .iter()
        .map(|s| (s.surface_id.clone(), s.name.clone()))
        .collect();

    // Create a map of identity_hash -> (DID, agent_identity fields, channel_config_id, channel_name, is_local, verified)
    let identity_map: std::collections::HashMap<String, IdentityInfo> = identities
        .into_iter()
        .map(|r| {
            let fields_json = serde_json::to_value(&r.identity_fields).unwrap_or_default();
            let channel_name = r
                .channel_config_id
                .as_ref()
                .and_then(|id| {
                    config_id_to_name
                        .get(id)
                        .cloned()
                });
            (
                r.identity_hash.clone(),
                (r.did.clone(), fields_json, r.channel_config_id.clone(), channel_name, r.is_local, r.verified),
            )
        })
        .collect();

    // Get last_payloads for all identities
    let mut last_payloads = std::collections::HashMap::new();
    for hash in identity_map.keys() {
        if let Some(payload) = state
            .metrics_store
            .get_last_payload(hash)
            .await
        {
            last_payloads.insert(hash.clone(), payload);
        }
    }

    // Group identity_channel_stats by DID to avoid duplicates
    // The same DID can appear with multiple channel_config_ids, so we need to aggregate
    let mut did_stats: std::collections::HashMap<String, DidStatsEntry> = std::collections::HashMap::new();

    for stat in identity_stats {
        // Try to find identity by hash, or with "external:" prefix for external DIDs
        let identity_data = identity_map
            .get(&stat.identity_hash)
            .cloned()
            .or_else(|| {
                // Try with "external:" prefix for external DIDs
                let external_key = format!("external:{}", stat.identity_hash);
                identity_map
                    .get(&external_key)
                    .cloned()
            })
            .unwrap_or_else(|| (stat.identity_hash.clone(), serde_json::json!({}), None, None, false, false));

        let (did, agent_identity, identity_channel_config_id, _channel_name, is_local, verified) = identity_data;

        // Map the stat's channel_config_id to channel name for display
        let stat_channel_name = config_id_to_name
            .get(&stat.channel_config_id)
            .cloned()
            .unwrap_or_else(|| stat.channel_config_id.clone());

        let entry = did_stats
            .entry(did.clone())
            .or_insert_with(|| {
                (
                    Vec::new(),
                    stat.identity_hash.clone(),
                    agent_identity.clone(),
                    identity_channel_config_id.clone(),
                    is_local,
                    verified,
                )
            });

        // Add this channel's stats to the list
        entry.0.push((
            stat.channel_config_id,
            stat_channel_name,
            stat.total_count,
            stat.success_count,
            stat.deny_count,
            stat.fault_count,
        ));
    }

    // Transform into agents list - one entry per DID
    let mut agents: Vec<serde_json::Value> = did_stats
        .into_iter()
        .map(|(did, (channel_stats, identity_hash, agent_identity, identity_channel_config_id, is_local, verified))| {
            let last_payload = last_payloads
                .get(&identity_hash)
                .cloned();

            // Aggregate totals across all channels for this DID
            let total_count: usize = channel_stats
                .iter()
                .map(|(_, _, total, _, _, _)| total)
                .sum();
            let success_count: usize = channel_stats
                .iter()
                .map(|(_, _, _, success, _, _)| success)
                .sum();
            let deny_count: usize = channel_stats
                .iter()
                .map(|(_, _, _, _, deny, _)| deny)
                .sum();
            let fault_count: usize = channel_stats
                .iter()
                .map(|(_, _, _, _, _, fault)| fault)
                .sum();

            // Use the first channel's info for primary channel display (could be improved to show all)
            let (primary_channel_config_id, primary_channel_name) = channel_stats
                .first()
                .map(|(id, name, _, _, _, _)| (id.clone(), name.clone()))
                .unwrap_or_else(|| ("unknown".to_string(), "None".to_string()));

            serde_json::json!({
                "identity_hash": identity_hash,
                "did": did,
                "is_local": is_local,
                "verified": verified,
                "channel_name": primary_channel_name,
                "total_count": total_count,
                "success_count": success_count,
                "deny_count": deny_count,
                "fault_count": fault_count,
                "agent_identity": agent_identity,
                "last_payload": last_payload,
                "channel_config_id": primary_channel_config_id,
                "identity_channel_name": identity_channel_config_id.and_then(|id| config_id_to_name.get(&id).cloned()),
                "channel_usage": channel_stats.iter().map(|(id, name, total, success, deny, fault)| {
                    serde_json::json!({
                        "channel_config_id": id,
                        "channel_name": name,
                        "total_count": total,
                        "success_count": success,
                        "deny_count": deny,
                        "fault_count": fault,
                    })
                }).collect::<Vec<_>>(),
            })
        })
        .collect();

    // Sort by total usage count descending
    agents.sort_by(|a, b| {
        let count_a = a
            .get("total_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let count_b = b
            .get("total_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        count_b.cmp(&count_a)
    });

    Ok(Json(serde_json::json!({
        "agents": agents
    })))
}
