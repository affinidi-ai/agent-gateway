//! Save-time posture validation for MPP payment surfaces.
//!
//! Pure, I/O-free checks run when a payment surface carrying an MPP
//! `payment_policy` is created or updated. They reject production-unsafe
//! crypto configuration before it reaches disk and the hot-reload path.
//! Only crypto methods (`tempo`/`crypto`/`evm`) are governed by
//! `crypto_verification_mode`; card/Stripe and other off-chain methods are not
//! affected.

use super::nonce_guard::MAX_REPLAY_TTL_SECS;
use super::types::{MppConfig, MppVerificationMode};

/// Payment-method names verified through the crypto (`crypto_verification_mode`)
/// path. Only these are subject to on-chain posture rules.
const CRYPTO_METHODS: &[&str] = &["tempo", "crypto", "evm"];

fn is_crypto_method(method: &str) -> bool {
    CRYPTO_METHODS.contains(
        &method
            .trim()
            .to_ascii_lowercase()
            .as_str(),
    )
}

/// Known non-production CAIP-2 network ids not caught by the substring markers
/// below -- numeric testnet chain ids whose name carries no test-like marker.
const KNOWN_TEST_NETWORK_IDS: &[&str] = &[
    "eip155:1337",     // Local dev chain
    "eip155:31337",    // Anvil / Hardhat
    "eip155:11155111", // Ethereum Sepolia
    "eip155:84532",    // Base Sepolia
    "eip155:421614",   // Arbitrum Sepolia
    "eip155:11155420", // Optimism Sepolia
    "eip155:80002",    // Polygon Amoy
    "eip155:43113",    // Avalanche Fuji
];

/// Substrings that mark a network name or id as a non-production chain.
const TEST_NETWORK_MARKERS: &[&str] =
    &["sepolia", "goerli", "holesky", "mumbai", "amoy", "fuji", "devnet", "testnet", "localhost", "anvil", "hardhat"];

/// Networks that are unambiguously test/dev chains, so a crypto method on one
/// of them is exempt from the mainnet-only posture rules below. Unknown
/// networks (including an unset one) are conservatively treated as mainnet.
fn is_test_network(network: &str) -> bool {
    let net = network
        .trim()
        .to_ascii_lowercase();
    KNOWN_TEST_NETWORK_IDS.contains(&net.as_str())
        || TEST_NETWORK_MARKERS
            .iter()
            .any(|marker| net.contains(marker))
}

/// Validate one MPP config's crypto verification posture. `label` identifies the
/// config (base or a named variant) in the returned message. Returns
/// `Err(reason)` on the first failing rule.
pub fn validate_mpp_posture(
    cfg: &MppConfig,
    label: &str,
) -> Result<(), String> {
    if let Some(reason) = passthrough_mainnet_rejection(cfg, label) {
        return Err(reason);
    }
    if let Some(reason) = mainnet_confirmation_rejection(cfg, label) {
        return Err(reason);
    }
    if let Some(reason) = challenge_ttl_exceeds_replay_window(cfg, label) {
        return Err(reason);
    }
    Ok(())
}

/// The mainnet network id of the first crypto payment method that is not
/// confirmed to be a test/dev chain, if any. A method with **no `network`
/// set** is treated as safe here (on-chain modes fail closed at runtime
/// without one to resolve an RPC endpoint against); `passthrough` cannot rely
/// on that runtime failure since it never touches the chain, so it uses the
/// stricter [`first_passthrough_unsafe_network`] instead.
fn first_mainnet_crypto_network(cfg: &MppConfig) -> Option<&str> {
    cfg.payment_methods
        .iter()
        .filter(|m| is_crypto_method(&m.method))
        .filter_map(|m| m.network.as_deref())
        .find(|net| !is_test_network(net))
}

/// The network of the first crypto payment method that is unsafe to accept via
/// `Passthrough` verification: any network not confirmed to be a test/dev
/// chain, **including a method with no `network` set at all**. Passthrough
/// never touches the chain, so an absent `network` cannot be relied on to fail
/// closed later the way it does for the on-chain modes -- omitting it must not
/// be a way to evade this check.
fn first_passthrough_unsafe_network(cfg: &MppConfig) -> Option<&str> {
    cfg.payment_methods
        .iter()
        .filter(|m| is_crypto_method(&m.method))
        .find(|m| {
            !m.network
                .as_deref()
                .is_some_and(is_test_network)
        })
        .map(|m| {
            m.network
                .as_deref()
                .unwrap_or("<unspecified>")
        })
}

/// `Passthrough` accepts any claimed crypto proof without touching the chain, so
/// it must never front a mainnet (or unspecified-network) crypto method on a
/// real payment surface.
fn passthrough_mainnet_rejection(
    cfg: &MppConfig,
    label: &str,
) -> Option<String> {
    if cfg.crypto_verification_mode != MppVerificationMode::Passthrough {
        return None;
    }
    first_passthrough_unsafe_network(cfg).map(|net| {
        format!(
            "{label}: crypto_verification_mode 'passthrough' accepts any proof without an on-chain check; network '{net}' looks like mainnet or is unspecified -- use 'onchain', 'signature', or 'full'"
        )
    })
}

/// On-chain verification of a mainnet crypto method must wait for at least one
/// confirmation; 0-conf mainnet settlement is unsafe and is rejected. Only the
/// on-chain modes (`Onchain`/`Full`) consult confirmations.
fn mainnet_confirmation_rejection(
    cfg: &MppConfig,
    label: &str,
) -> Option<String> {
    let onchain = matches!(cfg.crypto_verification_mode, MppVerificationMode::Onchain | MppVerificationMode::Full);
    if !onchain || cfg.min_confirmations >= 1 {
        return None;
    }
    first_mainnet_crypto_network(cfg).map(|net| {
        format!("{label}: network '{net}' looks like mainnet; set min_confirmations >= 1 for on-chain verification")
    })
}

/// The single-use replay guard only remembers a spent settlement for up to
/// [`MAX_REPLAY_TTL_SECS`] (a memory-bound ceiling). A `challenge_ttl_seconds`
/// beyond that means the guard forgets a spent credential while the challenge
/// itself is still valid -- letting the same settlement be re-verified and
/// re-granted access.
fn challenge_ttl_exceeds_replay_window(
    cfg: &MppConfig,
    label: &str,
) -> Option<String> {
    if cfg.challenge_ttl_seconds <= MAX_REPLAY_TTL_SECS {
        return None;
    }
    Some(format!(
        "{label}: challenge_ttl_seconds ({}) exceeds the maximum replay-protection window ({}s) -- the single-use guard would forget a spent credential while the challenge is still valid, allowing it to be re-verified and re-granted",
        cfg.challenge_ttl_seconds, MAX_REPLAY_TTL_SECS
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpp::types::MppPaymentMethod;

    fn crypto_method(network: Option<&str>) -> MppPaymentMethod {
        MppPaymentMethod {
            method: "tempo".to_string(),
            intent: "charge".to_string(),
            currency: "eip155:8453/erc20:0xUSDC".to_string(),
            recipient: "0xrecipient".to_string(),
            amount: "1000000".to_string(),
            network: network.map(str::to_string),
        }
    }

    fn config_with(
        mode: MppVerificationMode,
        min_confirmations: u64,
        methods: Vec<MppPaymentMethod>,
    ) -> MppConfig {
        MppConfig {
            crypto_verification_mode: mode,
            min_confirmations,
            payment_methods: methods,
            ..MppConfig::default()
        }
    }

    #[test]
    fn passthrough_mainnet_is_rejected() {
        let cfg = config_with(MppVerificationMode::Passthrough, 0, vec![crypto_method(Some("eip155:8453"))]);
        let err = validate_mpp_posture(&cfg, "cfg").unwrap_err();
        assert!(err.contains("passthrough"), "message names the mode: {err}");
        assert!(err.contains("eip155:8453"), "message names the network: {err}");
    }

    #[test]
    fn passthrough_testnet_is_allowed() {
        let cfg = config_with(MppVerificationMode::Passthrough, 0, vec![crypto_method(Some("eip155:84532-sepolia"))]);
        assert!(validate_mpp_posture(&cfg, "cfg").is_ok());
    }

    #[test]
    fn passthrough_known_numeric_testnet_id_is_allowed() {
        let cfg = config_with(MppVerificationMode::Passthrough, 0, vec![crypto_method(Some("eip155:84532"))]);
        assert!(validate_mpp_posture(&cfg, "cfg").is_ok());
    }

    #[test]
    fn passthrough_with_no_network_is_rejected() {
        let cfg = config_with(MppVerificationMode::Passthrough, 0, vec![crypto_method(None)]);
        let err = validate_mpp_posture(&cfg, "cfg").unwrap_err();
        assert!(err.contains("passthrough"), "message names the mode: {err}");
        assert!(err.contains("unspecified"), "message flags the missing network: {err}");
    }

    #[test]
    fn passthrough_card_only_is_allowed() {
        let card = MppPaymentMethod {
            method: "card".to_string(),
            intent: "charge".to_string(),
            currency: "usd".to_string(),
            recipient: "acct_test".to_string(),
            amount: "1.00".to_string(),
            network: None,
        };
        let cfg = config_with(MppVerificationMode::Passthrough, 0, vec![card]);
        assert!(validate_mpp_posture(&cfg, "cfg").is_ok());
    }

    #[test]
    fn onchain_mainnet_zero_confirmations_is_rejected() {
        let cfg = config_with(MppVerificationMode::Onchain, 0, vec![crypto_method(Some("eip155:8453"))]);
        let err = validate_mpp_posture(&cfg, "cfg").unwrap_err();
        assert!(err.contains("min_confirmations"), "unexpected: {err}");
    }

    #[test]
    fn onchain_mainnet_with_confirmations_is_allowed() {
        let cfg = config_with(MppVerificationMode::Onchain, 1, vec![crypto_method(Some("eip155:8453"))]);
        assert!(validate_mpp_posture(&cfg, "cfg").is_ok());
    }

    #[test]
    fn signature_mode_is_exempt_from_confirmation_rule() {
        let cfg = config_with(MppVerificationMode::Signature, 0, vec![crypto_method(Some("eip155:8453"))]);
        assert!(validate_mpp_posture(&cfg, "cfg").is_ok());
    }

    #[test]
    fn full_mode_mainnet_zero_confirmations_is_rejected() {
        let cfg = config_with(MppVerificationMode::Full, 0, vec![crypto_method(Some("eip155:8453"))]);
        assert!(validate_mpp_posture(&cfg, "cfg").is_err());
    }

    #[test]
    fn default_config_passes() {
        assert!(validate_mpp_posture(&MppConfig::default(), "cfg").is_ok());
    }

    #[test]
    fn challenge_ttl_within_replay_window_is_allowed() {
        let cfg = MppConfig {
            challenge_ttl_seconds: MAX_REPLAY_TTL_SECS,
            ..MppConfig::default()
        };
        assert!(validate_mpp_posture(&cfg, "cfg").is_ok());
    }

    #[test]
    fn challenge_ttl_beyond_replay_window_is_rejected() {
        let cfg = MppConfig {
            challenge_ttl_seconds: MAX_REPLAY_TTL_SECS + 1,
            ..MppConfig::default()
        };
        let err = validate_mpp_posture(&cfg, "cfg").unwrap_err();
        assert!(err.contains("challenge_ttl_seconds"), "unexpected: {err}");
    }
}
