//! On-chain and signature verification for MPP crypto payment proofs.
//!
//! Supports three verification strategies:
//! - **Onchain**: fetch EVM transaction receipt via RPC, verify status + amount + recipient
//! - **Signature**: offline EIP-3009 / Permit2 EIP-712 signature verification (no RPC)
//! - **Full**: requires *both* a valid offline signature and a successful on-chain
//!   receipt check; either one missing/failing rejects the payment

use tracing::info;

use super::types::{MppConfig, MppCredential, MppVerificationMode};

/// Verify a crypto payment proof according to the configured verification mode.
///
/// Returns `Ok(reference_string)` on success (tx hash, signer address, etc.).
pub async fn verify_crypto_proof(
    credential: &MppCredential,
    config: &MppConfig,
) -> Result<String, String> {
    let payload = &credential.payload;

    match config.crypto_verification_mode {
        MppVerificationMode::Passthrough => passthrough_reference(payload),
        MppVerificationMode::Onchain => verify_onchain(credential, config).await,
        MppVerificationMode::Signature => verify_signature(credential, config),
        MppVerificationMode::Full => {
            // Both proofs are required — a missing or failing signature, or a
            // missing or failing on-chain settlement, rejects the payment.
            let sig_ref = verify_signature(credential, config)?;
            if payload
                .get("tx_hash")
                .and_then(|v| v.as_str())
                .is_none()
            {
                return Err(
                    "Full verification requires 'tx_hash' in credential payload for the on-chain check".to_string()
                );
            }
            let tx_ref = verify_onchain(credential, config).await?;
            Ok(format!("{}+{}", sig_ref, tx_ref))
        }
    }
}

/// Passthrough: extract a reference without verification.
fn passthrough_reference(payload: &serde_json::Value) -> Result<String, String> {
    let reference = payload
        .get("proof")
        .or_else(|| payload.get("tx_hash"))
        .and_then(|v| v.as_str())
        .unwrap_or("crypto-verified")
        .to_string();
    Ok(reference)
}

// ───────────────────────────────────────────────────────────────────
// On-chain EVM transaction verification
// ───────────────────────────────────────────────────────────────────

/// Verify an EVM transaction receipt on-chain via JSON-RPC.
async fn verify_onchain(
    credential: &MppCredential,
    config: &MppConfig,
) -> Result<String, String> {
    let tx_hash = credential
        .payload
        .get("tx_hash")
        .and_then(|v| v.as_str())
        .ok_or("On-chain verification requires 'tx_hash' in credential payload")?;

    // Decode the challenge request to get expected amount/currency/recipient/network
    let request = decode_challenge_request(&credential.challenge.request)?;
    let network = request
        .get("network")
        .and_then(|v| v.as_str())
        .ok_or("Challenge request missing 'network' for on-chain verification")?;

    let rpc_url = config
        .rpc_endpoints
        .get(network)
        .ok_or_else(|| format!("No RPC endpoint configured for network '{}'", network))?;

    verify_evm_transaction(tx_hash, rpc_url, &request, config).await
}

/// Fetch and verify an EVM transaction receipt.
async fn verify_evm_transaction(
    tx_hash: &str,
    rpc_url: &str,
    request: &serde_json::Value,
    config: &MppConfig,
) -> Result<String, String> {
    use alloy::providers::{Provider, ProviderBuilder};

    let url: reqwest::Url = rpc_url
        .parse()
        .map_err(|e| format!("Invalid RPC URL '{}': {}", rpc_url, e))?;

    let provider = ProviderBuilder::new().connect_http(url);

    // Parse 0x-prefixed hex hash → [u8; 32]
    let hash_bytes: [u8; 32] = hex::decode(tx_hash.trim_start_matches("0x"))
        .map_err(|e| format!("Invalid tx_hash hex: {}", e))?
        .try_into()
        .map_err(|_| "tx_hash must be 32 bytes")?;

    let tx_b256: alloy::primitives::B256 = hash_bytes.into();

    // Fetch receipt (bounded by the configured verification timeout)
    let rpc_timeout = tokio::time::Duration::from_millis(
        config
            .verification_timeout_ms
            .max(1000),
    );
    let receipt = tokio::time::timeout(rpc_timeout, provider.get_transaction_receipt(tx_b256))
        .await
        .map_err(|_| format!("RPC timeout fetching receipt for {}", tx_hash))?
        .map_err(|e| format!("RPC error fetching receipt: {}", e))?
        .ok_or_else(|| format!("Transaction {} not found on chain", tx_hash))?;

    // Must be successful
    if !receipt.status() {
        return Err(format!("Transaction {} failed on-chain", tx_hash));
    }

    // Check confirmations
    if config.min_confirmations > 0 {
        let latest_block = tokio::time::timeout(rpc_timeout, provider.get_block_number())
            .await
            .map_err(|_| "RPC timeout fetching block number".to_string())?
            .map_err(|e| format!("RPC error: {}", e))?;

        let tx_block = receipt
            .block_number
            .ok_or("Transaction block number not available")?;
        let confirmations = latest_block.saturating_sub(tx_block);
        if confirmations < config.min_confirmations {
            return Err(format!(
                "Insufficient confirmations: {} (required {})",
                confirmations, config.min_confirmations
            ));
        }
    }

    // Fetch full transaction for value/to checks
    let tx = tokio::time::timeout(rpc_timeout, provider.get_transaction_by_hash(tx_b256))
        .await
        .map_err(|_| "RPC timeout fetching transaction".to_string())?
        .map_err(|e| format!("RPC error: {}", e))?
        .ok_or("Transaction not found")?;

    // Expected values from the challenge request
    let expected_recipient = request
        .get("recipient")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let expected_amount_str = request
        .get("amount")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let currency = request
        .get("currency")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Determine if this is a token transfer or native value transfer
    let is_token_transfer = currency.starts_with("0x") || currency.starts_with("0X");

    if is_token_transfer {
        verify_erc20_transfer(&receipt, currency, expected_recipient, expected_amount_str, tx_hash)
    } else {
        verify_native_transfer(&tx, expected_recipient, expected_amount_str, tx_hash)
    }
}

/// A decoded ERC-20 `Transfer` event reduced to the fields the payment binding
/// checks: the emitting token contract, the recipient, and the amount (token and
/// recipient are lowercased hex without the `0x` prefix; amount in base units).
#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedTransfer {
    token: String,
    recipient: String,
    amount: u128,
}

/// Bind an on-chain settlement to the challenge asset.
///
/// A transaction can emit any number of `Transfer` events — a swap or router call
/// emits several, often for unrelated tokens — so the payment is settled only when
/// some Transfer was emitted by the challenge's token contract, to the challenge
/// recipient, for the exact challenge amount. A transfer of the wrong asset, to
/// the wrong address, or for the wrong amount can never satisfy it.
fn match_erc20_settlement(
    transfers: &[DecodedTransfer],
    expected_token: &str,
    expected_recipient: &str,
    expected_amount: u128,
) -> Result<(), String> {
    let token = expected_token
        .trim_start_matches("0x")
        .to_lowercase();
    let recipient = expected_recipient
        .trim_start_matches("0x")
        .to_lowercase();

    let of_token: Vec<&DecodedTransfer> = transfers
        .iter()
        .filter(|t| t.token == token)
        .collect();
    if of_token.is_empty() {
        return Err(format!("no ERC-20 Transfer of expected token {} (wrong asset?)", token));
    }

    let to_recipient: Vec<&DecodedTransfer> = of_token
        .iter()
        .copied()
        .filter(|t| t.recipient == recipient)
        .collect();
    if to_recipient.is_empty() {
        return Err(format!("token {} transferred, but not to expected recipient {}", token, recipient));
    }

    if to_recipient
        .iter()
        .any(|t| t.amount == expected_amount)
    {
        return Ok(());
    }

    let got = to_recipient
        .iter()
        .map(|t| t.amount.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!("ERC-20 Transfer amount mismatch: expected exactly {}, got [{}]", expected_amount, got))
}

/// Verify an ERC-20 Transfer in the receipt logs, bound to the challenge's token
/// contract, recipient, and exact amount.
fn verify_erc20_transfer(
    receipt: &alloy::rpc::types::TransactionReceipt,
    expected_token: &str,
    expected_recipient: &str,
    expected_amount_str: &str,
    tx_hash: &str,
) -> Result<String, String> {
    // ERC-20 Transfer(address,address,uint256)
    const TRANSFER_TOPIC: &str = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

    let mut transfers = Vec::new();
    for log in receipt.inner.logs() {
        let is_transfer = log
            .topics()
            .first()
            .map(|t| {
                format!("{:?}", t)
                    .trim_start_matches("0x")
                    .eq_ignore_ascii_case(TRANSFER_TOPIC)
            })
            .unwrap_or(false);
        if !is_transfer {
            continue;
        }

        // Transfer has three topics: signature, indexed `from`, indexed `to`.
        let Some(recipient_topic) = log.topics().get(2) else {
            continue;
        };

        let token = format!("{:?}", log.inner.address)
            .trim_start_matches("0x")
            .to_lowercase();
        let recipient = format!("{:?}", recipient_topic)
            .trim_start_matches("0x")
            .chars()
            .skip(24)
            .collect::<String>()
            .to_lowercase();
        let amount_bytes = hex::decode(
            log.data()
                .data
                .to_string()
                .trim_start_matches("0x"),
        )
        .map_err(|e| format!("Failed to decode transfer amount: {}", e))?;
        let amount = to_u128_from_be_bytes(&amount_bytes)
            .map_err(|e| format!("Failed to decode transfer amount: {} (tx {})", e, tx_hash))?;

        transfers.push(DecodedTransfer { token, recipient, amount });
    }

    let expected_amount = parse_amount(expected_amount_str)?;
    match_erc20_settlement(&transfers, expected_token, expected_recipient, expected_amount)
        .map_err(|e| format!("{} (tx {})", e, tx_hash))?;

    info!(
        "[mpp_onchain] Transaction {} verified: ERC-20 {} transfer of {} to {}",
        tx_hash, expected_token, expected_amount, expected_recipient
    );
    Ok(tx_hash.to_string())
}

/// Verify a native ETH/MATIC transfer.
fn verify_native_transfer(
    tx: &alloy::rpc::types::Transaction,
    expected_recipient: &str,
    expected_amount_str: &str,
    tx_hash: &str,
) -> Result<String, String> {
    use alloy::consensus::Transaction as ConsensusTx;

    let actual_to = tx
        .inner
        .to()
        .map(|addr| {
            format!("{:?}", addr)
                .trim_start_matches("0x")
                .to_lowercase()
        })
        .unwrap_or_default();

    let expected_lower = expected_recipient
        .trim_start_matches("0x")
        .to_lowercase();

    if actual_to != expected_lower {
        return Err(format!("Native transfer recipient mismatch: expected {}, got {}", expected_lower, actual_to));
    }

    let actual_amount = tx.inner.value().to::<u128>();
    let expected_amount = parse_amount(expected_amount_str)?;
    verify_amount(actual_amount, expected_amount, tx_hash)
}

fn verify_amount(
    actual: u128,
    expected: u128,
    tx_hash: &str,
) -> Result<String, String> {
    if actual != expected {
        return Err(format!(
            "Native payment amount mismatch: expected exactly {}, got {} (tx {})",
            expected, actual, tx_hash
        ));
    }
    info!("[mpp_onchain] Transaction {} verified: amount={} (expected {})", tx_hash, actual, expected);
    Ok(tx_hash.to_string())
}

fn parse_amount(s: &str) -> Result<u128, String> {
    // Amounts must be an exact integer in the currency's smallest unit (e.g.
    // wei) so exact-match settlement binding is meaningful; a lossy float
    // fallback could silently floor a decimal amount to zero.
    s.parse::<u128>()
        .map_err(|_| format!("Invalid amount format: '{}' (expected an integer in the currency's smallest unit)", s))
}

fn to_u128_from_be_bytes(bytes: &[u8]) -> Result<u128, String> {
    if bytes.len() > 16 {
        let (high, low) = bytes.split_at(bytes.len() - 16);
        if high.iter().any(|&b| b != 0) {
            return Err(format!("amount exceeds u128 range ({} bytes with non-zero high bytes)", bytes.len()));
        }
        Ok(u128::from_be_bytes(low.try_into().unwrap()))
    } else {
        let mut buf = [0u8; 16];
        buf[16 - bytes.len()..].copy_from_slice(bytes);
        Ok(u128::from_be_bytes(buf))
    }
}

// ───────────────────────────────────────────────────────────────────
// EIP-712 Signature verification (offline, no RPC)
// ───────────────────────────────────────────────────────────────────

/// Verify an EIP-3009 or Permit2 signature offline.
fn verify_signature(
    credential: &MppCredential,
    config: &MppConfig,
) -> Result<String, String> {
    let payload = &credential.payload;

    if payload
        .get("authorization")
        .is_some()
        && payload
            .get("signature")
            .is_some()
    {
        verify_eip3009(credential, config)
    } else if payload
        .get("permit2Authorization")
        .is_some()
        && payload
            .get("signature")
            .is_some()
    {
        verify_permit2(credential, config)
    } else {
        Err("No recognizable signature payload (expected 'authorization'+'signature' for EIP-3009, or 'permit2Authorization'+'signature' for Permit2)".into())
    }
}

/// Verify an EIP-3009 `TransferWithAuthorization` signature.
fn verify_eip3009(
    credential: &MppCredential,
    _config: &MppConfig,
) -> Result<String, String> {
    use alloy::primitives::{Address, B256, U256, keccak256};
    use alloy::signers::Signature as AlloySignature;
    use alloy::sol_types::eip712_domain;

    let request = decode_challenge_request(&credential.challenge.request)?;

    let sig_hex = credential
        .payload
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'signature' in payload")?;

    let auth: Eip3009Authorization = serde_json::from_value(
        credential
            .payload
            .get("authorization")
            .cloned()
            .ok_or("Missing 'authorization' in payload")?,
    )
    .map_err(|e| format!("Invalid authorization: {}", e))?;

    // Parse signature (65 bytes: r[32] || s[32] || v[1])
    let sig_bytes =
        hex::decode(sig_hex.trim_start_matches("0x")).map_err(|e| format!("Invalid signature hex: {}", e))?;
    if sig_bytes.len() != 65 {
        return Err(format!("Invalid signature length: expected 65, got {}", sig_bytes.len()));
    }

    let r = U256::try_from_be_slice(&sig_bytes[0..32]).ok_or("Invalid r value")?;
    let s = U256::try_from_be_slice(&sig_bytes[32..64]).ok_or("Invalid s value")?;
    let v_parity = match sig_bytes[64] {
        27 | 0 => false,
        28 | 1 => true,
        v => return Err(format!("Invalid v value: {}", v)),
    };

    let signature = AlloySignature::new(r, s, v_parity);

    // Parse fields
    let from_addr: Address = auth
        .from
        .parse()
        .map_err(|_| "Invalid from address")?;
    let to_addr: Address = auth
        .to
        .parse()
        .map_err(|_| "Invalid to address")?;
    let value: U256 = auth
        .value
        .parse()
        .map_err(|_| "Invalid value")?;
    let valid_after: U256 = auth
        .valid_after
        .parse()
        .map_err(|_| "Invalid validAfter")?;
    let valid_before: U256 = auth
        .valid_before
        .parse()
        .map_err(|_| "Invalid validBefore")?;
    let nonce = B256::from_slice(
        &hex::decode(
            auth.nonce
                .trim_start_matches("0x"),
        )
        .map_err(|e| format!("Invalid nonce: {}", e))?,
    );

    // Time window checks
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if now < valid_after.to::<u64>() {
        return Err("Payment not yet valid (validAfter)".into());
    }
    if now >= valid_before.to::<u64>() {
        return Err("Payment expired (validBefore)".into());
    }

    // Amount check
    let expected_amount_str = request
        .get("amount")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let required: U256 = expected_amount_str
        .parse()
        .map_err(|_| format!("Invalid required amount: {}", expected_amount_str))?;
    if value < required {
        return Err(format!("Insufficient amount: {} < {}", value, required));
    }

    // Recipient check
    let expected_to_str = request
        .get("recipient")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let expected_to: Address = expected_to_str
        .parse()
        .map_err(|_| "Invalid expected recipient address")?;
    if to_addr != expected_to {
        return Err(format!("Recipient mismatch: {} != {}", to_addr, expected_to));
    }

    // Resolve token address and EIP-712 domain params from challenge
    let network = request
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let chain_id: u64 = network
        .strip_prefix("eip155:")
        .ok_or_else(|| format!("Invalid network for EIP-3009: {}", network))?
        .parse()
        .map_err(|e| format!("Invalid chain_id: {}", e))?;

    let token_addr: Address = request
        .get("currency")
        .and_then(|v| v.as_str())
        .ok_or("Missing currency (token address) in challenge")?
        .parse()
        .map_err(|e| format!("Invalid token address: {}", e))?;

    // Token name/version from extra fields in the challenge request
    let token_name = request
        .get("token_name")
        .and_then(|v| v.as_str())
        .unwrap_or("USD Coin");
    let token_version = request
        .get("token_version")
        .and_then(|v| v.as_str())
        .unwrap_or("2");

    // EIP-712 domain
    let domain = eip712_domain! {
        name: token_name.to_string(),
        version: token_version.to_string(),
        chain_id: chain_id,
        verifying_contract: token_addr,
    };

    // TransferWithAuthorization type hash
    let type_hash = keccak256(
        b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
    );

    let mut struct_data = Vec::with_capacity(7 * 32);
    struct_data.extend_from_slice(type_hash.as_slice());
    struct_data.extend_from_slice(&[0u8; 12]);
    struct_data.extend_from_slice(from_addr.as_slice());
    struct_data.extend_from_slice(&[0u8; 12]);
    struct_data.extend_from_slice(to_addr.as_slice());
    struct_data.extend_from_slice(&value.to_be_bytes::<32>());
    struct_data.extend_from_slice(&valid_after.to_be_bytes::<32>());
    struct_data.extend_from_slice(&valid_before.to_be_bytes::<32>());
    struct_data.extend_from_slice(nonce.as_slice());

    let struct_hash = keccak256(&struct_data);
    let domain_separator = domain.hash_struct();

    let mut message = Vec::with_capacity(2 + 32 + 32);
    message.extend_from_slice(b"\x19\x01");
    message.extend_from_slice(domain_separator.as_slice());
    message.extend_from_slice(struct_hash.as_slice());
    let message_hash = keccak256(&message);

    // Recover signer
    let recovered = signature
        .recover_address_from_prehash(&message_hash)
        .map_err(|e| format!("Signature recovery failed: {}", e))?;

    if recovered != from_addr {
        return Err(format!("EIP-3009 signer mismatch: expected {}, recovered {}", from_addr, recovered));
    }

    info!("[mpp_sig] EIP-3009 signature verified: from={} to={} value={}", from_addr, to_addr, value);

    // Keyed by signer + nonce, not signer alone -- two distinct authorizations
    // from the same wallet must not collide in the single-use replay guard.
    Ok(format!("eip3009:{}:{}", from_addr, nonce))
}

/// Verify a Permit2 `permitWitnessTransferFrom` signature.
fn verify_permit2(
    credential: &MppCredential,
    _config: &MppConfig,
) -> Result<String, String> {
    use alloy::primitives::{Address, U256, keccak256};
    use alloy::signers::Signature as AlloySignature;
    use alloy::sol_types::eip712_domain;

    let request = decode_challenge_request(&credential.challenge.request)?;

    let sig_hex = credential
        .payload
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'signature' in payload")?;

    let auth: Permit2Authorization = serde_json::from_value(
        credential
            .payload
            .get("permit2Authorization")
            .cloned()
            .ok_or("Missing 'permit2Authorization' in payload")?,
    )
    .map_err(|e| format!("Invalid permit2Authorization: {}", e))?;

    // Parse signature
    let sig_bytes =
        hex::decode(sig_hex.trim_start_matches("0x")).map_err(|e| format!("Invalid signature hex: {}", e))?;
    if sig_bytes.len() != 65 {
        return Err(format!("Invalid signature length: expected 65, got {}", sig_bytes.len()));
    }

    let r = U256::try_from_be_slice(&sig_bytes[0..32]).ok_or("Invalid r value")?;
    let s = U256::try_from_be_slice(&sig_bytes[32..64]).ok_or("Invalid s value")?;
    let v_parity = match sig_bytes[64] {
        27 | 0 => false,
        28 | 1 => true,
        v => return Err(format!("Invalid v value: {}", v)),
    };
    let signature = AlloySignature::new(r, s, v_parity);

    // Parse addresses/values
    let from_addr: Address = auth
        .from
        .parse()
        .map_err(|_| "Invalid from")?;
    let spender: Address = auth
        .spender
        .parse()
        .map_err(|_| "Invalid spender")?;
    let nonce: U256 = auth
        .nonce
        .parse()
        .map_err(|_| "Invalid nonce")?;
    let deadline: U256 = auth
        .deadline
        .parse()
        .map_err(|_| "Invalid deadline")?;

    let token_addr: Address = auth
        .permitted
        .token
        .parse()
        .map_err(|_| "Invalid permitted.token")?;
    let amount: U256 = auth
        .permitted
        .amount
        .parse()
        .map_err(|_| "Invalid permitted.amount")?;

    let witness_to: Address = auth
        .witness
        .to
        .parse()
        .map_err(|_| "Invalid witness.to")?;
    let witness_valid_after: U256 = auth
        .witness
        .valid_after
        .parse()
        .map_err(|_| "Invalid witness.valid_after")?;
    let witness_extra = auth
        .witness
        .extra
        .clone()
        .unwrap_or_default();

    // Time check
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now >= deadline.to::<u64>() {
        return Err("Permit2 payment expired (deadline)".into());
    }
    if now < witness_valid_after.to::<u64>() {
        return Err("Permit2 payment not yet valid (witness.valid_after)".into());
    }

    // Amount / recipient checks
    let expected_amount_str = request
        .get("amount")
        .and_then(|v| v.as_str())
        .unwrap_or("0");
    let required: U256 = expected_amount_str
        .parse()
        .map_err(|_| format!("Invalid required amount: {}", expected_amount_str))?;
    if amount < required {
        return Err(format!("Insufficient amount: {} < {}", amount, required));
    }

    let expected_to_str = request
        .get("recipient")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let expected_to: Address = expected_to_str
        .parse()
        .map_err(|_| "Invalid expected recipient")?;
    if witness_to != expected_to {
        return Err(format!("Permit2 recipient mismatch: {} != {}", witness_to, expected_to));
    }

    // Chain ID
    let network = request
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let chain_id: u64 = network
        .strip_prefix("eip155:")
        .ok_or_else(|| format!("Invalid network for Permit2: {}", network))?
        .parse()
        .map_err(|e| format!("Invalid chain_id: {}", e))?;

    // Permit2 canonical contract (same on all EVM chains)
    let permit2_addr: Address = "0x000000000022D473030F116dDEE9F6B43aC78BA3"
        .parse()
        .unwrap();

    // EIP-712 domain (Permit2 — no version field)
    let domain = eip712_domain! {
        name: "Permit2",
        chain_id: chain_id,
        verifying_contract: permit2_addr,
    };

    // PermitWitnessTransferFrom EIP-712 type hashes
    let token_permissions_typehash = keccak256(b"TokenPermissions(address token,uint256 amount)");

    let witness_typehash = keccak256(b"x402Witness(address to,uint256 validAfter,string extra)");

    let main_typehash = keccak256(
        b"PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,x402Witness witness)TokenPermissions(address token,uint256 amount)x402Witness(address to,uint256 validAfter,string extra)",
    );

    // TokenPermissions sub-struct hash
    let mut tp_data = Vec::with_capacity(3 * 32);
    tp_data.extend_from_slice(token_permissions_typehash.as_slice());
    tp_data.extend_from_slice(&[0u8; 12]);
    tp_data.extend_from_slice(token_addr.as_slice());
    tp_data.extend_from_slice(&amount.to_be_bytes::<32>());
    let tp_hash = keccak256(&tp_data);

    // x402Witness sub-struct hash
    let extra_hash = keccak256(witness_extra.as_bytes());
    let mut w_data = Vec::with_capacity(4 * 32);
    w_data.extend_from_slice(witness_typehash.as_slice());
    w_data.extend_from_slice(&[0u8; 12]);
    w_data.extend_from_slice(witness_to.as_slice());
    w_data.extend_from_slice(&witness_valid_after.to_be_bytes::<32>());
    w_data.extend_from_slice(extra_hash.as_slice());
    let w_hash = keccak256(&w_data);

    // Main struct hash
    let mut main_data = Vec::with_capacity(7 * 32);
    main_data.extend_from_slice(main_typehash.as_slice());
    main_data.extend_from_slice(tp_hash.as_slice());
    main_data.extend_from_slice(&[0u8; 12]);
    main_data.extend_from_slice(spender.as_slice());
    main_data.extend_from_slice(&nonce.to_be_bytes::<32>());
    main_data.extend_from_slice(&deadline.to_be_bytes::<32>());
    main_data.extend_from_slice(w_hash.as_slice());
    let struct_hash = keccak256(&main_data);

    let domain_separator = domain.hash_struct();

    let mut message = Vec::with_capacity(2 + 32 + 32);
    message.extend_from_slice(b"\x19\x01");
    message.extend_from_slice(domain_separator.as_slice());
    message.extend_from_slice(struct_hash.as_slice());
    let message_hash = keccak256(&message);

    let recovered = signature
        .recover_address_from_prehash(&message_hash)
        .map_err(|e| format!("Permit2 signature recovery failed: {}", e))?;

    if recovered != from_addr {
        return Err(format!("Permit2 signer mismatch: expected {}, recovered {}", from_addr, recovered));
    }

    info!("[mpp_sig] Permit2 signature verified: from={} to={} amount={}", from_addr, witness_to, amount);

    // Keyed by signer + nonce, not signer alone -- two distinct authorizations
    // from the same wallet must not collide in the single-use replay guard.
    Ok(format!("permit2:{}:{}", from_addr, nonce))
}

// ───────────────────────────────────────────────────────────────────
// Payload types (mirror x402 PaymentPayload's authorization structs)
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize)]
struct Eip3009Authorization {
    from: String,
    to: String,
    value: String,
    #[serde(alias = "validAfter", alias = "valid_after")]
    valid_after: String,
    #[serde(alias = "validBefore", alias = "valid_before")]
    valid_before: String,
    nonce: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Permit2Authorization {
    permitted: Permit2Permitted,
    from: String,
    spender: String,
    nonce: String,
    deadline: String,
    witness: Permit2Witness,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Permit2Permitted {
    token: String,
    amount: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct Permit2Witness {
    to: String,
    #[serde(alias = "validAfter", alias = "valid_after")]
    valid_after: String,
    extra: Option<String>,
}

/// Decode the base64url challenge `request` parameter.
fn decode_challenge_request(request_b64: &str) -> Result<serde_json::Value, String> {
    let bytes = super::challenge::base64url_decode_nopad(request_b64)
        .map_err(|e| format!("Failed to decode challenge request: {}", e))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("Failed to parse challenge request: {}", e))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::mpp::challenge::base64url_encode_nopad;
    use crate::mpp::types::*;

    fn test_config() -> MppConfig {
        MppConfig {
            enabled: true,
            realm: "test.example.com".to_string(),
            secret_key: "dGVzdA==".to_string(),
            stripe_secret_key: None,
            payment_methods: vec![],
            challenge_ttl_seconds: 300,
            mcp_payment_triggers: None,
            a2a_method_filters: None,
            verification_timeout_ms: 10000,
            crypto_verification_mode: MppVerificationMode::Passthrough,
            rpc_endpoints: HashMap::new(),
            min_confirmations: 0,
        }
    }

    fn make_challenge_request(
        amount: &str,
        currency: &str,
        recipient: &str,
        network: &str,
    ) -> String {
        let json = serde_json::json!({
            "amount": amount,
            "currency": currency,
            "recipient": recipient,
            "network": network,
        });
        base64url_encode_nopad(&serde_json::to_vec(&json).unwrap())
    }

    fn make_credential(
        method: &str,
        request_b64: &str,
        payload: serde_json::Value,
    ) -> MppCredential {
        MppCredential {
            challenge: MppChallengeEcho {
                id: "hmac-test".into(),
                realm: "test.example.com".into(),
                method: method.into(),
                intent: "charge".into(),
                request: request_b64.into(),
                expires: None,
                digest: None,
                description: None,
                opaque: None,
            },
            source: None,
            payload,
        }
    }

    #[tokio::test]
    async fn test_passthrough_returns_tx_hash() {
        let config = test_config();
        let req = make_challenge_request("100", "USDC", "0xabc", "eip155:8453");
        let cred = make_credential("tempo", &req, serde_json::json!({"tx_hash": "0xdeadbeef"}));

        let result = verify_crypto_proof(&cred, &config).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "0xdeadbeef");
    }

    #[tokio::test]
    async fn test_passthrough_returns_proof() {
        let config = test_config();
        let req = make_challenge_request("100", "USDC", "0xabc", "eip155:8453");
        let cred = make_credential("evm", &req, serde_json::json!({"proof": "some-proof-data"}));

        let result = verify_crypto_proof(&cred, &config).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "some-proof-data");
    }

    #[tokio::test]
    async fn test_passthrough_default_reference() {
        let config = test_config();
        let req = make_challenge_request("100", "USDC", "0xabc", "eip155:8453");
        let cred = make_credential("crypto", &req, serde_json::json!({}));

        let result = verify_crypto_proof(&cred, &config).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "crypto-verified");
    }

    #[tokio::test]
    async fn test_onchain_missing_tx_hash() {
        let mut config = test_config();
        config.crypto_verification_mode = MppVerificationMode::Onchain;
        config
            .rpc_endpoints
            .insert("eip155:8453".into(), "https://rpc.example.com".into());

        let req = make_challenge_request("100", "USDC", "0xabc", "eip155:8453");
        let cred = make_credential("tempo", &req, serde_json::json!({"proof": "sig"}));

        let result = verify_crypto_proof(&cred, &config).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("tx_hash")
        );
    }

    #[tokio::test]
    async fn test_onchain_missing_rpc_endpoint() {
        let mut config = test_config();
        config.crypto_verification_mode = MppVerificationMode::Onchain;
        // No RPC endpoints configured

        let req = make_challenge_request("100", "USDC", "0xabc", "eip155:8453");
        let cred = make_credential(
            "evm",
            &req,
            serde_json::json!({"tx_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"}),
        );

        let result = verify_crypto_proof(&cred, &config).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("No RPC endpoint")
        );
    }

    #[tokio::test]
    async fn test_signature_no_recognizable_payload() {
        let mut config = test_config();
        config.crypto_verification_mode = MppVerificationMode::Signature;

        let req = make_challenge_request("100", "USDC", "0xabc", "eip155:8453");
        let cred = make_credential("tempo", &req, serde_json::json!({"tx_hash": "0xabc"}));

        let result = verify_crypto_proof(&cred, &config).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("No recognizable signature")
        );
    }

    // `Full` requires *both* an offline signature and an on-chain settlement —
    // neither proof alone may satisfy it (previously an OR/fallback: a
    // signature-only credential passed when `tx_hash` was absent, and an
    // on-chain-only credential passed when the signature failed).

    #[tokio::test]
    async fn test_full_rejects_tx_hash_only_no_signature() {
        let mut config = test_config();
        config.crypto_verification_mode = MppVerificationMode::Full;

        let req = make_challenge_request("100", "USDC", "0xabc", "eip155:8453");
        // Only an on-chain proof is presented — no `authorization`/`signature`
        // or `permit2Authorization`/`signature` fields.
        let cred = make_credential("tempo", &req, serde_json::json!({"tx_hash": "0xdeadbeef"}));

        let result = verify_crypto_proof(&cred, &config).await;
        assert!(result.is_err());
        // Must fail on the missing signature, not silently fall back to an
        // on-chain-only check.
        assert!(
            result
                .unwrap_err()
                .contains("No recognizable signature")
        );
    }

    #[tokio::test]
    async fn test_full_rejects_invalid_signature_even_with_tx_hash() {
        let mut config = test_config();
        config.crypto_verification_mode = MppVerificationMode::Full;

        let req = make_challenge_request("100", "USDC", "0xabc", "eip155:8453");
        // A recognizable-shaped but invalid EIP-3009 signature, plus a
        // present `tx_hash` — the invalid signature must still reject the
        // whole payment rather than falling back to an on-chain-only check.
        let cred = make_credential(
            "evm",
            &req,
            serde_json::json!({
                "authorization": {
                    "from": "0x0000000000000000000000000000000000000001",
                    "to": "0xabc",
                    "value": "100",
                    "validAfter": "0",
                    "validBefore": "9999999999",
                    "nonce": "00",
                },
                "signature": "0xnothex",
                "tx_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            }),
        );

        let result = verify_crypto_proof(&cred, &config).await;
        assert!(result.is_err());
        // Must fail on the invalid signature, not fall back to on-chain-only
        // (which would otherwise have surfaced a different — or no — error).
        let err = result.unwrap_err();
        assert!(!err.contains("No RPC endpoint"), "should not have reached the on-chain fallback: {err}");
    }

    #[test]
    fn test_parse_amount_integer() {
        assert_eq!(parse_amount("1000000").unwrap(), 1000000u128);
    }

    #[test]
    fn test_parse_amount_float_is_rejected() {
        // Amounts must be an exact integer in the currency's smallest unit; a
        // lossy float fallback could silently floor a decimal amount to zero.
        let err = parse_amount("100.0").unwrap_err();
        assert!(err.contains("Invalid amount format"), "unexpected: {err}");
    }

    #[test]
    fn test_verify_amount_overpayment_rejected() {
        // Amounts must match exactly; an over-payment is no longer accepted.
        let result = verify_amount(200, 100, "0x123");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("expected exactly")
        );
    }

    #[test]
    fn test_verify_amount_exact() {
        assert!(verify_amount(100, 100, "0x123").is_ok());
    }

    #[test]
    fn test_verify_amount_too_low() {
        let result = verify_amount(50, 100, "0x123");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("expected exactly")
        );
    }

    fn transfer(
        token: &str,
        recipient: &str,
        amount: u128,
    ) -> DecodedTransfer {
        DecodedTransfer {
            token: token
                .trim_start_matches("0x")
                .to_lowercase(),
            recipient: recipient
                .trim_start_matches("0x")
                .to_lowercase(),
            amount,
        }
    }

    #[test]
    fn test_match_erc20_settlement_exact_ok() {
        let transfers = vec![transfer("0xToKeN", "0xReCiP", 1000)];
        assert!(match_erc20_settlement(&transfers, "0xtoken", "0xrecip", 1000).is_ok());
    }

    #[test]
    fn test_match_erc20_settlement_wrong_asset_rejected() {
        let transfers = vec![transfer("0xOTHER", "0xrecip", 1000)];
        let err = match_erc20_settlement(&transfers, "0xtoken", "0xrecip", 1000).unwrap_err();
        assert!(err.contains("wrong asset"), "unexpected: {err}");
    }

    #[test]
    fn test_match_erc20_settlement_wrong_recipient_rejected() {
        let transfers = vec![transfer("0xtoken", "0xSOMEONEELSE", 1000)];
        let err = match_erc20_settlement(&transfers, "0xtoken", "0xrecip", 1000).unwrap_err();
        assert!(err.contains("not to expected recipient"), "unexpected: {err}");
    }

    #[test]
    fn test_match_erc20_settlement_overpayment_rejected() {
        let transfers = vec![transfer("0xtoken", "0xrecip", 1500)];
        let err = match_erc20_settlement(&transfers, "0xtoken", "0xrecip", 1000).unwrap_err();
        assert!(err.contains("amount mismatch"), "unexpected: {err}");
    }

    #[test]
    fn test_match_erc20_settlement_underpayment_rejected() {
        let transfers = vec![transfer("0xtoken", "0xrecip", 900)];
        let err = match_erc20_settlement(&transfers, "0xtoken", "0xrecip", 1000).unwrap_err();
        assert!(err.contains("amount mismatch"), "unexpected: {err}");
    }

    #[test]
    fn test_match_erc20_settlement_picks_matching_among_many() {
        // A swap emits several Transfers; only the one of the right token, to the
        // right recipient, for the exact amount settles the payment.
        let transfers = vec![
            transfer("0xOTHER", "0xrecip", 1000),
            transfer("0xtoken", "0xrecip", 999),
            transfer("0xtoken", "0xrecip", 1000),
        ];
        assert!(match_erc20_settlement(&transfers, "0xtoken", "0xrecip", 1000).is_ok());
    }

    #[test]
    fn test_to_u128_from_be_bytes_32() {
        let mut bytes = vec![0u8; 32];
        bytes[31] = 42;
        assert_eq!(to_u128_from_be_bytes(&bytes), Ok(42));
    }

    #[test]
    fn test_to_u128_from_be_bytes_short() {
        let bytes = vec![1u8];
        assert_eq!(to_u128_from_be_bytes(&bytes), Ok(1));
    }

    #[test]
    fn test_to_u128_from_be_bytes_rejects_nonzero_high_bytes() {
        // A uint256 amount of 2^128 + 42 must not silently truncate to 42.
        let mut bytes = vec![0u8; 32];
        bytes[15] = 1; // sets bit 2^128
        bytes[31] = 42;
        let err = to_u128_from_be_bytes(&bytes).unwrap_err();
        assert!(err.contains("exceeds u128 range"), "unexpected: {err}");
    }

    #[test]
    fn test_to_u128_from_be_bytes_32_zero_high_bytes_ok() {
        // Exactly 32 bytes but the high 16 are all zero -- a legitimate small
        // uint256 value must still parse.
        let mut bytes = vec![0u8; 32];
        bytes[30] = 1;
        assert_eq!(to_u128_from_be_bytes(&bytes), Ok(256));
    }
}
