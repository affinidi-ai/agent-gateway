# X402 Payment Verification Configuration

This directory contains configuration and utilities for X402 payment verification using the embedded facilitator.

## Overview

The agent-gateway embeds the x402 facilitator functionality directly, eliminating the need for a separate Docker service. The facilitator handles:

- **Verification**: Validates EIP-3009 and Permit2 payment signatures on-chain
- **Settlement**: Executes payment settlements to the treasury address

## Configuration Files

### x402.json Structure

Each local environment has its own `x402.json` at `envs/<environment>/config/x402.json`, for
example `envs/local/config/x402.json`. `scripts/_prepare.sh` copies it from
[`config/examples/x402.example.json`](../../config/examples/x402.example.json) the first time
the environment is prepared. It contains:

```json
{
  "networks": [...],
  "rpc_endpoints": {
    "eip155:84532": "https://sepolia.base.org",
    "eip155:8453": "https://mainnet.base.org",
    ...
  },
  "facilitator_private_keys": {
    "eip155:84532": {
      "private_key": "0xYOUR_PRIVATE_KEY_OR_$ENV_VAR",
      "address": "0xC8577be191cfA89Be69D8DD2Df93fa8f51Fc238a"
    },
    "eip155:8453": {
      "private_key": "$FACILITATOR_KEY_BASE",
      "address": "0x274d02AfD22399016c7e04dE16b3EDaaa9e5E07a"
    },
    ...
  }
}
```

**Required Fields for Embedded Facilitator:**

- `rpc_endpoints` - RPC URLs for each blockchain network (CAIP-2 format)
- `facilitator_private_keys` - Object mapping chain IDs to key configurations
  - `private_key` - Private key (hex string or environment variable reference like `$VAR_NAME`)
  - `address` - Ethereum address derived from the private key (public, doesn't need obfuscation)

**Validation:** The embedded facilitator validates that every chain in `rpc_endpoints` has a corresponding private key before initialization.

## Setup Guide

### 1. Generate Private Keys

```bash
# Generate 10 secure random private keys
for i in {1..10}; do openssl rand -hex 32; done
```

**⚠️ Security:** Generate keys offline, store immediately in a secrets manager, never commit to git.

### 2. Derive Addresses and Update Configuration

Use the included utility script to derive Ethereum addresses from your private keys and automatically update the x402.json file:

```bash
# From agent-gateway directory
./scripts/x402/derive-facilitator-addresses.sh envs/local/config/x402.json --update
./scripts/x402/derive-facilitator-addresses.sh envs/local-<name>/config/x402.json --update
```

Without `--update` flag, the script only displays addresses without modifying the file.

**Prerequisites:**

```bash
brew install jq        # JSON parser
brew install foundry   # Ethereum toolkit (provides 'cast')
```

**Output:**

```
Deriving facilitator addresses from: envs/local/config/x402.json
================================================================

Chain: eip155:84532
  Private Key: 0xbdf42530...f7e3
  Address: 0xC8577be191cfA89Be69D8DD2Df93fa8f51Fc238a

Chain: eip155:8453
  Private Key: 0x9418c435...851e
  Address: 0x274d02AfD22399016c7e04dE16b3EDaaa9e5E07a
...
```

### 3. Fund Facilitator Addresses

Transfer native tokens to each derived address for gas:

| Network                | Recommended Amount |
| ---------------------- | ------------------ |
| Base / Base Sepolia    | 0.1 - 1 ETH        |
| Ethereum Mainnet       | 0.05 - 0.5 ETH     |
| Ethereum Sepolia       | 0.1 - 1 ETH        |
| Optimism / OP Sepolia  | 0.1 - 1 ETH        |
| Arbitrum / Arb Sepolia | 0.1 - 1 ETH        |
| Polygon                | 100 - 1000 MATIC   |
| Polygon Amoy           | 100 - 1000 MATIC   |

### 4. Configure x402.json

**Development (embedded keys - NOT FOR PRODUCTION):**

```json
"facilitator_private_keys": {
  "eip155:84532": {
    "private_key": "0x<YOUR_BASE_SEPOLIA_PRIVATE_KEY>",
    "address": "0xC8577be191cfA89Be69D8DD2Df93fa8f51Fc238a"
  },
  "eip155:8453": {
    "private_key": "0x<YOUR_BASE_PRIVATE_KEY>",
    "address": "0x274d02AfD22399016c7e04dE16b3EDaaa9e5E07a"
  }
}
```

**Production (environment variables - RECOMMENDED):**

```json
"facilitator_private_keys": {
  "eip155:84532": {
    "private_key": "$FACILITATOR_KEY_BASE_SEPOLIA",
    "address": "0xC8577be191cfA89Be69D8DD2Df93fa8f51Fc238a"
  },
  "eip155:8453": {
    "private_key": "$FACILITATOR_KEY_BASE",
    "address": "0x274d02AfD22399016c7e04dE16b3EDaaa9e5E07a"
  },
  "eip155:1": {
    "private_key": "$FACILITATOR_KEY_ETHEREUM",
    "address": "0xbF76939D3bd12Bb6c089bc68c84D38a87A7936d8"
  },
  "eip155:11155111": {
    "private_key": "$FACILITATOR_KEY_ETH_SEPOLIA",
    "address": "0x0a9F159E981D04605D55eF7Ee24b9DF4A421Fed4"
  },
  "eip155:10": {
    "private_key": "$FACILITATOR_KEY_OPTIMISM",
    "address": "0x6d4ce2D4569762aeFf940F442f8C8f1d4d671067"
  },
  "eip155:11155420": {
    "private_key": "$FACILITATOR_KEY_OP_SEPOLIA",
    "address": "0x05733D9E8083aEC7f0DEA58691B7e2fB26DdE097"
  },
  "eip155:42161": {
    "private_key": "$FACILITATOR_KEY_ARBITRUM",
    "address": "0x8F9d5cd8e8Cddc0A595C0b88397DF6C51Ec7E927"
  },
  "eip155:421614": {
    "private_key": "$FACILITATOR_KEY_ARB_SEPOLIA",
    "address": "0x84f4DE66444Cc23Ec3938358df2a5195da23B14b"
  },
  "eip155:137": {
    "private_key": "$FACILITATOR_KEY_POLYGON",
    "address": "0x829932fd62cBa287b1C11026232424fe8f5d2a64"
  },
  "eip155:80002": {
    "private_key": "$FACILITATOR_KEY_POLYGON_AMOY",
    "address": "0x69a482d49864F14BAf8BBC260c51588446FbA811"
  }
}
```

**Note:** Addresses are public information and don't need to be obfuscated. Only private keys should be stored as environment variables in production.

## Production Deployment

### Environment Variables

Set the environment variables before starting the gateway:

**Local Development (.env file - DO NOT COMMIT):**

```bash
export FACILITATOR_KEY_BASE_SEPOLIA="0x<YOUR_BASE_SEPOLIA_PRIVATE_KEY>"
export FACILITATOR_KEY_BASE="0x<YOUR_BASE_PRIVATE_KEY>"
# ... etc
```

**Docker:**

```yaml
# docker-compose.yml
services:
  agent-gateway:
    environment:
      - FACILITATOR_KEY_BASE_SEPOLIA=${FACILITATOR_KEY_BASE_SEPOLIA}
      - FACILITATOR_KEY_BASE=${FACILITATOR_KEY_BASE}
```

**Kubernetes:**

```yaml
# Use Secrets
apiVersion: v1
kind: Secret
metadata:
  name: facilitator-keys
type: Opaque
data:
  FACILITATOR_KEY_BASE: <base64-encoded-key>
```

**AWS / Cloud:**

- AWS Secrets Manager with IAM roles
- GCP Secret Manager
- Azure Key Vault

### Security Best Practices

✅ **DO:**

- Use environment variables in production
- Store keys in secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)
- Generate keys offline with secure random source
- Fund addresses with minimal gas amounts
- Rotate keys periodically
- Enable audit logging for settlement operations
- Keep development keys in files under `envs/`, which the repository `.gitignore` already excludes

❌ **DON'T:**

- Commit private keys to git
- Use the same key across multiple chains
- Embed keys in production config files
- Share keys between environments (dev/staging/prod)
- Fund addresses with more than needed

### .gitignore Configuration

The repository `.gitignore` already excludes `/envs/` and any file named `x402.json`, so a
generated configuration with embedded keys is not committed. Keep it that way in a fork.

**Template Approach:**

1. Create `x402.json.template` with `$VAR_NAME` placeholders
2. Commit the template to git
3. Generate actual `x402.json` from template + secrets on deployment
4. Keep actual `x402.json` gitignored

## Architecture

### Embedded Facilitator

Located at `src/x402/embedded_facilitator.rs`, the embedded facilitator:

- Uses `x402-facilitator-local` crate (same implementation as standalone service)
- Initializes lazily on first payment verification
- Detects configuration changes via hash validation and auto-reinitializes
- Supports both verification and settlement operations
- Single implementation serves both local verification and fabric facilitator modes

### Integration Points

**Local Verification (`verification_mode: "local"`):**

1. Payment received with EIP-3009/Permit2 signature
2. `verify_local_payment()` calls embedded facilitator
3. Facilitator verifies signature and on-chain state via RPC
4. Returns success/failure to request handler

**Settlement (when enabled):**

1. Verified payment stored for settlement
2. Facilitator uses private key to execute on-chain settlement
3. Transaction sent via configured RPC endpoint
4. Settlement status tracked and logged

## Troubleshooting

### Configuration Validation Errors

```
Error: No private key configured for chain eip155:8453
```

**Solution:** Ensure `facilitator_private_keys` contains an entry for every chain in `rpc_endpoints`.

### Environment Variable Not Resolved

```
Error: Environment variable FACILITATOR_KEY_BASE not set
```

**Solution:** Set the environment variable before starting the gateway.

### Invalid Private Key

```
Error: Invalid private key format for chain eip155:8453
```

**Solution:** Ensure private keys are 64 hex characters (32 bytes) with optional `0x` prefix.

### Insufficient Gas

Settlement transactions may fail if the facilitator address runs out of gas.

**Solution:** Monitor balances and fund addresses as needed.

## Monitoring

Key metrics to monitor:

- **Facilitator Address Balances** - Alert when gas falls below threshold
- **Settlement Success Rate** - Track failed vs successful settlements
- **RPC Endpoint Health** - Monitor RPC availability and latency
- **Configuration Changes** - Log when facilitator reinitializes due to config change

## Utilities

### derive-facilitator-addresses.sh

**Purpose:** Derive Ethereum addresses from private keys and update x402.json with the new structure

**Usage:**

```bash
./derive-facilitator-addresses.sh <path-to-x402.json> [--update]
```

**Options:**

- `--update` - Automatically update the x402.json file with derived addresses in the new object format

**Features:**

- Reads `facilitator_private_keys` from configuration (supports both old and new formats)
- Derives Ethereum addresses using `cast wallet address`
- Supports both embedded keys and environment variable references
- Shows truncated keys for security
- Displays funding recommendations
- **With `--update`**: Converts configuration to new object format `{"private_key": "...", "address": "..."}`

**Examples:**

```bash
# View addresses only (no file modification)
./scripts/x402/derive-facilitator-addresses.sh envs/local/config/x402.json

# Derive and update the file with addresses
./scripts/x402/derive-facilitator-addresses.sh envs/local/config/x402.json --update
```

**New Configuration Format:**
The script updates `facilitator_private_keys` from the old format:

```json
"eip155:8453": "0x9418c435..."
```

To the new object format:

```json
"eip155:8453": {
  "private_key": "0x9418c435...",
  "address": "0x274d02AfD22399016c7e04dE16b3EDaaa9e5E07a"
}
```

## References

- [X402 Protocol Documentation](https://x402.org)
- [EIP-3009: Transfer With Authorization](https://eips.ethereum.org/EIPS/eip-3009)
- [EIP-2612: Permit Extension for ERC-20](https://eips.ethereum.org/EIPS/eip-2612)
- [Permit2 Documentation](https://github.com/Uniswap/permit2)
- [CAIP-2: Blockchain ID Specification](https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md)

## Support

For issues or questions:

1. Check this README
2. Check embedded facilitator implementation in `src/x402/embedded_facilitator.rs`
3. Contact the development team
