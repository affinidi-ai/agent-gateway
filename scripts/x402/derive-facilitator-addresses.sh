#!/bin/bash
set -euo pipefail

# Script to derive Ethereum addresses from facilitator private keys and update x402.json
# Usage: ./scripts/derive-facilitator-addresses.sh config/GW1/config/x402.json [--update]


show_usage() {
    echo "Usage: $0 <path-to-x402.json> [--update]"
    echo ""
    echo "Derives Ethereum addresses from facilitator private keys in x402.json"
    echo ""
    echo "Options:"
    echo "  --update    Update the x402.json file with derived addresses"
    echo ""
    echo "Examples:"
    echo "  $0 config/GW1/config/x402.json              # Show addresses only"
    echo "  $0 config/GW1/config/x402.json --update     # Update file with addresses"
}

if [ $# -eq 0 ]; then
    show_usage
    exit 1
fi

X402_CONFIG="$1"
UPDATE_MODE=false

if [ $# -ge 2 ] && [ "$2" = "--update" ]; then
    UPDATE_MODE=true
fi

if [ ! -f "$X402_CONFIG" ]; then
    echo "Error: File not found: $X402_CONFIG"
    exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed"
    echo "Install with: brew install jq"
    exit 1
fi

# Check if cast is installed
if ! command -v cast &> /dev/null; then
    echo "Error: cast (foundry) is required but not installed"
    echo "Install with: brew install foundry"
    exit 1
fi

echo "Deriving facilitator addresses from: $X402_CONFIG"
echo "================================================================"
echo ""

# Check if facilitator_private_keys exists
if ! jq -e '.facilitator_private_keys' "$X402_CONFIG" > /dev/null 2>&1; then
    echo "Error: No facilitator_private_keys found in config"
    exit 1
fi

# Create temporary file for updates
TEMP_FILE=$(mktemp)
trap 'rm -f "${TEMP_FILE}"' EXIT

# Copy original file to temp
cp "$X402_CONFIG" "$TEMP_FILE"

# Parse and iterate through facilitator_private_keys
jq -r '.facilitator_private_keys | to_entries[] | "\(.key)|\(.value)"' "$X402_CONFIG" | while IFS='|' read -r chain_id key_data; do
    # Handle both old format (string) and new format (object)
    if echo "$key_data" | jq -e 'type == "object"' > /dev/null 2>&1; then
        # New format: {"private_key": "...", "address": "..."}
        private_key=$(echo "$key_data" | jq -r '.private_key')
        existing_address=$(echo "$key_data" | jq -r '.address // ""')
    else
        # Old format: just the private key string
        private_key="$key_data"
        existing_address=""
    fi
    
    # Skip if it's an environment variable reference
    if [[ "$private_key" == \$* ]]; then
        echo "Chain: $chain_id"
        echo "  Private Key: $private_key (environment variable)"
        
        # Try to resolve the env var
        env_var="${private_key:1}" # Remove the $
        if [ -n "${!env_var:-}" ]; then
            resolved_key="${!env_var}"
            address=$(cast wallet address --private-key "$resolved_key" 2>/dev/null || echo "ERROR: Invalid key")
            echo "  Address: $address"
            
            if [ "$UPDATE_MODE" = true ] && [ "$address" != "ERROR: Invalid key" ]; then
                # Update the JSON with the new structure
                jq --arg chain "$chain_id" --arg pk "$private_key" --arg addr "$address" \
                   '.facilitator_private_keys[$chain] = {"private_key": $pk, "address": $addr}' \
                   "$TEMP_FILE" > "$TEMP_FILE.new" && mv "$TEMP_FILE.new" "$TEMP_FILE"
            fi
        else
            echo "  Address: (environment variable not set)"
            if [ -n "$existing_address" ]; then
                echo "  Existing Address: $existing_address"
            fi
        fi
    else
        # Direct private key
        echo "Chain: $chain_id"
        echo "  Private Key: ${private_key:0:10}...${private_key: -4}"
        
        # Derive address using cast
        address=$(cast wallet address --private-key "$private_key" 2>/dev/null || echo "ERROR: Invalid key")
        echo "  Address: $address"
        
        if [ "$UPDATE_MODE" = true ] && [ "$address" != "ERROR: Invalid key" ]; then
            # Update the JSON with the new structure
            jq --arg chain "$chain_id" --arg pk "$private_key" --arg addr "$address" \
               '.facilitator_private_keys[$chain] = {"private_key": $pk, "address": $addr}' \
               "$TEMP_FILE" > "$TEMP_FILE.new" && mv "$TEMP_FILE.new" "$TEMP_FILE"
        fi
    fi
    echo ""
done

if [ "$UPDATE_MODE" = true ]; then
    # Write the updated file back
    mv "$TEMP_FILE" "$X402_CONFIG"
    echo "================================================================"
    echo "✅ Updated $X402_CONFIG with derived addresses"
    echo ""
fi

echo "================================================================"
echo "Fund these addresses with native tokens for gas:"
echo "  - Base/Sepolia: 0.1-1 ETH"
echo "  - Ethereum: 0.05-0.5 ETH"
echo "  - Optimism/Arbitrum: 0.1-1 ETH"
echo "  - Polygon: 100-1000 MATIC"

