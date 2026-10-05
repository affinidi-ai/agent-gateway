#!/bin/bash

# Trust Self-Signed Certificate (macOS)
# This script adds the self-signed certificate to the system keychain

set -e

CERT_PATH="${1:-config/certs/cert.pem}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== Trust Self-Signed Certificate ===${NC}\n"

# Check if certificate exists
if [ ! -f "$CERT_PATH" ]; then
    echo -e "${RED}Error: Certificate not found at $CERT_PATH${NC}"
    echo "Please generate the certificate first:"
    echo "  ./scripts/generate-cert.sh"
    exit 1
fi

# Detect OS
OS="$(uname)"

if [ "$OS" = "Darwin" ]; then
    echo -e "${YELLOW}Adding certificate to macOS keychain...${NC}"
    echo "You may be prompted for your password."
    
    sudo security add-trusted-cert -d -r trustRoot \
        -k /Library/Keychains/System.keychain "$CERT_PATH"
    
    echo -e "\n${GREEN}✓ Certificate added to system keychain${NC}"
    echo "You may need to restart your browser for changes to take effect."
    
elif [ "$OS" = "Linux" ]; then
    echo -e "${YELLOW}Adding certificate to Linux trust store...${NC}"
    
    if command -v update-ca-certificates &> /dev/null; then
        # Debian/Ubuntu
        sudo cp "$CERT_PATH" /usr/local/share/ca-certificates/
        sudo update-ca-certificates
        echo -e "\n${GREEN}✓ Certificate added to trust store${NC}"
    elif command -v update-ca-trust &> /dev/null; then
        # RedHat/CentOS/Fedora
        sudo cp "$CERT_PATH" /etc/pki/ca-trust/source/anchors/
        sudo update-ca-trust
        echo -e "\n${GREEN}✓ Certificate added to trust store${NC}"
    else
        echo -e "${RED}Error: Could not find update-ca-certificates or update-ca-trust${NC}"
        exit 1
    fi
    
else
    echo -e "${RED}Unsupported operating system: $OS${NC}"
    echo "Please manually add the certificate to your system's trust store."
    exit 1
fi

echo ""
echo -e "${YELLOW}Note:${NC} You may still see warnings in some browsers."
echo "For Chrome: Go to chrome://flags and enable 'Allow invalid certificates for localhost'"
