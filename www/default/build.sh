#!/bin/bash

# Build and deploy the React management dashboard to be served by the Rust proxy

set -e

echo "🚀 Building React Management Dashboard..."

# Navigate to the management directory
cd "$(dirname "$0")"

# Clean stale build artifacts to avoid ENOENT conflicts
rm -rf build

# Install dependencies
echo "📦 Installing React application dependencies..."
npm install
echo "✅ Dependencies installed successfully!"
echo ""

# Build the React application
# GENERATE_SOURCEMAP=false suppresses warnings from third-party packages
# (@solana/buffer-layout, superstruct) that reference missing .ts source files.
echo "📦 Building React application..."
GENERATE_SOURCEMAP=false npm run build

echo "✅ React build completed successfully!"
echo ""
echo "📋 Integration Notes:"
echo "   • Built files are in: ./build/"
echo "   • Configure Rust proxy to serve ./build/ at /management/*"
echo "   • The app expects to be hosted at /management/ path"
echo "   • API calls will be proxied to the main server"
echo ""
echo "🌐 Next Steps:"
echo "   1. Update your Rust proxy to serve the built React app"
echo "   2. Ensure /api/v1/* channels are available for the dashboard"
echo "   3. Set up WebSocket endpoint at /ws/dashboard for real-time updates"
echo "   4. Test the dashboard at https://localhost:8443/management/"
echo ""
echo "🎉 React Management Dashboard is ready for deployment!"
