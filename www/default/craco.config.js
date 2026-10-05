// CRACO configuration for optimized code splitting
// This creates separate chunks for vendors, common code, and routes
const webpack = require('webpack');

module.exports = {
  // https://craco.js.org/docs/configuration/eslint/
  // disable eslint to avoid issues in CI
  eslint: {
    enable: false,
  },
  webpack: {
    configure: (config, { env }) => {
      // Suppress mini-css-extract-plugin conflicting order warnings
      // These are false positives from lazy-loaded CSS chunks
      const MiniCssExtractPlugin = require('mini-css-extract-plugin');
      config.plugins = (config.plugins || []).map((plugin) => {
        if (plugin instanceof MiniCssExtractPlugin) {
          return new MiniCssExtractPlugin({
            ...plugin.options,
            ignoreOrder: true,
          });
        }
        return plugin;
      });

      // Polyfills needed by @solana/web3.js in browser
      config.resolve = {
        ...config.resolve,
        fallback: {
          ...(config.resolve?.fallback || {}),
          buffer: require.resolve('buffer/'),
          crypto: false,
          stream: false,
          http: false,
          https: false,
          zlib: false,
          url: false,
        },
      };
      config.plugins = [
        ...(config.plugins || []),
        new webpack.ProvidePlugin({
          Buffer: ['buffer', 'Buffer'],
        }),
      ];
      // Only apply optimizations in production build
      if (env === "production") {
        // Optimize chunk splitting for better caching and parallel loading
        config.optimization = {
          ...config.optimization,
          splitChunks: {
            chunks: "all",
            maxInitialRequests: 25,
            maxAsyncRequests: 25,
            minSize: 20000,
            cacheGroups: {
              // Large vendor libraries in separate chunks
              reactVendor: {
                test: /[\\/]node_modules[\\/](react|react-dom|react-router|react-router-dom)[\\/]/,
                name: "vendor-react",
                priority: 40,
                enforce: true,
              },
              chartVendor: {
                test: /[\\/]node_modules[\\/](chart\.js|react-chartjs-2|recharts|d3)[\\/]/,
                name: "vendor-charts",
                priority: 35,
                enforce: true,
              },
              bootstrapVendor: {
                test: /[\\/]node_modules[\\/](bootstrap|react-bootstrap)[\\/]/,
                name: "vendor-bootstrap",
                priority: 30,
                enforce: true,
              },
              // All other vendor code
              defaultVendors: {
                test: /[\\/]node_modules[\\/]/,
                name: "vendors",
                priority: 20,
              },
              // Common code shared across multiple routes
              common: {
                minChunks: 2,
                priority: 10,
                reuseExistingChunk: true,
                name: "common",
              },
            },
          },
          // Better runtime chunk for improved caching
          runtimeChunk: {
            name: "runtime",
          },
          // Module IDs optimization for better long-term caching
          moduleIds: "deterministic",
        };

        // Additional performance optimizations
        config.performance = {
          ...config.performance,
          maxEntrypointSize: 1024000, // 1MB
          maxAssetSize: 1024000, // 1MB
          hints: "warning",
        };
      }

      // Development optimizations for faster rebuilds
      if (env === "development") {
        config.optimization = {
          ...config.optimization,
          removeAvailableModules: false,
          removeEmptyChunks: false,
          splitChunks: false,
        };
      }

      return config;
    },
  },
};
