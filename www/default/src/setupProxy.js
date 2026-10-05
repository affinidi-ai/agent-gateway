const { createProxyMiddleware } = require('http-proxy-middleware');

const backendTarget = process.env.REACT_APP_BACKEND_URL || 'https://localhost:8443';

const onError = (err, _req, res) => {
  console.error('[proxy] error:', err.message);
  if (!res.headersSent) {
    res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('Proxy error: ' + err.message);
  }
};

module.exports = function (app) {
  app.use(
    '/api',
    createProxyMiddleware({
      target: backendTarget,
      changeOrigin: true,
      secure: false, // allow self-signed cert
      ws: true,
      on: { error: onError },
    })
  );
  app.use(
    '/ws',
    createProxyMiddleware({
      target: backendTarget,
      changeOrigin: true,
      secure: false,
      ws: true,
      on: { error: onError },
    })
  );
};
