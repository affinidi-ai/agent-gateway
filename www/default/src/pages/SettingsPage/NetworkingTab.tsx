import React, { useEffect, useState } from 'react';
import { apiClient } from '../../api';
import FieldHelp from '../../components/shared/FieldHelp';

type DirectMode = 'disabled' | 'optional' | 'required';
type ForwardedFormat = 'envoy_xfcc' | 'url_encoded_pem';

interface ForwardedHeaderConfig {
  header_name: string;
  format: ForwardedFormat;
}

interface ClientAuthConfig {
  direct: DirectMode;
  trusted_proxies?: string[];
  forwarded_header?: ForwardedHeaderConfig;
}

interface NetworkingConfigResponse {
  client_auth: ClientAuthConfig;
}

const DIRECT_LABEL: Record<DirectMode, string> = {
  disabled: 'Disabled',
  optional: 'Optional (request, don’t require)',
  required: 'Required (handshake fails without cert)',
};

const FORMAT_LABEL: Record<ForwardedFormat, string> = {
  envoy_xfcc: 'Envoy XFCC (x-forwarded-client-cert)',
  url_encoded_pem: 'URL-encoded PEM (nginx ssl_client_escaped_cert)',
};

const NetworkingTab: React.FC = () => {
  const [data, setData] = useState<NetworkingConfigResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    apiClient
      .fetch('/api/v1/config/networking')
      .then(async r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return (await r.json()) as NetworkingConfigResponse;
      })
      .then(d => {
        if (!cancelled) {
          setData(d);
          setError(null);
        }
      })
      .catch(e => {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return (
      <div className="text-center py-5">
        <div className="spinner-border text-primary" role="status" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="alert alert-danger" role="alert">
        Failed to load networking configuration: {error}
      </div>
    );
  }

  if (!data) return null;

  const { client_auth } = data;
  const trustedProxies = client_auth.trusted_proxies ?? [];
  const forwardedHeader: ForwardedHeaderConfig = client_auth.forwarded_header ?? {
    header_name: 'x-forwarded-client-cert',
    format: 'envoy_xfcc',
  };
  const forwardingEnabled = trustedProxies.length > 0;

  return (
    <div className="card shadow-sm">
      <div className="card-header bg-light">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-network-wired" /> Inbound mTLS / Client Authentication
        </h6>
      </div>
      <div className="card-body">
        <div className="alert alert-info" role="alert">
          <i className="fas fa-info-circle me-2" />
          These settings come from the bootstrap configuration and are{' '}
          <strong>read-only at runtime</strong>. To change them, edit
          <code className="mx-1">tls.client_auth</code> in the gateway bootstrap config and restart
          the process.
        </div>

        {/* Direct TLS mode */}
        <div className="mb-4">
          <h6 className="font-weight-bold mb-2">
            Direct TLS client-cert request{' '}
            <FieldHelp testId="field-help-direct-tls-mode" ariaLabel="About Direct TLS mode">
              Disabled never asks for a client certificate. Optional asks for one but still accepts
              the connection without it. Required refuses the handshake entirely if no certificate
              is presented.
            </FieldHelp>
          </h6>
          <p className="text-muted small mb-2">
            Controls whether the gateway asks for a client certificate during its own TLS handshake
            (rustls <code>WebPkiClientVerifier</code>).
          </p>
          <span
            className={`badge ${
              client_auth.direct === 'disabled'
                ? 'text-bg-secondary'
                : client_auth.direct === 'optional'
                  ? 'text-bg-info'
                  : 'text-bg-success'
            }`}
          >
            {DIRECT_LABEL[client_auth.direct]}
          </span>
        </div>

        {/* Trusted proxies */}
        <div className="mb-4">
          <h6 className="font-weight-bold mb-2">
            Trusted proxy CIDRs{' '}
            <FieldHelp testId="field-help-trusted-proxy-cidrs" ariaLabel="About CIDR notation">
              A CIDR (e.g. 10.0.0.0/8) describes a range of IP addresses in one entry instead of
              listing every address individually.
            </FieldHelp>
          </h6>
          <p className="text-muted small mb-2">
            Peer IPs allowed to present a forwarded client certificate header. Empty means the
            forwarded-cert path is disabled.
          </p>
          {trustedProxies.length === 0 ? (
            <span className="text-muted">None configured</span>
          ) : (
            <div className="d-flex flex-wrap gap-2">
              {trustedProxies.map(cidr => (
                <span key={cidr} className="badge text-bg-secondary">
                  {cidr}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* Forwarded header */}
        <div className="mb-2">
          <h6 className="font-weight-bold mb-2">
            Forwarded client-cert header{' '}
            <FieldHelp testId="field-help-forwarded-header-format" ariaLabel="About header formats">
              XFCC (x-forwarded-client-cert) is the header format Envoy uses. URL-encoded PEM is the
              format nginx uses (ssl_client_escaped_cert). Match whichever proxy sits in front of
              this gateway.
            </FieldHelp>
          </h6>
          <p className="text-muted small mb-2">
            Name and wire format of the header read when the peer matches a trusted proxy CIDR.
          </p>
          {forwardingEnabled ? (
            <div className="row">
              <div className="col-md-6">
                <small className="text-muted d-block">Header name</small>
                <code>{forwardedHeader.header_name}</code>
              </div>
              <div className="col-md-6">
                <small className="text-muted d-block">Format</small>
                <span>{FORMAT_LABEL[forwardedHeader.format]}</span>
              </div>
            </div>
          ) : (
            <span className="text-muted">
              Forwarded-cert header path is disabled because no trusted proxies are configured.
              Direct TLS client-cert handling (above) is unaffected.
            </span>
          )}
        </div>
      </div>
    </div>
  );
};

export default NetworkingTab;
