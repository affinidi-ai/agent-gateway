import React, { useState } from 'react';
import { Link } from '../../../components/shared/Link';
import { DOCS_URL } from '../../../config/docs';
import { EXPECTED_PACKAGE } from './policyDefaults';
import type { PolicyType } from './types';

const INPUT_FIELDS: [string, string][] = [
  [
    'input.source_auth.method',
    'How the caller authenticated: jwt_bearer, api_key, did_auth, mtls, or failed',
  ],
  ['input.source_auth.subject', 'The JWT subject, for jwt_bearer callers'],
  ['input.source_auth.claims', 'The JWT claims, such as role or iss, for jwt_bearer callers'],
  ['input.http.method', 'HTTP method'],
  [
    'input.http.path',
    "The whole request path, starting with the Access Point route; on a Transit Point, with /outbound<route>/<alias> or the Transit Point's listen_path",
  ],
  ['input.http.headers', 'HTTP headers'],
  ['input.gateway.direction', '"inbound" or "outbound"'],
  ['input.gateway.target_id', 'The target endpoint, on the outbound path'],
  ['input.mcp.method', 'The MCP method, such as tools/call'],
  [
    'input.mcp.tool_name',
    'The MCP tool being called; read it with input.mcp.method == "tools/call"',
  ],
  [
    'input.trust_check_results.target',
    'Trust check results: a list of { id, ok }, with one entry per authority, all with the same id, for a check that queries several',
  ],
  [
    'input.extension_identity.did',
    'The caller DID the gateway resolved; trust it only when input.extension_identity.verified is true',
  ],
  ['input.extension_identity.verified', 'true when the gateway verified the caller DID'],
];

const TOOL_INPUT_FIELDS: [string, string][] = [
  [
    'input.jwt.<claim>',
    "Claims of the bearer token in the request's Authorization header, such as sub or role",
  ],
  ['input.mcp.method', 'Always tools/call'],
  ['input.mcp.params.name', 'The tool being called'],
  ['input.channel.name', 'The surface name'],
  ['input.request.path', 'The request path'],
];

const Example: React.FC<{ icon: string; title: string; code: string }> = ({
  icon,
  title,
  code,
}) => (
  <>
    <h6 className="font-weight-bold mb-2 mt-3">
      <i className={`fas ${icon} me-2`} aria-hidden="true" />
      {title}
    </h6>
    <pre className="policy-preview-block policy-rego-reference-code p-3 rounded mb-2">
      <code>{code}</code>
    </pre>
  </>
);

/** A collapsible reference of the Rego structure, the policy input, and short examples. */
const RegoReference: React.FC<{ policyType: PolicyType }> = ({ policyType }) => {
  const [open, setOpen] = useState(false);
  const pkg = EXPECTED_PACKAGE[policyType];

  return (
    <div className="card shadow-sm mb-3 border-left-primary">
      <div className="card-body py-2">
        <h6 className="mb-0">
          <button
            type="button"
            className="btn btn-link w-100 p-0 border-0 d-flex justify-content-between align-items-center text-decoration-none text-start fw-bold text-primary"
            aria-expanded={open}
            aria-controls="policyDefInstructions"
            data-testid="policy-instructions-toggle"
            onClick={() => setOpen(o => !o)}
          >
            <span data-testid="policy-instructions-title">
              <i className="fas fa-graduation-cap me-2" aria-hidden="true" />
              Rego reference
            </span>
            <span className="btn btn-sm btn-outline-primary" aria-hidden="true">
              <i
                className={`fas fa-chevron-${open ? 'up' : 'down'}`}
                data-testid="policy-instructions-chevron"
              />
            </span>
          </button>
        </h6>

        <div
          className={`collapse${open ? ' show' : ''}`}
          id="policyDefInstructions"
          data-testid="policy-instructions-body"
        >
          <p className="text-gray-800 mb-2 mt-3">
            A policy uses the <code>{pkg}</code> package and defines an <code>allow</code> rule.
            Rules combine with OR: the request is allowed when any <code>allow</code> rule matches,
            otherwise the default decides.
          </p>
          <pre className="policy-preview-block policy-rego-reference-code p-3 rounded mb-3">
            <code>{`package ${pkg}

# Deny unless a rule below allows
default allow := false

allow if {
  # Your conditions here
}`}</code>
          </pre>

          <h6 className="font-weight-bold mb-2">
            <i className="fas fa-database me-2" aria-hidden="true" />
            Policy input
          </h6>
          <p className="small text-gray-800 mb-1">
            Gateway and surface policies read the request&apos;s caller context.{' '}
            <Link
              href={`${DOCS_URL.opaPoliciesReferencePage}#gateway-and-surface-policy-input-policyinput`}
              external
              variant="inline"
              testId="policy-instructions-input-docs-link"
            >
              All fields
            </Link>
          </p>
          <ul className="mb-2 text-gray-800 small" data-testid="policy-instructions-input-fields">
            {INPUT_FIELDS.map(([field, meaning]) => (
              <li key={field}>
                <code>{field}</code> – {meaning}
              </li>
            ))}
          </ul>
          <p className="small text-gray-800 mb-1">
            A policy bound to MCP tools reads the tool call instead, with the claims of the
            request&apos;s bearer token in <code>input.jwt</code> and no{' '}
            <code>input.source_auth</code>.{' '}
            <Link
              href={`${DOCS_URL.opaPoliciesReferencePage}#mcp-tool-policy-input`}
              external
              variant="inline"
              testId="policy-instructions-tool-input-docs-link"
            >
              MCP tool policy input
            </Link>
          </p>
          <ul
            className="mb-2 text-gray-800 small"
            data-testid="policy-instructions-tool-input-fields"
          >
            {TOOL_INPUT_FIELDS.map(([field, meaning]) => (
              <li key={field}>
                <code>{field}</code> – {meaning}
              </li>
            ))}
          </ul>

          <Example
            icon="fa-lock"
            title="Require an authenticated caller"
            code={`package ${pkg}

default allow := false

allow if {
  input.source_auth.method
  input.source_auth.method != "failed"
}`}
          />
          <Example
            icon="fa-user-shield"
            title="Admin role only"
            code={`package ${pkg}

default allow := false

allow if {
  input.source_auth.method == "jwt_bearer"
  input.source_auth.claims.role == "admin"
}`}
          />

          <div className="alert alert-warning mb-0 mt-3">
            <small>
              <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
              <strong>Best practice:</strong> start with <code>default allow := false</code> and
              allow only what you need. Caller identity and trust check results are set on Agent
              Surface policies.
            </small>
          </div>
        </div>
      </div>
    </div>
  );
};

export default RegoReference;
