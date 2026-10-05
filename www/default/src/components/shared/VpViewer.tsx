import React from 'react';
import { Modal } from 'react-bootstrap';
import { AppButton } from './AppButton';
import { tokenizeJson } from './jsonHighlight';
import { buildReadableRows, type ReadableRow } from './vpReadable';

export function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  try {
    const parts = jwt.split('.');
    if (parts.length < 2) return null;
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(payload));
  } catch {
    return null;
  }
}

export function looksLikeJwt(value: string): boolean {
  if (typeof value !== 'string') return false;
  const parts = value.split('.');
  return parts.length === 3 && parts.every(p => p.length > 10);
}

export function deepDecodeJwts(obj: unknown, depth = 0): unknown {
  if (depth > 5) return obj;
  if (typeof obj === 'string' && looksLikeJwt(obj)) {
    const decoded = decodeJwtPayload(obj);
    if (decoded) return deepDecodeJwts(decoded, depth + 1);
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(item => deepDecodeJwts(item, depth));
  }
  if (obj !== null && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      result[key] = deepDecodeJwts(value, depth);
    }
    return result;
  }
  return obj;
}

export function parseVp(vpJwt: string): { isJwt: boolean; parsed: unknown | null; raw: string } {
  if (looksLikeJwt(vpJwt)) {
    const payload = decodeJwtPayload(vpJwt);
    return { isJwt: true, parsed: payload ? deepDecodeJwts(payload) : null, raw: vpJwt };
  }
  try {
    const obj = JSON.parse(vpJwt);
    return { isJwt: false, parsed: deepDecodeJwts(obj), raw: vpJwt };
  } catch {
    return { isJwt: false, parsed: null, raw: vpJwt };
  }
}

/** Recursive presentational renderer for the human-friendly VP outline. */
const ReadableRows: React.FC<{ rows: ReadableRow[]; nested?: boolean }> = ({ rows, nested }) => (
  <dl className={`vp-readable${nested ? ' vp-readable--nested' : ''}`}>
    {rows.map((row, i) =>
      row.children ? (
        <div className="vp-readable-group" key={`${row.label}-${i}`}>
          <dt className="vp-readable-grouplabel">{row.label}</dt>
          <dd className="vp-readable-children">
            <ReadableRows rows={row.children} nested />
          </dd>
        </div>
      ) : (
        <div className="vp-readable-row" key={`${row.label}-${i}`}>
          <dt className="vp-readable-label">{row.label}</dt>
          <dd
            className={`vp-readable-value${row.mono ? ' vp-readable-value--mono' : ''}`}
            title={row.fullValue}
          >
            {row.value}
          </dd>
        </div>
      )
    )}
  </dl>
);

export const VpJwtRow: React.FC<{ vpJwt: string }> = ({ vpJwt }) => {
  const [showModal, setShowModal] = React.useState(false);
  const { parsed } = React.useMemo(() => parseVp(vpJwt), [vpJwt]);
  const readableRows = React.useMemo(() => (parsed ? buildReadableRows(parsed) : []), [parsed]);
  const [view, setView] = React.useState<'readable' | 'raw'>('readable');

  const jsonText = React.useMemo(
    () => (parsed ? JSON.stringify(parsed, null, 2) : vpJwt),
    [parsed, vpJwt]
  );
  const jsonTokens = React.useMemo(() => tokenizeJson(jsonText), [jsonText]);
  const [copied, setCopied] = React.useState(false);
  const handleCopy = () => {
    void navigator.clipboard?.writeText(jsonText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const isJson = !looksLikeJwt(vpJwt);
    const blob = new Blob([vpJwt], {
      type: isJson ? 'application/json' : 'application/jwt',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `verifiable-presentation-${Date.now()}.${isJson ? 'json' : 'jwt'}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <tr>
        <td className="text-muted fw-semibold" style={{ width: '140px', whiteSpace: 'nowrap' }}>
          Verifiable Presentation
        </td>
        <td>
          <AppButton
            variant="outline-primary"
            size="sm"
            className="me-2"
            onClick={() => setShowModal(true)}
            disabled={!parsed}
            title={parsed ? 'View decoded VP' : 'VP could not be decoded'}
            iconStart={<i className="fas fa-eye me-1" aria-hidden="true" />}
          >
            View
          </AppButton>
          <AppButton
            variant="outline-secondary"
            size="sm"
            onClick={handleDownload}
            title="Download VP"
            iconStart={<i className="fas fa-download me-1" aria-hidden="true" />}
          >
            Download
          </AppButton>
        </td>
      </tr>
      <Modal show={showModal} onHide={() => setShowModal(false)} size="lg" centered>
        <Modal.Header closeButton>
          <Modal.Title>
            <i className="fas fa-certificate me-2" />
            Verifiable Presentation
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <div
            className="d-flex align-items-center gap-2 mb-3"
            role="group"
            aria-label="VP view mode"
          >
            <AppButton
              variant={view === 'readable' ? 'primary' : 'outline-secondary'}
              size="sm"
              onClick={() => setView('readable')}
              disabled={readableRows.length === 0}
              aria-pressed={view === 'readable'}
              iconStart={<i className="fas fa-list-ul me-1" aria-hidden="true" />}
            >
              Readable
            </AppButton>
            <AppButton
              variant={view === 'raw' ? 'primary' : 'outline-secondary'}
              size="sm"
              onClick={() => setView('raw')}
              aria-pressed={view === 'raw'}
              iconStart={<i className="fas fa-code me-1" aria-hidden="true" />}
            >
              Raw JSON
            </AppButton>
            {view === 'raw' && (
              <AppButton
                variant="outline-secondary"
                size="sm"
                className="ms-auto"
                onClick={handleCopy}
                title="Copy JSON to clipboard"
                iconStart={
                  <i
                    className={`fas ${copied ? 'fa-check text-success' : 'fa-copy'} me-1`}
                    aria-hidden="true"
                  />
                }
              >
                {copied ? 'Copied' : 'Copy'}
              </AppButton>
            )}
          </div>
          {view === 'readable' && readableRows.length > 0 ? (
            <div className="vp-readable-wrap" style={{ maxHeight: '60vh', overflow: 'auto' }}>
              <ReadableRows rows={readableRows} />
            </div>
          ) : (
            <pre className="vp-json-pre mb-0">
              <code>
                {jsonTokens.map((token, i) =>
                  token.type === 'plain' ? (
                    <React.Fragment key={i}>{token.value}</React.Fragment>
                  ) : (
                    <span key={i} className={`json-${token.type}`}>
                      {token.value}
                    </span>
                  )
                )}
              </code>
            </pre>
          )}
        </Modal.Body>
        <Modal.Footer>
          <AppButton variant="outline-secondary" size="sm" onClick={() => setShowModal(false)}>
            Close
          </AppButton>
          <AppButton
            variant="outline-primary"
            size="sm"
            onClick={handleDownload}
            iconStart={<i className="fas fa-download me-1" aria-hidden="true" />}
          >
            Download
          </AppButton>
        </Modal.Footer>
      </Modal>
    </>
  );
};
