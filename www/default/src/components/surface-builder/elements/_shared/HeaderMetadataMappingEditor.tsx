import React from 'react';
import { Form } from 'react-bootstrap';
import {
  COPILOT_HEADER_METADATA_PRESET,
  HEADER_METADATA_EXTENSION_URI,
  type HeaderMetadataMappingConfig,
  validateHeaderMetadataMapping,
} from './headerMetadataMapping';
import InfoBanner from '../../../shared/InfoBanner';
import FieldHelp from '../../../shared/FieldHelp';

interface HeaderMetadataMappingEditorProps {
  idPrefix: string;
  testIdPrefix: string;
  mapping: HeaderMetadataMappingConfig | undefined;
  helpText: string;
  onChange: (mapping: HeaderMetadataMappingConfig | undefined) => void;
  hasAttemptedSave?: boolean;
}

const defaultMapping: HeaderMetadataMappingConfig = {
  extension_uri: HEADER_METADATA_EXTENSION_URI,
  strip_mapped_headers: true,
  headers: [],
};

const HeaderMetadataMappingEditor: React.FC<HeaderMetadataMappingEditorProps> = ({
  idPrefix,
  testIdPrefix,
  mapping,
  helpText,
  onChange,
  hasAttemptedSave,
}) => {
  const effectiveMapping = mapping ?? defaultMapping;
  const errors = validateHeaderMetadataMapping(mapping);
  const errorFor = (field: string) => errors.find(error => error.field === field)?.message;

  const updateMapping = (patch: Partial<HeaderMetadataMappingConfig>) => {
    onChange({
      ...defaultMapping,
      ...(mapping || {}),
      ...patch,
    });
  };

  const updateRow = (index: number, patch: Partial<{ header: string; field: string }>) => {
    const rows = [...(mapping?.headers || [])];
    rows[index] = { header: '', field: '', ...(rows[index] || {}), ...patch };
    updateMapping({ headers: rows });
  };

  return (
    <div className="config-section" data-testid={`${testIdPrefix}-section`}>
      <label>Header Metadata Mapping</label>
      <InfoBanner
        className="mb-2"
        title="What is header metadata mapping?"
        summary={
          <>
            Some callers (like Microsoft Copilot Studio) identify themselves with custom HTTP
            headers instead of the protocol's standard fields. This maps those headers into fields
            the gateway and downstream policies can actually read and act on: for example, turning
            an <code>x-ms-entra-agent-id</code> header into an <code>entra_agent_id</code> metadata
            field.
          </>
        }
      />
      <Form.Text className="text-muted d-block mb-2" style={{ fontSize: '10px' }}>
        {helpText}
      </Form.Text>

      <Form.Group className="mb-2">
        <div className="d-flex align-items-center gap-1 mb-1">
          <Form.Label className="small text-muted mb-0">Namespace URI</Form.Label>
          <FieldHelp
            testId="field-help-header-metadata-mapping-editor-namespace-uri"
            ariaLabel="About Namespace URI"
          >
            Protocol metadata namespace where mapped headers are written: a web address you control.
            It doesn't need to be a real, working link, it just needs to be consistent everywhere
            this metadata is read. Use any absolute http(s) URI you own. If another node, such as
            Identity, reads this mapped metadata, configure it with the same URI. Existing metadata
            under this namespace is merged, and mapped fields overwrite fields with the same name.
          </FieldHelp>
        </div>
        <Form.Control
          size="sm"
          type="text"
          data-testid={`${testIdPrefix}-extension-uri`}
          value={effectiveMapping.extension_uri ?? HEADER_METADATA_EXTENSION_URI}
          onChange={e => updateMapping({ extension_uri: e.target.value })}
          isInvalid={!!hasAttemptedSave && !!errorFor('header_metadata_mapping.extension_uri')}
        />
        <Form.Control.Feedback type="invalid" style={{ fontSize: '10px' }}>
          {errorFor('header_metadata_mapping.extension_uri')}
        </Form.Control.Feedback>
      </Form.Group>

      <Form.Check
        type="checkbox"
        id={`${idPrefix}-header-metadata-strip`}
        data-testid={`${testIdPrefix}-strip`}
        label="Strip mapped headers before forwarding"
        checked={effectiveMapping.strip_mapped_headers !== false}
        onChange={e => updateMapping({ strip_mapped_headers: e.target.checked })}
      />
      <Form.Text className="text-muted d-block mb-2" style={{ fontSize: '10px' }}>
        Enabled by default so transport-only identifiers are normalized into protocol metadata
        without leaking to the target as raw headers.
      </Form.Text>

      <div className="d-flex justify-content-between align-items-center mb-1">
        <Form.Label className="small text-muted mb-0">Header to metadata fields</Form.Label>
        <button
          type="button"
          className="btn btn-link btn-sm p-0"
          data-testid={`${testIdPrefix}-copilot-preset`}
          style={{ fontSize: '10px' }}
          onClick={() =>
            updateMapping({
              extension_uri: HEADER_METADATA_EXTENSION_URI,
              headers: COPILOT_HEADER_METADATA_PRESET.map(row => ({ ...row })),
              strip_mapped_headers: true,
            })
          }
        >
          Use Copilot Studio preset
        </button>
      </div>

      {(effectiveMapping.headers || []).map((row, index) => (
        <div key={`header-metadata-row-${index}`} className="row g-2 mb-2">
          <div className="col-5">
            <Form.Control
              size="sm"
              type="text"
              data-testid={`${testIdPrefix}-row-${index}-header`}
              placeholder="x-ms-entra-agent-id"
              value={row.header || ''}
              onChange={e => updateRow(index, { header: e.target.value })}
              isInvalid={
                !!hasAttemptedSave && !!errorFor(`header_metadata_mapping.headers.${index}.header`)
              }
            />
            <Form.Control.Feedback type="invalid" style={{ fontSize: '10px' }}>
              {errorFor(`header_metadata_mapping.headers.${index}.header`)}
            </Form.Control.Feedback>
          </div>
          <div className="col-5">
            <Form.Control
              size="sm"
              type="text"
              data-testid={`${testIdPrefix}-row-${index}-field`}
              placeholder="entra_agent_id"
              value={row.field || ''}
              onChange={e => updateRow(index, { field: e.target.value })}
              isInvalid={
                !!hasAttemptedSave && !!errorFor(`header_metadata_mapping.headers.${index}.field`)
              }
            />
            <Form.Control.Feedback type="invalid" style={{ fontSize: '10px' }}>
              {errorFor(`header_metadata_mapping.headers.${index}.field`)}
            </Form.Control.Feedback>
          </div>
          <div className="col-2 d-grid">
            <button
              type="button"
              className="btn btn-outline-danger btn-sm"
              data-testid={`${testIdPrefix}-row-${index}-remove`}
              aria-label="Remove header metadata mapping"
              onClick={() =>
                updateMapping({
                  headers: (effectiveMapping.headers || []).filter((_, i) => i !== index),
                })
              }
            >
              <i className="fas fa-trash" />
            </button>
          </div>
        </div>
      ))}

      <button
        type="button"
        className="btn btn-outline-primary btn-sm w-100"
        data-testid={`${testIdPrefix}-add-row`}
        onClick={() =>
          updateMapping({
            headers: [...(effectiveMapping.headers || []), { header: '', field: '' }],
          })
        }
      >
        <i className="fas fa-plus me-1" /> Add header mapping
      </button>
    </div>
  );
};

export default HeaderMetadataMappingEditor;
