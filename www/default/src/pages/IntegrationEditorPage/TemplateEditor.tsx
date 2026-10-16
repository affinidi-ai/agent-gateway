import React, { useEffect, useRef, useState } from 'react';
import { CatalogVariable, EndpointType } from '../../integrationsApi';
import { TEMPLATE_FIELDS, TemplateField, unfilledVariables } from './templateModel';

interface TemplateEditorProps {
  type: EndpointType;
  content: Record<string, unknown>;
  onChange: (content: Record<string, unknown>) => void;
  /** The variables the integration's event set fills. */
  variables: CatalogVariable[];
  /** Whether the template can be saved as it stands; false while a payload is not an object. */
  onValidityChange?: (valid: boolean) => void;
}

interface Cursor {
  field: string;
  start: number;
  end: number;
}

type Editable = HTMLInputElement | HTMLTextAreaElement;

const parsePayload = (text: string): Record<string, unknown> | null => {
  if (!text.trim()) return {};
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
};

const payloadText = (content: Record<string, unknown>) =>
  Object.keys(content).length ? JSON.stringify(content, null, 2) : '';

/** Writes an integration's template for its endpoint type, with the event set's variables. */
const TemplateEditor: React.FC<TemplateEditorProps> = ({
  type,
  content,
  onChange,
  variables,
  onValidityChange,
}) => {
  const fields = TEMPLATE_FIELDS[type];
  const [payload, setPayload] = useState(() => payloadText(content));
  const [payloadError, setPayloadError] = useState<string | null>(null);
  const cursor = useRef<Cursor | null>(null);

  useEffect(() => {
    setPayload(payloadText(content));
    setPayloadError(null);
    // Only a new endpoint type starts the payload over; edits keep the text as typed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [type]);

  const textOf = (field: TemplateField) =>
    field.kind === 'json' ? payload : String(content[field.name] ?? '');

  const setText = (field: TemplateField, text: string) => {
    if (field.kind === 'json') {
      setPayload(text);
      const parsed = parsePayload(text);
      setPayloadError(parsed ? null : 'The payload must be a JSON object.');
      onValidityChange?.(parsed !== null);
      if (parsed) onChange(parsed);
      return;
    }
    const next = { ...content };
    if (text) next[field.name] = text;
    else delete next[field.name];
    onChange(next);
  };

  const remember = (field: TemplateField) => (event: React.SyntheticEvent<Editable>) => {
    const element = event.currentTarget;
    cursor.current = {
      field: field.name,
      start: element.selectionStart ?? element.value.length,
      end: element.selectionEnd ?? element.value.length,
    };
  };

  const insert = (name: string) => {
    const editable = fields.filter(field => field.kind !== 'select');
    const field =
      editable.find(candidate => candidate.name === cursor.current?.field) ?? editable[0];
    if (!field) return;
    const text = textOf(field);
    const at = cursor.current?.field === field.name ? cursor.current : null;
    const start = at?.start ?? text.length;
    const end = at?.end ?? text.length;
    const token = `\${${name}}`;
    setText(field, text.slice(0, start) + token + text.slice(end));
    cursor.current = { field: field.name, start: start + token.length, end: start + token.length };
  };

  const unfilled = unfilledVariables(content, variables);

  return (
    <div className="row">
      <div className="col-lg-8">
        {fields.map(field => {
          const id = `template-${field.name}`;
          const tracking = {
            onFocus: remember(field),
            onSelect: remember(field),
            onKeyUp: remember(field),
            onClick: remember(field),
          };
          return (
            <div className="mb-3" key={field.name}>
              <label htmlFor={id} className="form-label">
                {field.label}
              </label>
              {field.kind === 'select' ? (
                <select
                  id={id}
                  data-testid={`${id}-input`}
                  className="form-select"
                  value={String(content[field.name] ?? '')}
                  onChange={event => setText(field, event.target.value)}
                >
                  {field.options?.map(option => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              ) : field.kind === 'text' ? (
                <input
                  id={id}
                  data-testid={`${id}-input`}
                  className="form-control"
                  value={textOf(field)}
                  placeholder={field.defaultText}
                  onChange={event => setText(field, event.target.value)}
                  {...tracking}
                />
              ) : (
                <textarea
                  id={id}
                  data-testid={`${id}-input`}
                  className={`form-control ${field.kind === 'json' ? 'font-monospace' : ''}`}
                  rows={field.kind === 'json' ? 10 : 5}
                  spellCheck={field.kind !== 'json'}
                  value={textOf(field)}
                  placeholder={field.defaultText}
                  onChange={event => setText(field, event.target.value)}
                  {...tracking}
                />
              )}
              {field.kind === 'json' && payloadError && (
                <div className="text-danger small">{payloadError}</div>
              )}
              {field.help && <div className="form-text">{field.help}</div>}
            </div>
          );
        })}
        <p className="text-muted small">
          Left empty, a field sends the default shown. A variable without a value for the event is
          sent empty.
        </p>
        {unfilled.length > 0 && (
          <div className="alert alert-warning small" role="alert">
            No event of the event set fills {unfilled.join(', ')}, so the integration cannot be
            saved with {unfilled.length === 1 ? 'it' : 'them'}.
          </div>
        )}
      </div>
      <div className="col-lg-4">
        <h6 className="font-weight-bold">Variables</h6>
        {variables.length === 0 ? (
          <p className="text-muted small">Pick an event set to see its variables.</p>
        ) : (
          <ul className="list-unstyled small">
            {variables.map(variable => (
              <li key={variable.name} className="mb-2">
                <button
                  type="button"
                  className="btn btn-link btn-sm p-0 font-monospace"
                  onMouseDown={event => event.preventDefault()}
                  onClick={() => insert(variable.name)}
                  aria-label={`Insert ${variable.name}`}
                  data-testid={`template-insert-${variable.name}-button`}
                >
                  {`\${${variable.name}}`}
                </button>
                <div className="text-muted">{variable.description}</div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

export default TemplateEditor;
