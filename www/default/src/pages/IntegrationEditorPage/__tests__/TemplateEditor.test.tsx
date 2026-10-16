/* eslint-disable no-template-curly-in-string -- ${NAME} is the gateway's placeholder syntax */
import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import TemplateEditor from '../TemplateEditor';
import { CatalogVariable, EndpointType } from '../../../integrationsApi';

const VARIABLES: CatalogVariable[] = [
  { name: 'EVENT_NAME', label: 'Event name', description: 'The name of the event' },
  { name: 'GATEWAY_NAME', label: 'Gateway name', description: 'The gateway that changed' },
];

function Harness({
  type,
  initial = {},
}: {
  type: EndpointType;
  initial?: Record<string, unknown>;
}) {
  const [content, setContent] = useState<Record<string, unknown>>(initial);
  const [valid, setValid] = useState(true);
  return (
    <>
      <TemplateEditor
        type={type}
        content={content}
        onChange={setContent}
        variables={VARIABLES}
        onValidityChange={setValid}
      />
      <output data-testid="content">{JSON.stringify(content)}</output>
      <output data-testid="valid">{String(valid)}</output>
    </>
  );
}

const content = () => JSON.parse(screen.getByTestId('content').textContent || '{}');

test('email fields show the gateway default and only keep what is written', () => {
  render(<Harness type="email" />);
  const subject = screen.getByLabelText('Subject');
  expect(subject).toHaveAttribute('placeholder', '${EVENT_NAME}');
  expect(screen.getByLabelText('Body')).toHaveAttribute('placeholder', '${EVENT_SUMMARY}');

  fireEvent.change(subject, { target: { value: 'Alert: ${GATEWAY_NAME}' } });
  expect(content()).toEqual({ subject: 'Alert: ${GATEWAY_NAME}' });

  fireEvent.change(subject, { target: { value: '' } });
  expect(content()).toEqual({});
});

test('an email can be sent as HTML', () => {
  render(<Harness type="email" />);

  fireEvent.change(screen.getByLabelText('Format'), { target: { value: 'html' } });
  expect(content()).toEqual({ format: 'html' });

  fireEvent.change(screen.getByLabelText('Format'), { target: { value: '' } });
  expect(content()).toEqual({});
});

test('slack has one message field', () => {
  render(<Harness type="slack" />);

  fireEvent.change(screen.getByLabelText('Message'), { target: { value: '${EVENT_NAME}' } });

  expect(content()).toEqual({ text: '${EVENT_NAME}' });
});

test('a webhook payload is a JSON object, shown as stored', () => {
  render(<Harness type="webhook" initial={{ alert: '${EVENT_NAME}' }} />);
  const payload = screen.getByLabelText('Payload');
  expect(JSON.parse((payload as HTMLTextAreaElement).value)).toEqual({ alert: '${EVENT_NAME}' });

  fireEvent.change(payload, { target: { value: '{"gateway": "${GATEWAY_NAME}"}' } });
  expect(content()).toEqual({ gateway: '${GATEWAY_NAME}' });
  expect(screen.getByTestId('valid')).toHaveTextContent('true');
});

test.each([
  ['not JSON', '{"gateway": '],
  ['not an object', '["a", "b"]'],
])('a payload that is %s is reported and not taken', (_, text) => {
  render(<Harness type="stream" initial={{ kept: true }} />);

  fireEvent.change(screen.getByLabelText('Payload'), { target: { value: text } });

  expect(screen.getByText(/payload must be a json object/i)).toBeInTheDocument();
  expect(screen.getByTestId('valid')).toHaveTextContent('false');
  expect(content()).toEqual({ kept: true });
});

test('an empty payload sends the default envelope', () => {
  render(<Harness type="stream" initial={{ kept: true }} />);
  const payload = screen.getByLabelText('Payload');
  expect(payload.getAttribute('placeholder')).toContain('"event_type": "${EVENT_TYPE}"');

  fireEvent.change(payload, { target: { value: '' } });

  expect(content()).toEqual({});
  expect(screen.getByTestId('valid')).toHaveTextContent('true');
});

test('lists the variables the event set fills, and inserts one where the cursor is', () => {
  render(<Harness type="email" initial={{ subject: 'Gateway  changed' }} />);
  expect(screen.getByText('The gateway that changed')).toBeInTheDocument();

  const subject = screen.getByLabelText('Subject') as HTMLInputElement;
  fireEvent.focus(subject);
  subject.setSelectionRange(8, 8);
  fireEvent.select(subject);
  fireEvent.click(screen.getByRole('button', { name: /insert gateway_name/i }));

  expect(content()).toEqual({ subject: 'Gateway ${GATEWAY_NAME} changed' });
});

test('warns about variables no event of the set fills', () => {
  render(<Harness type="slack" initial={{ text: '${EVENT_NAME} by ${USERNAME}' }} />);

  expect(screen.getByRole('alert')).toHaveTextContent(
    'No event of the event set fills USERNAME, so the integration cannot be saved with it.'
  );
});
