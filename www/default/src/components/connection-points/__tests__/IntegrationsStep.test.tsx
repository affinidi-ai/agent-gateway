/* eslint-disable no-template-curly-in-string */
import React, { useState } from 'react';
import { fireEvent, render, screen, within } from '@testing-library/react';
import '@testing-library/jest-dom';
import { IntegrationsStep, integrationIntegration } from '../IntegrationsStep';

const AVAILABLE = [
  {
    id: 'int-user',
    name: 'Watch',
    type: 'webhook',
    category: 'user',
    content: { team: '${_TEAM}', event: '${EVENT_TYPE}' },
  },
  {
    id: 'int-general',
    name: 'Ops channel',
    type: 'slack',
    category: 'general',
    content: { text: 'Event ${EVENT_TYPE}' },
  },
  { id: 'int-gateway', name: 'Gateway sink', type: 'webhook', category: 'gateway', content: {} },
];

const EVENT_TYPES = [
  { value: 'user.created', label: 'New User Registered', description: 'A user registered' },
  { value: 'user.login', label: 'User Login', description: 'A user signed in' },
];

interface HarnessProps {
  initial?: integrationIntegration[];
  requireEventTypes?: boolean;
  onChange?: (integrations: integrationIntegration[]) => void;
  onValidationChange?: (hasErrors: boolean) => void;
}

const Harness: React.FC<HarnessProps> = ({
  initial = [],
  requireEventTypes = false,
  onChange = () => undefined,
  onValidationChange = () => undefined,
}) => {
  const [integrations, setIntegrations] = useState<integrationIntegration[]>(initial);
  return (
    <IntegrationsStep
      integrations={integrations}
      onChange={next => {
        onChange(next);
        setIntegrations(next);
      }}
      availableIntegrations={AVAILABLE}
      category="user"
      availableEventTypes={EVENT_TYPES}
      requireEventTypes={requireEventTypes}
      onValidationChange={onValidationChange}
    />
  );
};

const selector = () => screen.getByTestId('integrations-step-select') as HTMLSelectElement;

const offeredNames = () =>
  within(selector())
    .getAllByRole('option')
    .map(option => option.textContent);

describe('IntegrationsStep', () => {
  it('attaches the selected integration with its template custom variables', () => {
    const onChange = jest.fn();
    render(<Harness onChange={onChange} />);

    fireEvent.change(selector(), { target: { value: 'int-user' } });

    expect(onChange).toHaveBeenLastCalledWith([
      { integration_id: 'int-user', variables: { _TEAM: '' }, event_types: [] },
    ]);
    expect(selector().value).toBe('');
  });

  it('opens the attached integration so its events can be chosen', () => {
    render(<Harness />);

    fireEvent.change(selector(), { target: { value: 'int-general' } });

    expect(screen.getByTestId('integration-0-event-user.created')).toBeInTheDocument();
  });

  it('offers only matching integrations that are not attached yet', () => {
    render(
      <Harness
        initial={[{ integration_id: 'int-user', variables: { _TEAM: 'a' }, event_types: [] }]}
      />
    );

    expect(offeredNames()).toEqual(['Select an integration', 'Ops channel (slack)']);
  });

  it('flags custom variables the template needs but the mapping lacks', () => {
    const onValidationChange = jest.fn();
    render(
      <Harness
        initial={[{ integration_id: 'int-user', variables: {}, event_types: ['user.created'] }]}
        onValidationChange={onValidationChange}
      />
    );

    expect(onValidationChange).toHaveBeenLastCalledWith(true);
  });

  it('requires at least one event type when asked to', () => {
    const onValidationChange = jest.fn();
    render(<Harness requireEventTypes onValidationChange={onValidationChange} />);

    fireEvent.change(selector(), { target: { value: 'int-general' } });
    expect(onValidationChange).toHaveBeenLastCalledWith(true);
    expect(screen.getByText('Select at least one event for each integration.')).toBeInTheDocument();

    fireEvent.click(screen.getByTestId('integration-0-event-user.created'));
    expect(onValidationChange).toHaveBeenLastCalledWith(false);
  });

  it('accepts an integration without event types when they are optional', () => {
    const onValidationChange = jest.fn();
    render(<Harness onValidationChange={onValidationChange} />);

    fireEvent.change(selector(), { target: { value: 'int-general' } });

    expect(onValidationChange).toHaveBeenLastCalledWith(false);
  });
});
