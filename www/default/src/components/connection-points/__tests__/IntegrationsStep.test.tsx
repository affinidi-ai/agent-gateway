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

const UNCATEGORISED = { id: 'int-legacy', name: 'Legacy hook', type: 'webhook', content: {} };

const TENANT_OWNED = {
  id: 'int-tenant',
  name: 'Tenant sink',
  type: 'webhook',
  category: 'general',
  tenant_id: 'tenant-a',
  content: {},
};

interface HarnessProps {
  initial?: integrationIntegration[];
  available?: React.ComponentProps<typeof IntegrationsStep>['availableIntegrations'];
  requireEventTypes?: boolean;
  applianceWide?: boolean;
  onChange?: (integrations: integrationIntegration[]) => void;
  onValidationChange?: (hasErrors: boolean) => void;
}

const Harness: React.FC<HarnessProps> = ({
  initial = [],
  available = AVAILABLE,
  requireEventTypes = false,
  applianceWide = false,
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
      availableIntegrations={available}
      category="user"
      availableEventTypes={EVENT_TYPES}
      requireEventTypes={requireEventTypes}
      applianceWide={applianceWide}
      onValidationChange={onValidationChange}
    />
  );
};

const mapping = (integrationId: string): integrationIntegration => ({
  integration_id: integrationId,
  variables: {},
  event_types: ['user.created'],
});

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

  describe('mappings that can no longer be attached', () => {
    const unavailableRows = () => screen.queryAllByTestId(/^integration-\d+-unavailable$/);

    it('renders a mapping whose integration is unavailable as a removable row', () => {
      const onChange = jest.fn();
      const onValidationChange = jest.fn();
      render(
        <Harness
          initial={[mapping('int-deleted'), mapping('int-general')]}
          onChange={onChange}
          onValidationChange={onValidationChange}
        />
      );

      const row = screen.getByTestId('integration-0-unavailable');
      expect(within(row).getByText('int-deleted')).toBeInTheDocument();
      expect(within(row).getByText('NOT AVAILABLE')).toBeInTheDocument();
      expect(screen.getByText(/Remove the integrations marked NOT AVAILABLE/)).toBeInTheDocument();
      expect(onValidationChange).toHaveBeenLastCalledWith(true);

      fireEvent.click(within(row).getByTitle('Remove integration'));

      expect(onChange).toHaveBeenLastCalledWith([mapping('int-general')]);
      expect(unavailableRows()).toHaveLength(0);
      expect(onValidationChange).toHaveBeenLastCalledWith(false);
    });

    it('keeps the open integration open when an earlier one is removed', () => {
      render(<Harness initial={[mapping('int-deleted'), mapping('int-general')]} />);
      fireEvent.click(screen.getByText('Ops channel'));
      expect(screen.getByTestId('integration-1-event-user.created')).toBeInTheDocument();

      fireEvent.click(
        within(screen.getByTestId('integration-0-unavailable')).getByTitle('Remove integration')
      );

      expect(screen.getByTestId('integration-0-event-user.created')).toBeInTheDocument();
    });

    it('flags a mapping whose integration has the wrong category', () => {
      const onValidationChange = jest.fn();
      render(
        <Harness initial={[mapping('int-gateway')]} onValidationChange={onValidationChange} />
      );

      expect(
        within(screen.getByTestId('integration-0-unavailable')).getByText('NOT AVAILABLE')
      ).toBeInTheDocument();
      expect(onValidationChange).toHaveBeenLastCalledWith(true);
    });

    it('does not flag general or uncategorised integrations on a resource page', () => {
      const onValidationChange = jest.fn();
      render(
        <Harness
          available={[...AVAILABLE, UNCATEGORISED]}
          initial={[mapping('int-general'), mapping('int-legacy')]}
          onValidationChange={onValidationChange}
        />
      );

      expect(unavailableRows()).toHaveLength(0);
      expect(onValidationChange).toHaveBeenLastCalledWith(false);
    });

    it('flags uncategorised and tenant-owned integrations for appliance-wide events', () => {
      const onValidationChange = jest.fn();
      render(
        <Harness
          applianceWide
          available={[...AVAILABLE, UNCATEGORISED, TENANT_OWNED]}
          initial={[mapping('int-legacy'), mapping('int-tenant'), mapping('int-general')]}
          onValidationChange={onValidationChange}
        />
      );

      expect(screen.getByTestId('integration-0-unavailable')).toBeInTheDocument();
      expect(screen.getByTestId('integration-1-unavailable')).toBeInTheDocument();
      expect(screen.queryByTestId('integration-2-unavailable')).not.toBeInTheDocument();
      expect(onValidationChange).toHaveBeenLastCalledWith(true);
    });

    it('offers only integrations that appliance-wide events can use', () => {
      render(<Harness applianceWide available={[...AVAILABLE, UNCATEGORISED, TENANT_OWNED]} />);

      expect(offeredNames()).toEqual([
        'Select an integration',
        'Watch (webhook)',
        'Ops channel (slack)',
      ]);
    });
  });
});
