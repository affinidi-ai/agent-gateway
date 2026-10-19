import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import AuditEventsSection from '../AuditEventsSection';
import type { AuditEventCatalogEntry } from '../../../types';

const CATALOG: AuditEventCatalogEntry[] = [
  {
    event: 'policy_decision',
    label: 'Policy Decision',
    description: 'An OPA policy allowed or denied a request',
    group: 'policies',
    group_label: 'Policies',
  },
  {
    event: 'auth_failed',
    label: 'Auth Failed',
    description: 'A caller failed authentication',
    group: 'auth',
    group_label: 'Auth',
  },
];

const loadCatalog = () => Promise.resolve(CATALOG);

describe('AuditEventsSection', () => {
  it('lists the catalog events for the integration to receive', async () => {
    render(<AuditEventsSection selected={[]} onChange={jest.fn()} loadCatalog={loadCatalog} />);

    expect(
      await screen.findByTestId('integration-audit-event-policy_decision')
    ).toBeInTheDocument();
    expect(screen.getByTestId('integration-audit-group-auth')).toBeInTheDocument();
  });

  it('warns that an integration with no events selected receives nothing', async () => {
    render(<AuditEventsSection selected={[]} onChange={jest.fn()} loadCatalog={loadCatalog} />);

    expect(await screen.findByTestId('integration-audit-events-empty')).toHaveTextContent(
      'will receive nothing'
    );
  });

  it('shows no warning once an event is selected', async () => {
    render(
      <AuditEventsSection
        selected={['auth_failed']}
        onChange={jest.fn()}
        loadCatalog={loadCatalog}
      />
    );

    expect(await screen.findByTestId('integration-audit-event-auth_failed')).toBeChecked();
    expect(screen.queryByTestId('integration-audit-events-empty')).not.toBeInTheDocument();
  });

  it('reports the selection the operator makes', async () => {
    const onChange = jest.fn();
    render(<AuditEventsSection selected={[]} onChange={onChange} loadCatalog={loadCatalog} />);

    fireEvent.click(await screen.findByTestId('integration-audit-group-policies'));

    expect(onChange).toHaveBeenCalledWith(['policy_decision']);
  });

  it('says when the event list cannot be loaded and offers no toggles', async () => {
    render(
      <AuditEventsSection
        selected={['auth_failed']}
        onChange={jest.fn()}
        loadCatalog={() => Promise.reject(new Error('offline'))}
      />
    );

    expect(await screen.findByTestId('integration-audit-events-error')).toHaveTextContent(
      'current selection is kept'
    );
    expect(screen.queryByTestId('integration-audit-event-auth_failed')).not.toBeInTheDocument();
  });
});
