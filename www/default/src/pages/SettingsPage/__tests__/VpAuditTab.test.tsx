import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import VpAuditTab from '../VpAuditTab';
import type { AuditEventCatalogEntry, Settings } from '../../../types';

jest.mock('../../../utils/toaster', () => ({
  showToast: jest.fn(),
}));

const BASE_SETTINGS = {
  audit_enabled: false,
  audit_events: [],
} as unknown as Settings;

const entry = (event: string, group: string, group_label: string): AuditEventCatalogEntry => ({
  event,
  label: event,
  description: `${event} description`,
  group,
  group_label,
});

const CATALOG: AuditEventCatalogEntry[] = [
  entry('policy_decision', 'policies', 'Policies'),
  entry('trust_check', 'trust', 'Trust'),
  entry('vp_injected', 'identity', 'Identity'),
  entry('auth_failed', 'auth', 'Auth'),
];

const loadCatalog = () => Promise.resolve(CATALOG);

describe('VpAuditTab', () => {
  it('exposes stable data-testids on the toggle and save button', () => {
    render(
      <VpAuditTab settings={BASE_SETTINGS} updateSettings={jest.fn()} loadCatalog={loadCatalog} />
    );

    expect(screen.getByTestId('vp-audit-enabled-toggle')).toBeInTheDocument();
    expect(screen.getByTestId('vp-audit-save-button')).toBeInTheDocument();
    // Event toggles are hidden until auditing is enabled.
    expect(screen.queryByTestId('vp-audit-event-policy_decision')).not.toBeInTheDocument();
  });

  it('lists every catalog event under its group once auditing is enabled', async () => {
    render(
      <VpAuditTab settings={BASE_SETTINGS} updateSettings={jest.fn()} loadCatalog={loadCatalog} />
    );

    fireEvent.click(screen.getByTestId('vp-audit-enabled-toggle'));

    expect(await screen.findByTestId('vp-audit-event-auth_failed')).toBeInTheDocument();
    expect(screen.getByTestId('vp-audit-group-auth')).toBeInTheDocument();
    for (const { event } of CATALOG) {
      expect(screen.getByTestId(`vp-audit-event-${event}`)).toBeInTheDocument();
    }
  });

  it('says it controls the audit log only', () => {
    render(
      <VpAuditTab settings={BASE_SETTINGS} updateSettings={jest.fn()} loadCatalog={loadCatalog} />
    );

    expect(screen.getByTestId('vp-audit-scope-note')).toHaveTextContent(
      'Governance Audit integrations choose their own events'
    );
  });

  it('checks the events stored in the settings', async () => {
    const settings = {
      audit_enabled: true,
      audit_events: ['trust_check'],
    } as unknown as Settings;
    render(<VpAuditTab settings={settings} updateSettings={jest.fn()} loadCatalog={loadCatalog} />);

    expect(await screen.findByTestId('vp-audit-event-trust_check')).toBeChecked();
    expect(screen.getByTestId('vp-audit-event-policy_decision')).not.toBeChecked();
  });

  it('saves the enabled flag and the selected events', async () => {
    const updateSettings = jest.fn().mockResolvedValue(undefined);
    render(
      <VpAuditTab
        settings={BASE_SETTINGS}
        updateSettings={updateSettings}
        loadCatalog={loadCatalog}
      />
    );

    fireEvent.click(screen.getByTestId('vp-audit-enabled-toggle'));
    fireEvent.click(await screen.findByTestId('vp-audit-event-policy_decision'));
    fireEvent.click(screen.getByTestId('vp-audit-group-auth'));
    fireEvent.click(screen.getByTestId('vp-audit-save-button'));

    await waitFor(() =>
      expect(updateSettings).toHaveBeenCalledWith({
        audit_enabled: true,
        audit_events: ['policy_decision', 'auth_failed'],
      })
    );
  });

  it('keeps stored events the catalog does not list when saving', async () => {
    const updateSettings = jest.fn().mockResolvedValue(undefined);
    const settings = {
      audit_enabled: true,
      audit_events: ['retired_event', 'policy_decision'],
    } as unknown as Settings;
    render(
      <VpAuditTab settings={settings} updateSettings={updateSettings} loadCatalog={loadCatalog} />
    );

    fireEvent.click(await screen.findByTestId('vp-audit-event-policy_decision'));
    fireEvent.click(screen.getByTestId('vp-audit-save-button'));

    await waitFor(() =>
      expect(updateSettings).toHaveBeenCalledWith({
        audit_enabled: true,
        audit_events: ['retired_event'],
      })
    );
  });

  it('says when the event list cannot be loaded', async () => {
    const settings = { audit_enabled: true, audit_events: [] } as unknown as Settings;
    render(
      <VpAuditTab
        settings={settings}
        updateSettings={jest.fn()}
        loadCatalog={() => Promise.reject(new Error('offline'))}
      />
    );

    expect(await screen.findByTestId('vp-audit-catalog-error')).toHaveTextContent(
      'could not be loaded'
    );
  });
});
