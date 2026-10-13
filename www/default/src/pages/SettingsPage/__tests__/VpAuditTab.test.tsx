import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import VpAuditTab from '../VpAuditTab';
import type { Settings } from '../../../types';

jest.mock('../../../utils/toaster', () => ({
  showToast: jest.fn(),
}));

const BASE_SETTINGS = {
  audit_enabled: false,
  audit_events: [],
} as unknown as Settings;

describe('VpAuditTab', () => {
  it('exposes stable data-testids on the toggle and save button', () => {
    render(<VpAuditTab settings={BASE_SETTINGS} updateSettings={jest.fn()} />);

    expect(screen.getByTestId('vp-audit-enabled-toggle')).toBeInTheDocument();
    expect(screen.getByTestId('vp-audit-save-button')).toBeInTheDocument();
    // Event toggles are hidden until auditing is enabled.
    expect(screen.queryByTestId('vp-audit-event-policy_decision')).not.toBeInTheDocument();
  });

  it('reveals the event toggles once auditing is enabled', () => {
    render(<VpAuditTab settings={BASE_SETTINGS} updateSettings={jest.fn()} />);

    fireEvent.click(screen.getByTestId('vp-audit-enabled-toggle'));

    expect(screen.getByTestId('vp-audit-event-policy_decision')).toBeInTheDocument();
    expect(screen.getByTestId('vp-audit-event-trust_check')).toBeInTheDocument();
    expect(screen.getByTestId('vp-audit-event-vp_injected')).toBeInTheDocument();
  });

  it('checks the events stored in the settings', () => {
    const settings = {
      audit_enabled: true,
      audit_events: ['trust_check'],
    } as unknown as Settings;
    render(<VpAuditTab settings={settings} updateSettings={jest.fn()} />);

    expect(screen.getByTestId('vp-audit-event-trust_check')).toBeChecked();
    expect(screen.getByTestId('vp-audit-event-policy_decision')).not.toBeChecked();
  });

  it('saves the enabled flag and the selected events', async () => {
    const updateSettings = jest.fn().mockResolvedValue(undefined);
    render(<VpAuditTab settings={BASE_SETTINGS} updateSettings={updateSettings} />);

    fireEvent.click(screen.getByTestId('vp-audit-enabled-toggle'));
    fireEvent.click(screen.getByTestId('vp-audit-event-policy_decision'));
    fireEvent.click(screen.getByTestId('vp-audit-event-trust_check'));
    fireEvent.click(screen.getByTestId('vp-audit-save-button'));

    await waitFor(() =>
      expect(updateSettings).toHaveBeenCalledWith({
        audit_enabled: true,
        audit_events: ['policy_decision', 'trust_check'],
      })
    );
  });

  it('keeps stored events the tab does not show when saving', async () => {
    const updateSettings = jest.fn().mockResolvedValue(undefined);
    const settings = {
      audit_enabled: true,
      audit_events: ['auth_failed', 'policy_decision'],
    } as unknown as Settings;
    render(<VpAuditTab settings={settings} updateSettings={updateSettings} />);

    fireEvent.click(screen.getByTestId('vp-audit-event-policy_decision'));
    fireEvent.click(screen.getByTestId('vp-audit-save-button'));

    await waitFor(() =>
      expect(updateSettings).toHaveBeenCalledWith({
        audit_enabled: true,
        audit_events: ['auth_failed'],
      })
    );
  });
});
