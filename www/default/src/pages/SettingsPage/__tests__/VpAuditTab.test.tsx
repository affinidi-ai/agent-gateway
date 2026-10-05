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
  audit_categories: { policies: false, trust_checks: false, identity: false },
} as unknown as Settings;

describe('VpAuditTab', () => {
  it('exposes stable data-testids on the toggle and save button', () => {
    render(<VpAuditTab settings={BASE_SETTINGS} updateSettings={jest.fn()} />);

    expect(screen.getByTestId('vp-audit-enabled-toggle')).toBeInTheDocument();
    expect(screen.getByTestId('vp-audit-save-button')).toBeInTheDocument();
    // Category toggles are hidden until auditing is enabled.
    expect(screen.queryByTestId('vp-audit-category-policies')).not.toBeInTheDocument();
  });

  it('reveals the category toggles once auditing is enabled', () => {
    render(<VpAuditTab settings={BASE_SETTINGS} updateSettings={jest.fn()} />);

    fireEvent.click(screen.getByTestId('vp-audit-enabled-toggle'));

    expect(screen.getByTestId('vp-audit-category-policies')).toBeInTheDocument();
    expect(screen.getByTestId('vp-audit-category-trust_checks')).toBeInTheDocument();
    expect(screen.getByTestId('vp-audit-category-identity')).toBeInTheDocument();
  });

  it('saves the enabled flag and selected categories', async () => {
    const updateSettings = jest.fn().mockResolvedValue(undefined);
    render(<VpAuditTab settings={BASE_SETTINGS} updateSettings={updateSettings} />);

    fireEvent.click(screen.getByTestId('vp-audit-enabled-toggle'));
    fireEvent.click(screen.getByTestId('vp-audit-category-policies'));
    fireEvent.click(screen.getByTestId('vp-audit-category-trust_checks'));
    fireEvent.click(screen.getByTestId('vp-audit-save-button'));

    await waitFor(() =>
      expect(updateSettings).toHaveBeenCalledWith({
        audit_enabled: true,
        audit_categories: { policies: true, trust_checks: true, identity: false },
      })
    );
  });
});
