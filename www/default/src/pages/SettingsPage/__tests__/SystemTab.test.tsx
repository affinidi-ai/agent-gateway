import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import SystemTab from '../SystemTab';
import type { Settings } from '../../../types';

jest.mock('../../../api', () => ({
  apiClient: {},
}));

jest.mock('../../../utils/toaster', () => ({
  showToast: jest.fn(),
}));

const SETTINGS = {
  feature_flags: { a2a_legacy_compatibility: false },
} as unknown as Settings;

const renderTab = (settings: Settings = SETTINGS) =>
  render(
    <SystemTab
      isSubmitting={false}
      onTruncateMetrics={jest.fn()}
      settings={settings}
      updateSettings={jest.fn()}
    />
  );

describe('SystemTab feature flags', () => {
  it.each(['metrics', 'a2a_legacy_compatibility', 'agent_pay_delegation'])(
    'names the %s switch after its flag',
    flag => {
      renderTab();

      expect(screen.getByRole('switch', { name: flag })).toBe(
        screen.getByTestId(`settings-flag-${flag}`)
      );
    }
  );

  it('reflects the flag state on the named switch', () => {
    renderTab();

    expect(screen.getByRole('switch', { name: 'metrics' })).toBeChecked();
    expect(screen.getByRole('switch', { name: 'a2a_legacy_compatibility' })).not.toBeChecked();
  });

  it('shows A2A legacy compatibility on when the flag is unset', () => {
    renderTab({ feature_flags: {} } as unknown as Settings);

    expect(screen.getByRole('switch', { name: 'a2a_legacy_compatibility' })).toBeChecked();
  });

  it('turns A2A legacy compatibility off with an explicit false', async () => {
    const updateSettings = jest.fn().mockResolvedValue(undefined);
    render(
      <SystemTab
        isSubmitting={false}
        onTruncateMetrics={jest.fn()}
        settings={{ feature_flags: {} } as unknown as Settings}
        updateSettings={updateSettings}
      />
    );

    fireEvent.click(screen.getByRole('switch', { name: 'a2a_legacy_compatibility' }));

    await waitFor(() =>
      expect(updateSettings).toHaveBeenCalledWith({
        feature_flags: { a2a_legacy_compatibility: false },
      })
    );
  });

  it('names every switch after its own flag', () => {
    renderTab();

    for (const toggle of screen.getAllByRole('switch')) {
      const flag = toggle.getAttribute('data-testid')?.replace(/^settings-flag-/, '');
      expect(flag).toBeTruthy();
      expect(toggle).toHaveAccessibleName(flag as string);
    }
  });
});
