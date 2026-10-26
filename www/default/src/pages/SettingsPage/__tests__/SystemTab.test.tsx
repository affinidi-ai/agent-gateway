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
  feature_flags: { metrics: false },
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
  it.each(['metrics', 'mediator_federation'])('names the %s switch after its flag', flag => {
    renderTab();

    expect(screen.getByRole('switch', { name: flag })).toBe(
      screen.getByTestId(`settings-flag-${flag}`)
    );
  });

  it('reflects the flag state on the named switch', () => {
    renderTab();

    expect(screen.getByRole('switch', { name: 'metrics' })).not.toBeChecked();
    expect(screen.getByRole('switch', { name: 'mediator_federation' })).not.toBeChecked();
  });

  it('has no Agent-Pay delegation switch', () => {
    renderTab();

    expect(screen.queryByTestId('settings-flag-agent_pay_delegation')).not.toBeInTheDocument();
  });

  // Accepted A2A versions are set per A2A surface, on its Access Point.
  it('has no A2A legacy compatibility switch', () => {
    renderTab({ feature_flags: {} } as unknown as Settings);

    expect(screen.queryByTestId('settings-flag-a2a_legacy_compatibility')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('switch', { name: 'a2a_legacy_compatibility' })
    ).not.toBeInTheDocument();
  });

  it('turns a flag on with an explicit true', async () => {
    const updateSettings = jest.fn().mockResolvedValue(undefined);
    render(
      <SystemTab
        isSubmitting={false}
        onTruncateMetrics={jest.fn()}
        settings={{ feature_flags: {} } as unknown as Settings}
        updateSettings={updateSettings}
      />
    );

    fireEvent.click(screen.getByRole('switch', { name: 'mediator_federation' }));

    await waitFor(() =>
      expect(updateSettings).toHaveBeenCalledWith({
        feature_flags: { mediator_federation: true },
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

describe('SystemTab restore from backup', () => {
  it('tells the operator legacy .tgwbak backups are still supported', () => {
    renderTab();

    expect(screen.getByTestId('restore-legacy-format-note')).toHaveTextContent(
      'Legacy .tgwbak backups are still supported.'
    );
    expect(screen.getByTestId('restore-file-input')).toHaveAttribute('accept', '.agbak,.tgwbak');
  });

  it('names both backup extensions when the selected file is not a backup', () => {
    renderTab();
    const { showToast } = jest.requireMock('../../../utils/toaster');

    fireEvent.change(screen.getByTestId('restore-file-input'), {
      target: { files: [new File(['x'], 'backup.zip')] },
    });

    expect(showToast).toHaveBeenCalledWith(
      'error',
      'Please select a .agbak or legacy .tgwbak backup file'
    );
  });
});
