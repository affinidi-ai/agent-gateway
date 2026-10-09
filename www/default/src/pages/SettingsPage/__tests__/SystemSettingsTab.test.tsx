import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import SystemSettingsTab from '../SystemSettingsTab';
import { Settings } from '../../../types';

const SETTINGS: Settings = {
  badge_threshold: 5,
  metrics_retention: 360,
  task_activity_window: 60,
  connections_window: 60,
  latency_window: 60,
  onboarding_channel_ttl_seconds: 30,
  refresh_interval_seconds: 5,
  log_timestamp_format: 'local',
  bucket_seconds: 30,
  payments_min_display: 10,
};

function applianceIdInput(formData: Settings, onInputChange = jest.fn()) {
  render(
    <SystemSettingsTab
      formData={formData}
      isSubmitting={false}
      onInputChange={onInputChange}
      onSave={jest.fn()}
      onReset={jest.fn()}
    />
  );
  return screen.getByTestId('settings-appliance-id-input') as HTMLInputElement;
}

describe('SystemSettingsTab appliance id', () => {
  it('starts empty and explains that an unset id is sent unfilled', () => {
    const input = applianceIdInput(SETTINGS);

    expect(input.value).toBe('');
    expect(input.placeholder).toContain('Agent Watch');
    expect(screen.getByText(/sent unfilled/)).toBeInTheDocument();
  });

  it('shows the configured id and reports edits as text', () => {
    const onInputChange = jest.fn();
    const input = applianceIdInput({ ...SETTINGS, appliance_id: 'aw-appliance-42' }, onInputChange);

    expect(input.value).toBe('aw-appliance-42');
    expect(input).toHaveAttribute('type', 'text');
    fireEvent.change(input, { target: { value: 'aw-appliance-43' } });
    expect(onInputChange).toHaveBeenCalledTimes(1);
    expect(onInputChange.mock.calls[0][0].target.name).toBe('appliance_id');
  });
});
