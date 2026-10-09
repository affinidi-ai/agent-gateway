import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import PublishingTab from './PublishingTab';
import { ExposureMode } from '../../utils/gateways';

const channels = [
  { config_id: 'alpha', name: 'Alpha' },
  { config_id: 'beta', name: 'Beta' },
];

function renderTab(exposureMode: ExposureMode | undefined, exposedChannels: string[] = []) {
  const setForm = jest.fn();
  const onToggle = jest.fn();
  const onSave = jest.fn();
  const form = {
    name: 'Peer',
    description: '',
    did: 'did:web:peer.example',
    gateway_type: 'remote' as const,
    status: 'active' as const,
    exposed_channels: exposedChannels,
    exposure_mode: exposureMode,
  };
  render(
    <PublishingTab
      form={form}
      setForm={setForm}
      allChannels={channels}
      savingExposedChannels={false}
      success={null}
      setSuccess={jest.fn()}
      handleToggleExposedChannel={onToggle}
      handleSaveExposedChannels={onSave}
    />
  );
  return { form, setForm, onToggle, onSave };
}

describe('PublishingTab exposure mode', () => {
  it('checks the current mode and hides the surface list outside list mode', () => {
    renderTab('none');

    expect(screen.getByTestId('gateway-exposure-mode-none')).toBeChecked();
    expect(screen.getByTestId('gateway-exposure-mode-all')).not.toBeChecked();
    expect(screen.queryByTestId('gateway-exposure-surfaces')).not.toBeInTheDocument();
    expect(screen.getByTestId('gateway-exposure-summary')).toHaveTextContent(
      'No surfaces are exposed'
    );
  });

  it('treats a form without a mode as none', () => {
    renderTab(undefined);

    expect(screen.getByTestId('gateway-exposure-mode-none')).toBeChecked();
  });

  it('shows the selected surfaces in list mode', () => {
    const { onToggle } = renderTab('list', ['alpha']);

    expect(screen.getByTestId('gateway-exposure-surface-alpha')).toBeChecked();
    expect(screen.getByTestId('gateway-exposure-surface-beta')).not.toBeChecked();
    expect(screen.getByTestId('gateway-exposure-summary')).toHaveTextContent(
      '1 of 2 surfaces selected'
    );

    fireEvent.click(screen.getByTestId('gateway-exposure-surface-beta'));
    expect(onToggle).toHaveBeenCalledWith('beta');
  });

  it('changes the mode and saves', () => {
    const { form, setForm, onSave } = renderTab('none');

    fireEvent.click(screen.getByTestId('gateway-exposure-mode-all'));
    expect(setForm).toHaveBeenCalledWith({ ...form, exposure_mode: 'all' });

    fireEvent.click(screen.getByTestId('gateway-exposure-save-button'));
    expect(onSave).toHaveBeenCalled();
  });
});
