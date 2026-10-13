import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import NetworkingPanel from '../networking/NetworkingPanel';

function showPanel(config: Record<string, unknown>, errorByField?: Record<string, string>) {
  const updateField = jest.fn();
  render(
    <NetworkingPanel
      {...({
        node: { id: 'networking', type: 'networking', label: '', configured: true, config },
        config,
        updateField,
        updateFields: jest.fn(),
        errorByField,
      } as any)}
    />
  );
  return updateField;
}

describe('NetworkingPanel retryable status codes', () => {
  it('shows an empty field as the gateway default', () => {
    showPanel({ retry_enabled: true });

    const input = screen.getByTestId('networking-retry-status-codes-input');
    expect(input).toHaveAttribute('placeholder', 'Gateway default');
    expect(input).toHaveValue('');
    expect(input).toBeEnabled();
    expect(screen.getByTestId('networking-retry-connection-errors-only-switch')).not.toBeChecked();
  });

  it('shows connection errors only with the codes field disabled', () => {
    showPanel({ retry_enabled: true, retry_connection_errors_only: true });

    expect(screen.getByTestId('networking-retry-connection-errors-only-switch')).toBeChecked();
    expect(screen.getByTestId('networking-retry-status-codes-input')).toBeDisabled();
  });

  it('turns connection errors only on from the switch', () => {
    const updateField = showPanel({ retry_enabled: true });

    fireEvent.click(screen.getByTestId('networking-retry-connection-errors-only-switch'));

    expect(updateField).toHaveBeenCalledWith('retry_connection_errors_only', true);
  });

  it('shows the validation error under the codes field', () => {
    showPanel(
      { retry_enabled: true, retry_status_codes: 'abc' },
      { retry_status_codes: 'Enter HTTP status codes separated by commas, e.g. 502,503,504' }
    );

    expect(screen.getByTestId('networking-retry-status-codes-input')).toHaveClass('is-invalid');
    expect(
      screen.getByText('Enter HTTP status codes separated by commas, e.g. 502,503,504')
    ).toBeInTheDocument();
  });
});
