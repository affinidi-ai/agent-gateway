import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import AuditDeliveryLimitsSection from '../AuditDeliveryLimitsSection';

describe('AuditDeliveryLimitsSection', () => {
  it('shows the limits, empty meaning never', () => {
    render(
      <AuditDeliveryLimitsSection
        limits={{ maxAttempts: '10', dropAfterSecs: '' }}
        onChange={jest.fn()}
      />
    );

    expect(screen.getByTestId('integration-audit-max-attempts-input')).toHaveValue(10);
    const dropAfter = screen.getByTestId('integration-audit-drop-after-input');
    expect(dropAfter).toHaveValue(null);
    expect(dropAfter).toHaveAttribute('placeholder', 'Never');
  });

  it('reports each change with the other limit kept', () => {
    const onChange = jest.fn();
    render(
      <AuditDeliveryLimitsSection
        limits={{ maxAttempts: '10', dropAfterSecs: '3600' }}
        onChange={onChange}
      />
    );

    fireEvent.change(screen.getByTestId('integration-audit-max-attempts-input'), {
      target: { value: '20' },
    });
    expect(onChange).toHaveBeenLastCalledWith({ maxAttempts: '20', dropAfterSecs: '3600' });

    fireEvent.change(screen.getByTestId('integration-audit-drop-after-input'), {
      target: { value: '' },
    });
    expect(onChange).toHaveBeenLastCalledWith({ maxAttempts: '10', dropAfterSecs: '' });
  });

  it('flags a limit that is not a whole number of 1 or more', () => {
    render(
      <AuditDeliveryLimitsSection
        limits={{ maxAttempts: '0', dropAfterSecs: '-1' }}
        onChange={jest.fn()}
      />
    );

    expect(screen.getByTestId('integration-audit-max-attempts-input')).toHaveClass('is-invalid');
    expect(screen.getByTestId('integration-audit-max-attempts-error')).toHaveTextContent(
      'whole number of 1 or more'
    );
    expect(screen.getByTestId('integration-audit-drop-after-error')).toHaveTextContent(
      'whole number of 1 or more'
    );
  });

  it('flags nothing for valid limits', () => {
    render(
      <AuditDeliveryLimitsSection
        limits={{ maxAttempts: '5', dropAfterSecs: '' }}
        onChange={jest.fn()}
      />
    );

    expect(screen.getByTestId('integration-audit-max-attempts-input')).not.toHaveClass(
      'is-invalid'
    );
    expect(screen.queryByTestId('integration-audit-max-attempts-error')).not.toBeInTheDocument();
    expect(screen.queryByTestId('integration-audit-drop-after-error')).not.toBeInTheDocument();
  });
});
