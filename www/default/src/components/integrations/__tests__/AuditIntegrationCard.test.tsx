import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import AuditIntegrationCard from '../AuditIntegrationCard';

describe('AuditIntegrationCard', () => {
  it.each(['stream', 'webhook'])('offers the audit record template for %s integrations', type => {
    const onUseTemplate = jest.fn();
    render(<AuditIntegrationCard type={type} onUseTemplate={onUseTemplate} />);

    expect(screen.getByTestId('integration-audit-card')).toHaveTextContent('VP Audit Log');
    fireEvent.click(screen.getByTestId('integration-audit-template-button'));
    expect(onUseTemplate).toHaveBeenCalledTimes(1);
  });

  it.each(['slack', 'email'])('has no payload template for %s integrations', type => {
    render(<AuditIntegrationCard type={type} onUseTemplate={jest.fn()} />);

    expect(screen.getByTestId('integration-audit-card')).toBeInTheDocument();
    expect(screen.queryByTestId('integration-audit-template-button')).not.toBeInTheDocument();
  });

  it('warns that caller data and the signed VP leave the appliance', () => {
    render(<AuditIntegrationCard type="stream" onUseTemplate={jest.fn()} />);

    const warning = screen.getByTestId('integration-audit-data-warning');
    expect(warning).toHaveTextContent('leave the appliance');
    expect(warning).toHaveTextContent('AUDIT_VP_JWT');
  });

  it('disables the template action while saving', () => {
    const onUseTemplate = jest.fn();
    render(<AuditIntegrationCard type="stream" onUseTemplate={onUseTemplate} disabled />);

    const button = screen.getByTestId('integration-audit-template-button');
    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(onUseTemplate).not.toHaveBeenCalled();
  });
});
