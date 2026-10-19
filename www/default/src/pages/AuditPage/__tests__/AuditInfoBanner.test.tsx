import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import AuditInfoBanner from '../AuditInfoBanner';

describe('AuditInfoBanner', () => {
  it('stays collapsed until toggled', () => {
    const onToggle = jest.fn();
    render(<AuditInfoBanner open={false} onToggle={onToggle} />);

    expect(screen.queryByTestId('audit-about-body')).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId('audit-about-toggle'));
    expect(onToggle).toHaveBeenCalledTimes(1);
  });

  it('says the log keeps the events selected under VP Audit while VP Auditing is enabled', () => {
    render(<AuditInfoBanner open onToggle={jest.fn()} />);

    const body = screen.getByTestId('audit-about-body');
    expect(body).toHaveTextContent('Settings › Security › VP Audit');
    expect(body).toHaveTextContent('while VP Auditing is enabled');
  });

  it('says each Governance Audit integration receives its own events, at least once', () => {
    render(<AuditInfoBanner open onToggle={jest.fn()} />);

    const body = screen.getByTestId('audit-about-body');
    expect(body).toHaveTextContent('receives the events selected for it');
    expect(body).toHaveTextContent('independently of this log');
    expect(body).toHaveTextContent('at least once');
    expect(body).toHaveTextContent('deduplicate on event_id');
  });

  it('no longer claims every entry is sent or that forwarding is best-effort', () => {
    render(<AuditInfoBanner open onToggle={jest.fn()} />);

    const body = screen.getByTestId('audit-about-body');
    expect(body).not.toHaveTextContent('every entry');
    expect(body).not.toHaveTextContent('best-effort');
    expect(body).not.toHaveTextContent('record of truth');
  });
});
