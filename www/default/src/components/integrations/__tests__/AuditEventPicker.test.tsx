import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import AuditEventPicker from '../AuditEventPicker';
import type { AuditEventCatalogEntry } from '../../../types';

const CATALOG: AuditEventCatalogEntry[] = [
  {
    event: 'policy_decision',
    label: 'Policy Decision',
    description: 'An OPA policy allowed or denied a request',
    group: 'policies',
    group_label: 'Policies',
  },
  {
    event: 'auth_failed',
    label: 'Auth Failed',
    description: 'A caller failed authentication',
    group: 'auth',
    group_label: 'Auth',
  },
  {
    event: 'request_rejected',
    label: 'Request Rejected',
    description: 'The Access Point refused a request',
    group: 'requests',
    group_label: 'Requests',
  },
  {
    event: 'rate_limited',
    label: 'Rate Limited',
    description: 'A request was refused because a limit was reached',
    group: 'requests',
    group_label: 'Requests',
  },
];

const showPicker = (selected: string[], onChange = jest.fn()) => {
  render(
    <AuditEventPicker
      testIdPrefix="picker"
      catalog={CATALOG}
      selected={selected}
      onChange={onChange}
    />
  );
  return onChange;
};

describe('AuditEventPicker', () => {
  it('lists every event under its group with its label and description from the catalog', () => {
    showPicker([]);

    expect(screen.getByTestId('picker-group-requests')).toBeInTheDocument();
    expect(screen.getByText('Requests')).toBeInTheDocument();
    expect(screen.getByText('Rate Limited')).toBeInTheDocument();
    expect(screen.getByText('The Access Point refused a request')).toBeInTheDocument();
    for (const entry of CATALOG) {
      expect(screen.getByTestId(`picker-event-${entry.event}`)).toBeInTheDocument();
    }
  });

  it('shows a group toggle as on, off or partly on from the selected events', () => {
    showPicker(['policy_decision', 'request_rejected']);

    const policies = screen.getByTestId('picker-group-policies') as HTMLInputElement;
    const auth = screen.getByTestId('picker-group-auth') as HTMLInputElement;
    const requests = screen.getByTestId('picker-group-requests') as HTMLInputElement;
    expect(policies).toBeChecked();
    expect(policies.indeterminate).toBe(false);
    expect(auth).not.toBeChecked();
    expect(auth.indeterminate).toBe(false);
    expect(requests).not.toBeChecked();
    expect(requests.indeterminate).toBe(true);
  });

  it('turns on every event in a group that is not fully on', () => {
    const onChange = showPicker(['request_rejected']);

    fireEvent.click(screen.getByTestId('picker-group-requests'));

    expect(onChange).toHaveBeenCalledWith(['request_rejected', 'rate_limited']);
  });

  it('turns off every event in a group that is fully on, leaving other groups', () => {
    const onChange = showPicker(['policy_decision', 'request_rejected', 'rate_limited']);

    fireEvent.click(screen.getByTestId('picker-group-requests'));

    expect(onChange).toHaveBeenCalledWith(['policy_decision']);
  });

  it('changes only the event whose toggle is clicked', () => {
    const onChange = showPicker(['policy_decision']);

    fireEvent.click(screen.getByTestId('picker-event-auth_failed'));

    expect(onChange).toHaveBeenCalledWith(['policy_decision', 'auth_failed']);
  });

  it('keeps selected events the catalog does not list', () => {
    const onChange = showPicker(['retired_event', 'policy_decision']);

    fireEvent.click(screen.getByTestId('picker-event-policy_decision'));

    expect(onChange).toHaveBeenCalledWith(['retired_event']);
  });

  it('disables every toggle when disabled', () => {
    render(
      <AuditEventPicker
        testIdPrefix="picker"
        catalog={CATALOG}
        selected={[]}
        onChange={jest.fn()}
        disabled
      />
    );

    expect(screen.getByTestId('picker-group-auth')).toBeDisabled();
    expect(screen.getByTestId('picker-event-auth_failed')).toBeDisabled();
  });
});
