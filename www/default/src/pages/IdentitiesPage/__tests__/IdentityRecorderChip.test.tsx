import React from 'react';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import type { TrustRecorderReason, TrustRecorderState, TrustRecorderStatus } from '../../../types';
import { IdentityRecorderChip } from '../IdentityRecorderChip';

const status = (
  state: TrustRecorderState,
  overrides: Partial<TrustRecorderStatus> = {}
): TrustRecorderStatus => ({
  state,
  reason: null,
  last_attempt_at: null,
  entries: [],
  ...overrides,
});

describe('IdentityRecorderChip', () => {
  it.each<[TrustRecorderState, string]>([
    ['recorded', 'Recorded'],
    ['partial', 'Partly recorded'],
    ['failed', 'Failed'],
    ['skipped', 'Skipped'],
    ['not_attempted', 'Not attempted yet'],
  ])('renders the %s state with the text "%s"', (state, label) => {
    render(<IdentityRecorderChip status={status(state)} />);

    const chip = screen.getByTestId(`identities-recorder-chip-${state}`);
    expect(chip).toHaveTextContent(label);
    expect(chip).toHaveAccessibleName(`Trust Recorder status: ${label}`);
  });

  it('renders nothing when the identity has no recorder', () => {
    const { container } = render(<IdentityRecorderChip />);

    expect(container).toBeEmptyDOMElement();
  });

  it('is a keyboard-focusable button that does not toggle the row', async () => {
    const onRowClick = jest.fn();
    render(
      <div onClick={onRowClick} role="presentation">
        <IdentityRecorderChip status={status('recorded')} />
      </div>
    );

    const chip = screen.getByRole('button', { name: 'Trust Recorder status: Recorded' });
    await userEvent.tab();
    expect(chip).toHaveFocus();

    fireEvent.click(chip);
    expect(onRowClick).not.toHaveBeenCalled();
  });

  it('shows the last attempt and one row per registry in the tooltip on focus', async () => {
    const at = new Date(Date.now() - 10 * 60 * 1000).toISOString();
    render(
      <IdentityRecorderChip
        status={status('partial', {
          last_attempt_at: at,
          entries: [
            {
              trust_registry_id: 'reg-a',
              state: 'recorded',
              reason: null,
              created: 2,
              already_existed: 1,
              failed: 0,
            },
            {
              trust_registry_id: 'reg-b',
              state: 'failed',
              reason: 'rejected',
              created: 0,
              already_existed: 0,
              failed: 3,
            },
          ],
        })}
      />
    );

    expect(screen.queryByTestId('identities-recorder-tooltip')).not.toBeInTheDocument();
    await userEvent.tab();

    expect(await screen.findByTestId('identities-recorder-tooltip')).toBeInTheDocument();
    expect(screen.getByTestId('identities-recorder-last-attempt')).toHaveTextContent(
      /^Last attempt: 10 minutes ago \(.+\)$/
    );
    const entryA = screen.getByTestId('identities-recorder-entry-reg-a');
    expect(entryA).toHaveTextContent('reg-a');
    expect(entryA).toHaveTextContent('Recorded');
    expect(entryA).toHaveTextContent('created 2, already existed 1, failed 0');
    const entryB = screen.getByTestId('identities-recorder-entry-reg-b');
    expect(entryB).toHaveTextContent('Failed: Registry rejected the record');
    expect(entryB).toHaveTextContent('created 0, already existed 0, failed 3');
    expect(screen.queryByTestId('identities-recorder-reason')).not.toBeInTheDocument();
  });

  it('shows the tooltip on hover and hides it again', async () => {
    render(<IdentityRecorderChip status={status('recorded')} />);
    const chip = screen.getByTestId('identities-recorder-chip-recorded');

    await userEvent.hover(chip);
    expect(await screen.findByTestId('identities-recorder-tooltip')).toBeInTheDocument();

    await userEvent.unhover(chip);
    await waitFor(() =>
      expect(screen.queryByTestId('identities-recorder-tooltip')).not.toBeInTheDocument()
    );
  });

  it('says No attempt yet when there is no attempt time and no entries', async () => {
    render(<IdentityRecorderChip status={status('not_attempted')} />);

    await userEvent.tab();
    const tooltip = await screen.findByTestId('identities-recorder-tooltip');

    expect(within(tooltip).getByTestId('identities-recorder-last-attempt')).toHaveTextContent(
      'No attempt yet'
    );
    expect(within(tooltip).queryByRole('listitem')).not.toBeInTheDocument();
  });

  it.each<[TrustRecorderReason, string]>([
    ['registry_not_found', 'Trust registry not found'],
    ['registry_not_connected', 'Trust registry not connected'],
    ['no_surface_issuer', 'Surface has no Issuer'],
    ['no_response', 'No response from the registry'],
    ['rejected', 'Registry rejected the record'],
    ['error', 'Registry error'],
  ])('explains reason %s as "%s"', async (reason, text) => {
    render(<IdentityRecorderChip status={status('skipped', { reason })} />);

    await userEvent.tab();

    expect(await screen.findByTestId('identities-recorder-reason')).toHaveTextContent(text);
  });
});
