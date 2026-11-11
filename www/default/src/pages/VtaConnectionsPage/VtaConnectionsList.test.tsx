import React from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { VtaConnectionsList } from './VtaConnectionsList';
import type { VtaConnection } from './types';

const connection = (id: string, state: VtaConnection['pairing']['state']): VtaConnection =>
  ({
    id,
    name: id === 'vta-bootstrap' ? 'Bootstrap VTA' : 'Customer VTA',
    enabled: true,
    transport: 'https',
    endpoint: 'http://127.0.0.1:8100',
    vta_did: 'did:key:z6MkVta',
    default_context_id: 'gateway',
    status: state === 'connected' ? 'connected' : 'unpaired',
    pairing: { state, granted_role: 'initiator', granted_contexts: ['gateway'] },
    keys: {},
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  }) as unknown as VtaConnection;

const renderList = (
  connections: VtaConnection[],
  extra: Partial<React.ComponentProps<typeof VtaConnectionsList>> = {}
) =>
  render(
    <VtaConnectionsList
      connections={connections}
      busyId={null}
      canEdit
      canDelete
      canRotateKeys
      onOpen={() => {}}
      onVerify={() => {}}
      onRevoke={() => {}}
      onRotateKey={() => {}}
      onCancelRotation={() => {}}
      {...extra}
    />
  );

const webvh = (overrides: Partial<VtaConnection> = {}): VtaConnection => ({
  ...connection('customer-1', 'connected'),
  control_did: 'did:webvh:QmScid:gw.example.com:vta-auth:customer-1',
  ...overrides,
});

describe('VtaConnectionsList', () => {
  it('shows the [vta] block agent as connected, not as waiting to be paired', () => {
    renderList([connection('vta-bootstrap', 'connected')]);
    expect(screen.getByText('Connected')).toBeInTheDocument();
    expect(screen.queryByText(/Not paired/)).not.toBeInTheDocument();
  });

  it('offers no Revoke or Verify on the bootstrap connection, which the server refuses both', () => {
    renderList([connection('vta-bootstrap', 'connected')]);
    expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Verify' })).not.toBeInTheDocument();
  });

  it('still offers Verify and Revoke on a connection the operator paired', () => {
    renderList([connection('customer-1', 'connected')]);
    expect(screen.getByRole('button', { name: 'Revoke' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Verify' })).toBeInTheDocument();
  });

  describe('control key rotation', () => {
    it('offers Rotate control key on a connected did:webvh connection', () => {
      renderList([webvh()]);
      expect(screen.getByTestId('vta-row-rotate-control-key')).toBeInTheDocument();
      expect(screen.getByTestId('vta-row-control-key-rotated-at')).toHaveTextContent(
        'Never rotated'
      );
    });

    it('offers nothing for a did:key connection, the [vta] record or a user without the right', () => {
      renderList([
        connection('customer-1', 'connected'),
        webvh({ id: 'vta-bootstrap', name: 'Bootstrap VTA' }),
      ]);
      expect(screen.queryByTestId('vta-row-rotate-control-key')).not.toBeInTheDocument();
    });

    it('hides the action from a user who cannot manage keys', () => {
      renderList([webvh()], { canRotateKeys: false });
      expect(screen.queryByTestId('vta-row-rotate-control-key')).not.toBeInTheDocument();
    });

    it('asks first and rotates only once confirmed', async () => {
      const onRotateKey = jest.fn();
      renderList([webvh()], { onRotateKey });

      await userEvent.click(screen.getByTestId('vta-row-rotate-control-key'));
      expect(onRotateKey).not.toHaveBeenCalled();
      expect(screen.getByTestId('vta-row-rotate-confirm-text')).toHaveTextContent(
        /The DID and the grant on the trust agent do not change/
      );

      await userEvent.click(screen.getByTestId('vta-row-rotate-confirm'));
      expect(onRotateKey).toHaveBeenCalledWith(expect.objectContaining({ id: 'customer-1' }));
      expect(screen.queryByTestId('vta-row-rotate-confirm')).not.toBeInTheDocument();
    });

    it('cancelling the confirmation sends nothing', async () => {
      const onRotateKey = jest.fn();
      renderList([webvh()], { onRotateKey });

      await userEvent.click(screen.getByTestId('vta-row-rotate-control-key'));
      await userEvent.click(screen.getByTestId('vta-row-rotate-confirm-cancel'));

      expect(onRotateKey).not.toHaveBeenCalled();
      expect(screen.queryByTestId('vta-row-rotate-confirm')).not.toBeInTheDocument();
    });

    it('shows when the key was last rotated and which key is in use', () => {
      renderList([
        webvh({
          control_key_state: { verification_method: '#key-2', rotated_at: '2026-11-10T10:00:00Z' },
        }),
      ]);
      expect(screen.getByTestId('vta-row-control-key')).toHaveTextContent('key-2');
      expect(screen.getByTestId('vta-row-control-key-rotated-at')).toHaveTextContent(
        /Rotated .*2026/
      );
    });

    it('shows a rotation under way with its last error, offers Cancel and no new rotation', async () => {
      const onCancelRotation = jest.fn();
      renderList(
        [
          webvh({
            control_key_state: {
              last_error: 'the trust agent could not be reached',
              rotation: {
                phase: 'introduced',
                previous_verification_method: '#key-1',
                next_verification_method: '#key-2',
                started_at: '2026-11-10T10:00:00Z',
                give_up_at: '2026-11-10T10:05:30Z',
                attempts: 2,
              },
            },
          }),
        ],
        { onCancelRotation }
      );

      expect(screen.getByTestId('vta-row-rotation-status')).toHaveTextContent(
        /Rotating control key/
      );
      expect(screen.getByTestId('vta-row-rotation-error')).toHaveTextContent(
        'could not be reached'
      );
      expect(screen.queryByTestId('vta-row-rotate-control-key')).not.toBeInTheDocument();

      await userEvent.click(screen.getByTestId('vta-row-rotate-cancel'));
      expect(onCancelRotation).toHaveBeenCalledWith(expect.objectContaining({ id: 'customer-1' }));
    });

    it('offers no Cancel once the gateway has switched to the new key', () => {
      renderList([
        webvh({
          control_key_state: {
            rotation: {
              phase: 'switched',
              previous_verification_method: '#key-1',
              next_verification_method: '#key-2',
              started_at: '2026-11-10T10:00:00Z',
              give_up_at: '2026-11-10T10:05:30Z',
              attempts: 0,
            },
          },
        }),
      ]);
      expect(screen.getByTestId('vta-row-rotation-status')).toBeInTheDocument();
      expect(screen.queryByTestId('vta-row-rotate-cancel')).not.toBeInTheDocument();
    });

    it('shows the last rolled back error after a rotation that did not take', () => {
      renderList([
        webvh({
          control_key_state: {
            last_error:
              'the trust agent did not accept the new key; the previous key is still in use',
          },
        }),
      ]);
      expect(screen.getByTestId('vta-row-rotation-error')).toHaveTextContent(
        'previous key is still in use'
      );
      expect(screen.getByTestId('vta-row-rotate-control-key')).toBeInTheDocument();
    });
  });
});
