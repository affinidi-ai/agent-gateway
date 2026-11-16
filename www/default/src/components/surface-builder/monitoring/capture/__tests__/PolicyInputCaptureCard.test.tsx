import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import type { AgentSurface } from '../../../../../api';
import PolicyInputCaptureCard, { surfaceHasPolicy } from '../PolicyInputCaptureCard';
import { usePolicyInputCaptureStream } from '../usePolicyInputCaptureStream';

jest.mock('../../PolicyInputCaptureControl', () => ({
  __esModule: true,
  default: () => <div data-testid="policy-input-capture" />,
}));

const Harness: React.FC<{ paused?: boolean }> = ({ paused = false }) => {
  const { captures } = usePolicyInputCaptureStream('surface-1', paused);
  return <PolicyInputCaptureCard captures={captures} />;
};

const captured = (detail: Record<string, unknown>) =>
  act(() => {
    window.dispatchEvent(
      new CustomEvent('ws-message', {
        detail: {
          type: 'policy_input_captured',
          config_id: 'surface-1',
          timestamp: '2026-11-13T10:00:00Z',
          plane: 'surface',
          engine: 'surface-1',
          slot: 'target',
          decision: 'allow',
          input: { a2a: { text: 'hello policy' } },
          ...detail,
        },
      })
    );
  });

describe('PolicyInputCaptureCard', () => {
  it('says how to capture policy input while it has none', () => {
    render(<Harness />);
    expect(screen.getByTestId('policy-input-capture-empty')).toBeInTheDocument();
    expect(screen.getByTestId('policy-input-capture')).toBeInTheDocument();
  });

  it('says a surface needs a policy only while it has none', () => {
    const { rerender } = render(<PolicyInputCaptureCard captures={[]} hasPolicy={false} />);
    expect(screen.getByTestId('policy-input-capture-no-policy')).toHaveTextContent(
      'This surface has no policy yet'
    );

    rerender(<PolicyInputCaptureCard captures={[]} hasPolicy />);
    expect(screen.queryByTestId('policy-input-capture-no-policy')).not.toBeInTheDocument();
  });

  it('finds a policy on the Access Point, Target, response or a Transit Point', () => {
    const policy = { policy_definition_id: 'policy-1' };
    const surface = (extra: Record<string, unknown>) =>
      ({
        access_point: {},
        target: { endpoint: 'https://agent.example' },
        ...extra,
      }) as unknown as AgentSurface;

    expect(surfaceHasPolicy(surface({}))).toBe(false);
    expect(surfaceHasPolicy(surface({ transit: { points: [{ name: 'tp' }] } }))).toBe(false);
    expect(surfaceHasPolicy(surface({ access_point: { inbound_policy: policy } }))).toBe(true);
    expect(surfaceHasPolicy(surface({ target: { endpoint: 'x', policy } }))).toBe(true);
    expect(surfaceHasPolicy(surface({ target: { endpoint: 'x', response_policy: policy } }))).toBe(
      true
    );
    expect(surfaceHasPolicy(surface({ transit: { points: [{ name: 'tp', policy }] } }))).toBe(true);
  });

  it('lists each captured evaluation of its surface with its decision and input', () => {
    render(<Harness />);
    captured({ slot: 'inbound', decision: 'deny', reason: 'only message/send is allowed' });
    captured({ config_id: 'surface-2' });

    expect(screen.getAllByTestId('policy-input-capture-row')).toHaveLength(1);
    expect(screen.getByText('inbound')).toBeInTheDocument();
    expect(screen.getByText('Deny')).toBeInTheDocument();
    expect(screen.getByTestId('policy-input-capture-reason')).toHaveTextContent(
      'only message/send is allowed'
    );

    fireEvent.click(screen.getByTestId('policy-input-capture-toggle'));
    expect(screen.getByTestId('policy-input-capture-input')).toHaveTextContent('hello policy');
  });

  it('keeps nothing while paused', () => {
    render(<Harness paused />);
    captured({});
    expect(screen.queryByTestId('policy-input-capture-row')).not.toBeInTheDocument();
  });
});
