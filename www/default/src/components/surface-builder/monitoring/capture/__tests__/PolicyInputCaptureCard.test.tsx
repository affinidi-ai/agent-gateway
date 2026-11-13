import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import PolicyInputCaptureCard from '../PolicyInputCaptureCard';
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
