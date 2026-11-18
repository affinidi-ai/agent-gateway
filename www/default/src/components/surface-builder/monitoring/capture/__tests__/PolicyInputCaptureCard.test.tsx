import React from 'react';
import { act, fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import type { AgentSurface } from '../../../../../api';
import PolicyInputCaptureCard, { policyLabel, surfaceHasPolicy } from '../PolicyInputCaptureCard';
import {
  type CapturedPolicyInput,
  MAX_POLICY_INPUTS,
  usePolicyInputCaptureStream,
} from '../usePolicyInputCaptureStream';

jest.mock('../../PolicyInputCaptureControl', () => ({
  __esModule: true,
  default: () => <div data-testid="policy-input-capture" />,
}));

let mockCaptureFlag = { enabled: true, loaded: true };
jest.mock('../../../../../utils/featureFlags', () => ({
  usePolicyInputCaptureFlag: () => mockCaptureFlag,
}));

beforeEach(() => {
  mockCaptureFlag = { enabled: true, loaded: true };
});

const Harness: React.FC = () => {
  const { captures, skipped } = usePolicyInputCaptureStream('surface-1');
  return <PolicyInputCaptureCard captures={captures} skipped={skipped} />;
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

  it('offers listening and no off notice while the flag is on', () => {
    render(<PolicyInputCaptureCard captures={[]} hasPolicy={false} />);

    expect(screen.getByTestId('policy-input-capture')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-input-capture-off')).not.toBeInTheDocument();
  });

  it('says capture is turned off, with no Listen control or hints, while the flag is off', () => {
    mockCaptureFlag = { enabled: false, loaded: true };

    render(<PolicyInputCaptureCard captures={[]} hasPolicy={false} />);

    expect(screen.getByTestId('policy-input-capture-off')).toHaveTextContent(
      'Policy input capture is turned off on this gateway. An administrator can turn it on under Settings › Admin › Feature Flags (policy_input_capture).'
    );
    expect(screen.queryByTestId('policy-input-capture')).not.toBeInTheDocument();
    expect(screen.queryByTestId('policy-input-capture-empty')).not.toBeInTheDocument();
    expect(screen.queryByTestId('policy-input-capture-no-policy')).not.toBeInTheDocument();
  });

  it('shows neither the Listen control nor the off notice while the settings load', () => {
    mockCaptureFlag = { enabled: false, loaded: false };

    render(<PolicyInputCaptureCard captures={[]} hasPolicy={false} />);

    expect(screen.queryByTestId('policy-input-capture')).not.toBeInTheDocument();
    expect(screen.queryByTestId('policy-input-capture-off')).not.toBeInTheDocument();
  });

  it('keeps the evaluations already captured when the flag is off', () => {
    mockCaptureFlag = { enabled: false, loaded: true };
    const capture: CapturedPolicyInput = {
      id: 1,
      timestamp: new Date('2026-11-13T10:00:00Z'),
      plane: 'surface',
      engine: 'surface-1',
      slot: 'target',
      policies: [],
      decision: 'allow',
      input: {},
    };

    render(<PolicyInputCaptureCard captures={[capture]} hasPolicy />);

    expect(screen.getByTestId('policy-input-capture-off')).toBeInTheDocument();
    expect(screen.getAllByTestId('policy-input-capture-row')).toHaveLength(1);
  });

  it('says a surface needs a policy only while it has none', () => {
    const { rerender } = render(<PolicyInputCaptureCard captures={[]} hasPolicy={false} />);
    expect(screen.getByTestId('policy-input-capture-no-policy')).toHaveTextContent(
      'This surface has no policy yet'
    );

    rerender(<PolicyInputCaptureCard captures={[]} hasPolicy />);
    expect(screen.queryByTestId('policy-input-capture-no-policy')).not.toBeInTheDocument();
  });

  it('finds a shared Transit Point policy, a Transit Point response policy and a variant policy', () => {
    const policy = { policy_definition_id: 'policy-1' };
    const surface = (extra: Record<string, unknown>) =>
      ({
        access_point: {},
        target: { endpoint: 'https://agent.example' },
        ...extra,
      }) as unknown as AgentSurface;

    expect(
      surfaceHasPolicy(surface({ transit: { points: [], opa_policy_definition_id: 'policy-1' } }))
    ).toBe(true);
    expect(
      surfaceHasPolicy(surface({ transit: { points: [{ name: 'tp', response_policy: policy }] } }))
    ).toBe(true);
    expect(
      surfaceHasPolicy(
        surface({
          variants: [{ alias: 'beta', overrides: { access_point: { inbound_policy: policy } } }],
        })
      )
    ).toBe(true);
    expect(
      surfaceHasPolicy(
        surface({ variants: [{ alias: 'beta', overrides: { target: { policy } } }] })
      )
    ).toBe(true);
    expect(
      surfaceHasPolicy(
        surface({
          variants: [{ alias: 'beta', overrides: { target: { response_policy: policy } } }],
        })
      )
    ).toBe(true);
    expect(surfaceHasPolicy(surface({ variants: [{ alias: 'beta', overrides: {} }] }))).toBe(false);
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
    expect(screen.getByText('inbound', { selector: '.badge' })).toBeInTheDocument();
    expect(screen.getByText('Deny')).toBeInTheDocument();
    expect(screen.getByTestId('policy-input-capture-reason')).toHaveTextContent(
      'only message/send is allowed'
    );

    fireEvent.click(screen.getByTestId('policy-input-capture-toggle'));
    expect(screen.getByTestId('policy-input-capture-input')).toHaveTextContent('hello policy');
  });

  it('names the policy each captured evaluation ran, with its version', () => {
    render(<Harness />);
    captured({ policies: [{ id: 'allow-partners', name: 'Allow partners', version: 3 }] });

    expect(screen.getByTestId('policy-input-capture-policy')).toHaveTextContent(
      'Allow partners v3'
    );
  });

  it('marks the policy of a set that denied', () => {
    render(<Harness />);
    captured({
      plane: 'gateway',
      slot: 'gateway',
      decision: 'deny',
      decided_by: 'block-nights',
      policies: [
        { id: 'allow-partners', name: 'Allow partners' },
        { id: 'block-nights', name: 'Block nights' },
      ],
    });

    const policies = screen.getAllByTestId('policy-input-capture-policy');
    expect(policies).toHaveLength(2);
    expect(policies[0]).toHaveTextContent('Allow partners');
    expect(policies[0]).not.toHaveTextContent('(denied)');
    expect(policies[1]).toHaveTextContent('Block nights (denied)');
  });

  it('falls back to the id, then to "inline policy", without a name', () => {
    expect(policyLabel({ id: 'p-1' })).toBe('p-1');
    expect(policyLabel({})).toBe('inline policy');
  });

  it('shows no policy line for a capture that lists none', () => {
    render(<Harness />);
    captured({});

    expect(screen.queryByTestId('policy-input-capture-policy')).not.toBeInTheDocument();
  });

  it('shows only the evaluations of the chosen policy slot', () => {
    render(<Harness />);
    captured({ slot: 'inbound' });
    captured({ slot: 'target' });
    captured({ slot: 'target' });

    fireEvent.change(screen.getByTestId('policy-input-capture-slot-filter'), {
      target: { value: 'target' },
    });
    expect(screen.getAllByTestId('policy-input-capture-row')).toHaveLength(2);

    fireEvent.change(screen.getByTestId('policy-input-capture-slot-filter'), {
      target: { value: '' },
    });
    expect(screen.getAllByTestId('policy-input-capture-row')).toHaveLength(3);
  });

  it('shows every slot again when the chosen slot has left the list', () => {
    const Clearable: React.FC = () => {
      const { captures, clear } = usePolicyInputCaptureStream('surface-1', false);
      return (
        <>
          <button onClick={clear}>clear</button>
          <PolicyInputCaptureCard captures={captures} />
        </>
      );
    };
    render(<Clearable />);
    captured({ slot: 'target' });
    fireEvent.change(screen.getByTestId('policy-input-capture-slot-filter'), {
      target: { value: 'target' },
    });

    fireEvent.click(screen.getByText('clear'));
    captured({ slot: 'inbound' });

    expect(screen.getAllByTestId('policy-input-capture-row')).toHaveLength(1);
    expect(screen.getByTestId('policy-input-capture-slot-filter')).toHaveValue('');
  });

  it('keeps the last evaluations up to the cap and says how many it keeps', () => {
    render(<Harness />);
    for (let i = 0; i < MAX_POLICY_INPUTS + 3; i++) {
      captured({ reason: `evaluation ${i}` });
    }

    expect(screen.getAllByTestId('policy-input-capture-row')).toHaveLength(MAX_POLICY_INPUTS);
    expect(screen.getByTestId('policy-input-capture-kept')).toHaveTextContent(
      `The last ${MAX_POLICY_INPUTS} policy evaluations are kept`
    );
  });

  it('warns that it is for developing and testing policies before anything is captured', () => {
    render(<Harness />);

    expect(screen.getByTestId('policy-input-capture-warning')).toHaveTextContent(
      'For developing and testing policies only'
    );
  });

  it('says how many evaluations the gateway skipped for this dashboard', () => {
    render(<Harness />);
    expect(screen.queryByTestId('policy-input-capture-skipped')).not.toBeInTheDocument();

    const skipped = (configId: string, count: number) =>
      act(() => {
        window.dispatchEvent(
          new CustomEvent('ws-message', {
            detail: { type: 'policy_input_skipped', config_id: configId, skipped: count },
          })
        );
      });
    skipped('surface-1', 3);
    skipped('surface-2', 7);
    skipped('surface-1', 2);

    expect(screen.getByTestId('policy-input-capture-skipped')).toHaveTextContent(
      '5 policy evaluations were not shown'
    );
  });
});
