import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import TransitConfigPanel from '../TransitConfigPanel';
import { transitConfigConfigFromPayload, transitConfigDefinition } from '../definition';
import type { ConfigPanelProps } from '../../types';

jest.mock('../../access-point/defaults', () => ({
  fetchRoutingConfig: () => Promise.resolve(null),
}));

const slicesFor = (config: Record<string, unknown>) =>
  transitConfigDefinition.buildPayload!({
    firstNodeOfType: () => ({ id: 'transit-config', type: 'transit-config', config }),
  } as any) ?? [];

describe('Transit Settings', () => {
  it('loads a surface stored with reference transit tokens as embedded, without sign_requests', () => {
    const config = transitConfigConfigFromPayload({
      transit: {
        transit_token_mode: 'reference',
        sign_requests: false,
        rate_limit: { requests: 5, window_secs: 60 },
      },
    });
    expect(config).toEqual({
      transit_token_mode: 'embedded',
      rate_limit_requests: '5',
      rate_limit_window_secs: '60',
    });
  });

  it('saves embedded transit tokens and never sign_requests, whatever the node holds', () => {
    const slices = slicesFor({ transit_token_mode: 'reference', sign_requests: false });
    expect(slices).toContainEqual({ path: 'transit.transit_token_mode', value: 'embedded' });
    expect(slices.map(slice => slice.path)).not.toContain('transit.sign_requests');
    expect(transitConfigDefinition.defaultConfig!()).toEqual({ transit_token_mode: 'embedded' });
  });

  it('never summarises a node as unsigned', () => {
    expect(
      transitConfigDefinition.summary!({ transit_token_mode: 'embedded', sign_requests: false })
    ).toBe('token: embedded');
  });

  it('offers no reference mode and no request signing switch', () => {
    const props = {
      config: { transit_token_mode: 'embedded' },
      updateField: jest.fn(),
    } as unknown as ConfigPanelProps;
    render(<TransitConfigPanel {...props} />);
    expect(screen.getByTestId('transit-config-token-mode')).toHaveTextContent('Embedded');
    expect(screen.queryByText(/Reference/)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/Sign every outbound request/)).not.toBeInTheDocument();
  });
});
