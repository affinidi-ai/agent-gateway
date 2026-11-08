import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { VtaTierBanner } from './VtaTierBanner';
import type { VtaBootstrapStatus, VtaDeploymentStatus } from './types';

const bootstrap = (overrides: Partial<VtaBootstrapStatus> = {}): VtaBootstrapStatus => ({
  state: 'connected',
  advice: 'nothing to do',
  context_id: 'gateway',
  previously_connected: true,
  owner: 'unclaimed',
  ...overrides,
});

const deployment = (extra: Partial<VtaDeploymentStatus> = {}): VtaDeploymentStatus => ({
  enabled: true,
  tier: 'bundled',
  custody_claim: false,
  self_administered: true,
  auto_provision_contexts: true,
  reserved_origins: [],
  ...extra,
});

describe('VtaTierBanner bundled bootstrap', () => {
  it('shows no bootstrap line when this gateway runs none', () => {
    render(<VtaTierBanner deployment={deployment()} />);
    expect(screen.queryByTestId('vta-bootstrap-status')).not.toBeInTheDocument();
  });

  it('says the trust agent is connected and unowned', () => {
    render(<VtaTierBanner deployment={deployment({ bootstrap: bootstrap() })} />);
    expect(screen.getByTestId('vta-bootstrap-status')).toHaveTextContent('Connected');
    expect(screen.getByTestId('vta-bootstrap-owner')).toHaveTextContent('unclaimed');
    expect(screen.getByTestId('vta-bootstrap-status')).toHaveTextContent(
      'no person owns this trust agent yet'
    );
    expect(screen.queryByTestId('vta-bootstrap-advice')).not.toBeInTheDocument();
  });

  it('never implies custody for a bundled trust agent, whatever its state', () => {
    render(<VtaTierBanner deployment={deployment({ bootstrap: bootstrap() })} />);
    expect(screen.getByText(/not/, { selector: 'strong' })).toBeInTheDocument();
    expect(screen.queryByText(/support a key custody claim/)).not.toBeInTheDocument();
  });

  it('shows the advice and the detail when the trust agent was replaced', () => {
    render(
      <VtaTierBanner
        deployment={deployment({
          bootstrap: bootstrap({
            state: 'vta_replaced',
            advice: 'investigate before re-bootstrapping',
            detail: 'the sidecar now publishes a different DID',
          }),
        })}
      />
    );
    expect(screen.getByTestId('vta-bootstrap-status')).toHaveTextContent('Trust agent replaced');
    expect(screen.getByTestId('vta-bootstrap-advice')).toHaveTextContent(
      'investigate before re-bootstrapping'
    );
    expect(screen.getByTestId('vta-bootstrap-detail')).toHaveTextContent('different DID');
    expect(screen.getByTestId('vta-bootstrap-status')).toHaveTextContent('Signing is refused');
  });

  it('does not say signing is refused for a gateway that never connected', () => {
    render(
      <VtaTierBanner
        deployment={deployment({
          bootstrap: bootstrap({
            state: 'waiting_for_vta',
            advice: 'start the bundled trust agent, then restart the gateway',
            previously_connected: false,
          }),
        })}
      />
    );
    expect(screen.getByTestId('vta-bootstrap-advice')).toHaveTextContent('start the bundled');
    expect(screen.getByTestId('vta-bootstrap-status')).not.toHaveTextContent('Signing is refused');
  });
});
