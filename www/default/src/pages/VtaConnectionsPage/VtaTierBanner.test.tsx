import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { VtaTierBanner } from './VtaTierBanner';
import type { VtaDeploymentStatus } from './types';

const deployment = (extra: Partial<VtaDeploymentStatus> = {}): VtaDeploymentStatus => ({
  enabled: true,
  tier: 'self-hosted',
  custody_claim: false,
  auto_provision_contexts: true,
  reserved_origins: [],
  ...extra,
});

describe('VtaTierBanner', () => {
  it('says the gateway signs with its own keys when no trust agent is enabled', () => {
    render(<VtaTierBanner deployment={deployment({ enabled: false, tier: 'local' })} />);
    expect(screen.getByText(/Signing locally/)).toBeInTheDocument();
    expect(screen.getByText(/own keys/)).toBeInTheDocument();
  });

  it('never implies custody when the deployment makes no custody claim', () => {
    render(<VtaTierBanner deployment={deployment()} />);
    expect(screen.getByText(/Deployment: self-hosted/)).toBeInTheDocument();
    expect(screen.getByText(/not/, { selector: 'strong' })).toBeInTheDocument();
    expect(screen.queryByText(/held by a separately-operated agent/)).not.toBeInTheDocument();
  });

  it('states a custody claim only when the backend makes one', () => {
    render(<VtaTierBanner deployment={deployment({ custody_claim: true })} />);
    expect(screen.getByText(/held by a separately-operated agent/)).toBeInTheDocument();
  });

  it('lists reserved control-plane origins', () => {
    render(
      <VtaTierBanner deployment={deployment({ reserved_origins: ['http://127.0.0.1:8100'] })} />
    );
    expect(screen.getByText('http://127.0.0.1:8100')).toBeInTheDocument();
  });

  it('renders nothing before the status is known', () => {
    const { container } = render(<VtaTierBanner deployment={null} />);
    expect(container).toBeEmptyDOMElement();
  });
});
