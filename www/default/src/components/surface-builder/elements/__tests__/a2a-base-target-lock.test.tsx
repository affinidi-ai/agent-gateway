import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { MemoryRouter } from 'react-router-dom';
import AccessPointPanel from '../access-point/AccessPointPanel';
import ManagedAgentPanel from '../managed-agent/ManagedAgentPanel';
import { apiClient } from '../../../../api';
import type { BaseSurfaceView } from '../types';

jest.mock('../_shared/RouteListenerSection', () => () => null);
jest.mock('../../../../api', () => ({ apiClient: { get: jest.fn(), fetch: jest.fn() } }));

beforeEach(() => {
  (apiClient.get as jest.Mock).mockResolvedValue({ data: [] });
  (apiClient.fetch as jest.Mock).mockResolvedValue({ ok: true, json: () => Promise.resolve([]) });
});

const PROXY = 'a2a-proxy://worker';
const URL_TARGET = 'https://agent.example';

function nodes(apConfig: Record<string, unknown>, targetConfig: Record<string, unknown>) {
  return [
    { id: 'access-point', type: 'access-point', label: 'Access Point', config: apConfig },
    { id: 'target', type: 'target', label: 'Managed Agent', config: targetConfig },
  ];
}

const proxyTargetConfig = {
  endpoint_type: 'a2a-proxy',
  a2a_proxy_id: 'worker',
  endpoint: PROXY,
};

function renderAccessPoint(
  apConfig: Record<string, unknown>,
  targetEndpoint: string,
  base: BaseSurfaceView,
  updateFields: jest.Mock = jest.fn()
) {
  const allNodes = nodes(apConfig, { endpoint: targetEndpoint });
  render(
    <AccessPointPanel
      {...({
        node: allNodes[0],
        config: apConfig,
        updateField: jest.fn(),
        updateFields,
        protocol: 'a2a',
        allNodes,
        base,
      } as any)}
    />
  );
}

function renderManagedAgent(apConfig: Record<string, unknown>, base: BaseSurfaceView) {
  const allNodes = nodes(apConfig, proxyTargetConfig);
  render(
    <MemoryRouter>
      <ManagedAgentPanel
        {...({
          node: allNodes[1],
          config: proxyTargetConfig,
          updateField: jest.fn(),
          updateFields: jest.fn(),
          protocol: 'a2a',
          allNodes,
          base,
        } as any)}
      />
    </MemoryRouter>
  );
}

const version = (v: string) => screen.getByTestId(`access-point-a2a-version-${v}`);
const validation = () => screen.getByTestId('access-point-a2a-validation') as HTMLSelectElement;

describe('A2A settings of a variant whose Target differs from the base Target', () => {
  describe('URL base Target with an A2A proxy variant in view', () => {
    const base: BaseSurfaceView = {
      targetEndpoint: URL_TARGET,
      accessPointConfig: { a2a_accepted_versions: ['0.3'], a2a_validation: 'full' },
    };
    const apConfig = { a2a_accepted_versions: ['0.3'], a2a_validation: 'full' };

    it('keeps the versions editable and shows the surface selection', () => {
      const updateFields = jest.fn();
      renderAccessPoint(apConfig, PROXY, base, updateFields);

      expect(version('0.3')).toBeChecked();
      expect(version('1.0')).not.toBeChecked();
      expect(version('0.3')).toBeEnabled();
      expect(version('1.0')).toBeEnabled();
      expect(screen.queryByTestId('access-point-a2a-proxy-locked')).not.toBeInTheDocument();

      fireEvent.click(version('1.0'));
      expect(updateFields).toHaveBeenCalledWith({ a2a_accepted_versions: ['0.3', '1.0'] });
    });

    it('locks the validation to the JSON-RPC envelope for this Target', () => {
      renderAccessPoint(apConfig, PROXY, base);

      expect(validation().value).toBe('envelope');
      expect(validation()).toBeDisabled();
      expect(screen.getByTestId('access-point-a2a-proxy-envelope-only')).toHaveTextContent(
        "This Target is an A2A proxy, so it checks only the JSON-RPC envelope. The versions below are the surface's and apply to it too."
      );
    });

    it('asks for a version when none is selected', () => {
      renderAccessPoint({ a2a_accepted_versions: [] }, PROXY, base);

      expect(screen.getByTestId('access-point-a2a-versions-error')).toBeInTheDocument();
    });

    it('shows the Managed Agent the versions the gateway serves, not fixed ones', async () => {
      renderManagedAgent(apConfig, base);
      await waitFor(() => expect(apiClient.get).toHaveBeenCalledWith('/a2a-proxies'));

      const hint = screen.getByTestId('managed-agent-a2a-proxy-protocol-hint');
      expect(screen.getByTestId('managed-agent-a2a-proxy-versions')).toHaveTextContent(
        'Accepts A2A 0.3 only'
      );
      expect(hint).toHaveTextContent('Callers may send A2A-Version: 0.3, or no header');
      expect(hint).not.toHaveTextContent('Callers must send A2A-Version: 1.0');
      expect(hint).not.toHaveTextContent('These versions are fixed.');
      expect(hint).toHaveTextContent("These are the surface's versions, set in the Access Point.");
      expect(screen.queryByTestId('managed-agent-a2a-proxy-0-3-reason')).not.toBeInTheDocument();
    });
  });

  describe('A2A proxy base Target with a URL variant in view', () => {
    const base: BaseSurfaceView = {
      targetEndpoint: PROXY,
      accessPointConfig: { a2a_locked_versions: ['0.3', '1.0'], a2a_validation: 'full' },
    };
    const apConfig = { a2a_accepted_versions: ['1.0'], a2a_validation: 'full' };

    it("locks the versions to the base Target's fixed ones", () => {
      renderAccessPoint(apConfig, URL_TARGET, base);

      expect(version('0.3')).toBeChecked();
      expect(version('1.0')).toBeChecked();
      expect(version('0.3')).toBeDisabled();
      expect(version('1.0')).toBeDisabled();
      expect(screen.getByTestId('access-point-a2a-proxy-locked')).toHaveTextContent(
        'This surface was created as an A2A 0.3 proxy, so it keeps accepting 0.3 for its existing callers. New surfaces with an A2A proxy accept A2A 1.0 only. The base Target is an A2A proxy, so these versions are fixed. Message validation applies to this Target, a URL.'
      );
      expect(screen.queryByTestId('access-point-a2a-proxy-envelope-only')).not.toBeInTheDocument();
    });

    it('keeps the validation level editable', () => {
      const updateFields = jest.fn();
      renderAccessPoint(apConfig, URL_TARGET, base, updateFields);

      expect(validation().value).toBe('full');
      expect(validation()).toBeEnabled();
      fireEvent.change(validation(), { target: { value: 'off' } });
      expect(updateFields).toHaveBeenLastCalledWith({ a2a_validation: 'off' });
    });

    it('shows A2A 1.0 only for a base Target just moved to an A2A proxy', () => {
      renderAccessPoint(apConfig, URL_TARGET, { targetEndpoint: PROXY, accessPointConfig: {} });

      expect(version('0.3')).not.toBeChecked();
      expect(version('1.0')).toBeChecked();
      expect(screen.getByTestId('access-point-a2a-proxy-locked')).toHaveTextContent(
        'A surface with an A2A proxy accepts A2A 1.0 only.'
      );
    });

    it("shows the Managed Agent of an A2A proxy variant the base Target's fixed versions", async () => {
      renderManagedAgent({ a2a_accepted_versions: ['1.0'] }, base);
      await waitFor(() => expect(apiClient.get).toHaveBeenCalledWith('/a2a-proxies'));

      const hint = screen.getByTestId('managed-agent-a2a-proxy-protocol-hint');
      expect(screen.getByTestId('managed-agent-a2a-proxy-versions')).toHaveTextContent(
        'Accepts A2A 0.3 and 1.0'
      );
      expect(screen.getByTestId('managed-agent-a2a-proxy-0-3-reason')).toBeInTheDocument();
      expect(hint).toHaveTextContent('These versions are fixed.');
    });
  });
});
