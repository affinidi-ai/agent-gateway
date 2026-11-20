import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import TransitPointPanel from '../transit-point/TransitPointPanel';
import {
  SELF_RECOGNITION_REQUIRES_IDENTITY,
  SELF_RECOGNITION_REQUIRES_RECORDER,
  SELF_RECOGNITION_REQUIRES_REGISTRY,
  ownedAgentRegistryIds,
  selfRecognitionCheckBlocker,
} from '../transit-point/SelfRecognitionCheckSection';
import { registry } from '../index';
import { apiClient } from '../../../../api';
import type { CanvasNode } from '../../SurfaceCanvas';
import type { ConfigPanelProps, SurfaceContext } from '../types';

jest.mock('../../../../api', () => ({
  apiClient: { get: jest.fn(), fetch: jest.fn(), listTrustRegistries: jest.fn() },
}));

beforeEach(() => {
  (apiClient.fetch as jest.Mock).mockImplementation((url: string) =>
    Promise.resolve({
      ok: true,
      json: () =>
        Promise.resolve(
          url === '/api/v1/config/surface-routing'
            ? {
                available_listen_addresses: [],
                available_outbound_listen_addresses: [],
                channel_path_prefix: [],
              }
            : []
        ),
    })
  );
  (apiClient.get as jest.Mock).mockResolvedValue({ data: [] });
  (apiClient.listTrustRegistries as jest.Mock).mockResolvedValue([
    { id: 'alpha', name: 'Alpha Registry' },
    { id: 'beta', name: 'Beta Registry' },
  ]);
});

const TP_ID = 'transit-point-a2a-1';

const recorder = (entries: Array<[string, boolean]>): CanvasNode =>
  ({
    id: 'trust-recorder',
    type: 'trust-recorder',
    label: 'Trust Recorder',
    configured: true,
    config: {
      entries: entries.map(([trustRegistryId, includeOwnedAgent]) => ({
        trust_registry_id: trustRegistryId,
        issuer_did: 'did:web:issuer.example',
        authority_did: 'did:web:authority.example',
        include_owned_agent: includeOwnedAgent,
      })),
    },
  }) as CanvasNode;

const identity = (config: Record<string, unknown>, parentId = TP_ID): CanvasNode =>
  ({
    id: `identity-${parentId}`,
    type: 'identity',
    label: 'Identity',
    configured: true,
    parentId,
    config,
  }) as CanvasNode;

const staticIdentity = identity({ type: 'static', static_did: 'did:web:tp.example' });
const twoRegistries = recorder([
  ['alpha', true],
  ['beta', true],
]);

function panelProps(
  config: Record<string, unknown>,
  allNodes: CanvasNode[]
): ConfigPanelProps & { updateField: jest.Mock } {
  return {
    node: {
      id: TP_ID,
      type: 'transit-point-a2a',
      label: '',
      configured: true,
      config,
    } as CanvasNode,
    config: { id: 'tp-1', ...config },
    updateField: jest.fn(),
    updateFields: jest.fn(),
    replaceCommit: jest.fn(),
    protocol: 'a2a',
    allNodes,
  } as unknown as ConfigPanelProps & { updateField: jest.Mock };
}

describe('selfRecognitionCheckBlocker', () => {
  const injectsVp = { identity_injection: { inject_vp: true } };

  it('requires a Trust Recorder entry that records the owned agent', () => {
    expect(selfRecognitionCheckBlocker(TP_ID, {}, [staticIdentity])).toBe(
      SELF_RECOGNITION_REQUIRES_RECORDER
    );
    expect(
      selfRecognitionCheckBlocker(TP_ID, {}, [recorder([['alpha', false]]), staticIdentity])
    ).toBe(SELF_RECOGNITION_REQUIRES_RECORDER);
  });

  it('requires a managed agent identity on the Transit Point', () => {
    expect(selfRecognitionCheckBlocker(TP_ID, {}, [twoRegistries])).toBe(
      SELF_RECOGNITION_REQUIRES_IDENTITY
    );
    expect(
      selfRecognitionCheckBlocker(TP_ID, {}, [twoRegistries, identity({ type: 'from_jwt_claim' })])
    ).toBe(SELF_RECOGNITION_REQUIRES_IDENTITY);
    expect(
      selfRecognitionCheckBlocker(TP_ID, {}, [
        twoRegistries,
        { ...staticIdentity, parentId: 'other' },
      ])
    ).toBe(SELF_RECOGNITION_REQUIRES_IDENTITY);
    expect(
      selfRecognitionCheckBlocker(TP_ID, injectsVp, [
        twoRegistries,
        identity({ type: 'from_jwt_claim' }),
      ])
    ).toBe(SELF_RECOGNITION_REQUIRES_IDENTITY);
  });

  it('is clear with its own Identity or the surface’s through a stored VP injection', () => {
    expect(selfRecognitionCheckBlocker(TP_ID, {}, [twoRegistries, staticIdentity])).toBeNull();
    expect(selfRecognitionCheckBlocker(TP_ID, injectsVp, [twoRegistries])).toBeNull();
  });

  it('offers only the registries the Trust Recorder records the owned agent in', () => {
    expect(
      ownedAgentRegistryIds([
        recorder([
          ['alpha', true],
          ['beta', false],
          ['gamma', true],
        ]),
      ])
    ).toEqual(['alpha', 'gamma']);
  });
});

describe('Transit Point self recognition check switch', () => {
  it('is labelled Self Recognition Check with its explanation under it', () => {
    render(<TransitPointPanel {...panelProps({}, [twoRegistries, staticIdentity])} />);
    expect(screen.getByLabelText('Self Recognition Check')).toBe(
      screen.getByTestId('transit-point-self-recognition-check-switch')
    );
    expect(screen.getByTestId('transit-point-self-recognition-check-help')).toHaveTextContent(
      "the trust registries you pick from this surface's Trust Recorder must still recognise the agent calling out"
    );
  });

  it('is disabled with a Requires note while the surface has no Trust Recorder', () => {
    render(<TransitPointPanel {...panelProps({}, [staticIdentity])} />);
    const toggle = screen.getByTestId('transit-point-self-recognition-check-switch');
    expect(toggle).toBeDisabled();
    const note = screen.getByTestId('transit-point-self-recognition-check-note');
    expect(note).toHaveTextContent(SELF_RECOGNITION_REQUIRES_RECORDER);
    expect(toggle.getAttribute('aria-describedby')).toContain(note.id);
  });

  it('turns on with no trust registry picked', () => {
    const props = panelProps({}, [twoRegistries, staticIdentity]);
    render(<TransitPointPanel {...props} />);
    fireEvent.click(screen.getByTestId('transit-point-self-recognition-check-switch'));
    expect(props.updateField).toHaveBeenCalledWith('self_recognition_check', {
      trust_registry_ids: [],
    });
  });

  it('lists the owned-agent registries by name, none picked, and asks for one', async () => {
    render(
      <TransitPointPanel
        {...panelProps({ self_recognition_check: { trust_registry_ids: [] } }, [
          twoRegistries,
          staticIdentity,
        ])}
      />
    );
    const alpha = screen.getByTestId('transit-point-self-recognition-check-registry-alpha');
    expect(alpha).not.toBeChecked();
    expect(
      screen.getByTestId('transit-point-self-recognition-check-registry-beta')
    ).not.toBeChecked();
    expect(await screen.findByLabelText('Alpha Registry')).toBe(alpha);
    expect(
      screen.getByTestId('transit-point-self-recognition-check-registry-required')
    ).toHaveTextContent(SELF_RECOGNITION_REQUIRES_REGISTRY);
  });

  it('writes the picked registries', () => {
    const props = panelProps({ self_recognition_check: { trust_registry_ids: ['alpha'] } }, [
      twoRegistries,
      staticIdentity,
    ]);
    render(<TransitPointPanel {...props} />);
    expect(
      screen.queryByTestId('transit-point-self-recognition-check-registry-required')
    ).not.toBeInTheDocument();
    fireEvent.click(screen.getByTestId('transit-point-self-recognition-check-registry-beta'));
    expect(props.updateField).toHaveBeenCalledWith('self_recognition_check', {
      trust_registry_ids: ['alpha', 'beta'],
    });
  });

  it('can still be turned off when it can no longer run', () => {
    const props = panelProps({ self_recognition_check: { trust_registry_ids: ['alpha'] } }, [
      twoRegistries,
    ]);
    render(<TransitPointPanel {...props} />);
    const toggle = screen.getByTestId('transit-point-self-recognition-check-switch');
    expect(toggle).toBeChecked();
    expect(toggle).not.toBeDisabled();
    expect(screen.getByTestId('transit-point-self-recognition-check-note')).toHaveTextContent(
      SELF_RECOGNITION_REQUIRES_IDENTITY
    );
    fireEvent.click(toggle);
    expect(props.updateField).toHaveBeenCalledWith('self_recognition_check', null);
  });
});

describe('transit.points[*].self_recognition_check', () => {
  function makeCtx(nodes: any[]): SurfaceContext {
    return {
      protocol: 'a2a',
      surfaceMeta: { name: 'self-recognition', tags: [], status: 'active' },
      allNodes: nodes,
      nodesOfType: type => nodes.filter(n => n.type === type),
      firstNodeOfType: type => nodes.find(n => n.type === type),
    };
  }

  function savedPoint(point: Record<string, unknown>, edit?: (nodes: any[]) => void) {
    const nodes = registry.nodesFromPayload({
      access_point: { route: '/a2a', protocol: 'a2a' },
      target: { endpoint: 'https://upstream.example.com' },
      transit: {
        points: [
          { alias: 'partner', protocol: 'a2a', target_endpoint: 'https://p.example', ...point },
        ],
      },
    });
    edit?.(nodes);
    return registry.buildPayload(makeCtx(nodes)).transit.points[0];
  }

  const transitPointNode = (nodes: any[]) =>
    nodes.find(node => String(node.type).startsWith('transit-point-'));

  it('keeps the stored registries across a dashboard save', () => {
    expect(
      savedPoint({ self_recognition_check: { trust_registry_ids: ['alpha'] } })
        .self_recognition_check
    ).toEqual({ trust_registry_ids: ['alpha'] });
  });

  it('sends nothing for a Transit Point that never had the switch', () => {
    expect(savedPoint({})).not.toHaveProperty('self_recognition_check');
  });

  it('sends an explicit null when the switch is turned off', () => {
    const point = savedPoint(
      { self_recognition_check: { trust_registry_ids: ['alpha'] } },
      nodes => {
        const node = transitPointNode(nodes);
        node.config = { ...node.config, self_recognition_check: null };
      }
    );
    expect(point.self_recognition_check).toBeNull();
  });

  it('blocks Save while no trust registry is picked', () => {
    const definition = registry.get('transit-point-a2a');
    const errors =
      definition?.validate?.({
        target_endpoint: 'https://p.example',
        require_transit_token: true,
        self_recognition_check: { trust_registry_ids: [] },
      }) ?? [];
    expect(errors).toContainEqual({
      field: 'self_recognition_check',
      message: SELF_RECOGNITION_REQUIRES_REGISTRY,
    });
    expect(
      definition?.validate?.({
        target_endpoint: 'https://p.example',
        require_transit_token: true,
        self_recognition_check: { trust_registry_ids: ['alpha'] },
      }) ?? []
    ).not.toContainEqual(expect.objectContaining({ field: 'self_recognition_check' }));
  });

  it('keeps a stored VP injection, so a save does not take the agent identity away', () => {
    const point = savedPoint({
      self_recognition_check: { trust_registry_ids: ['alpha'] },
      identity_injection: { inject_vp: true },
    });
    expect(point.identity_injection).toEqual({ inject_vp: true });
    expect(savedPoint({ identity_injection: { inject_vp: false } })).not.toHaveProperty(
      'identity_injection'
    );
  });
});
