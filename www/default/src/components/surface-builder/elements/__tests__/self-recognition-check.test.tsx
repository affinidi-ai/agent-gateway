import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import TransitPointPanel from '../transit-point/TransitPointPanel';
import {
  SELF_RECOGNITION_NEEDS_IDENTITY,
  SELF_RECOGNITION_NEEDS_RECORDER,
  selfRecognitionCheckBlocker,
} from '../transit-point/SelfRecognitionCheckSection';
import { registry } from '../index';
import { apiClient } from '../../../../api';
import type { CanvasNode } from '../../SurfaceCanvas';
import type { ConfigPanelProps, SurfaceContext } from '../types';

jest.mock('../../../../api', () => ({ apiClient: { get: jest.fn(), fetch: jest.fn() } }));

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
});

const TP_ID = 'transit-point-a2a-1';

const recorder = (includeOwnedAgent: boolean): CanvasNode =>
  ({
    id: 'trust-recorder',
    type: 'trust-recorder',
    label: 'Trust Recorder',
    configured: true,
    config: {
      entries: [
        {
          trust_registry_id: 'alpha',
          issuer_did: 'did:web:issuer.example',
          authority_did: 'did:web:authority.example',
          include_owned_agent: includeOwnedAgent,
        },
      ],
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

  it('needs a Trust Recorder entry that records the owned agent', () => {
    expect(selfRecognitionCheckBlocker(TP_ID, {}, [staticIdentity])).toBe(
      SELF_RECOGNITION_NEEDS_RECORDER
    );
    expect(selfRecognitionCheckBlocker(TP_ID, {}, [recorder(false), staticIdentity])).toBe(
      SELF_RECOGNITION_NEEDS_RECORDER
    );
  });

  it('needs a managed agent identity on the Transit Point', () => {
    expect(selfRecognitionCheckBlocker(TP_ID, {}, [recorder(true)])).toBe(
      SELF_RECOGNITION_NEEDS_IDENTITY
    );
    expect(
      selfRecognitionCheckBlocker(TP_ID, {}, [recorder(true), identity({ type: 'from_jwt_claim' })])
    ).toBe(SELF_RECOGNITION_NEEDS_IDENTITY);
    expect(
      selfRecognitionCheckBlocker(TP_ID, {}, [
        recorder(true),
        { ...staticIdentity, parentId: 'other' },
      ])
    ).toBe(SELF_RECOGNITION_NEEDS_IDENTITY);
    expect(
      selfRecognitionCheckBlocker(TP_ID, injectsVp, [
        recorder(true),
        identity({ type: 'from_jwt_claim' }),
      ])
    ).toBe(SELF_RECOGNITION_NEEDS_IDENTITY);
  });

  it('is clear with its own Identity or the surface’s through a stored VP injection', () => {
    expect(selfRecognitionCheckBlocker(TP_ID, {}, [recorder(true), staticIdentity])).toBeNull();
    expect(selfRecognitionCheckBlocker(TP_ID, injectsVp, [recorder(true)])).toBeNull();
  });
});

describe('Transit Point self recognition check switch', () => {
  it('is disabled with a note while the surface has no Trust Recorder', () => {
    render(<TransitPointPanel {...panelProps({}, [staticIdentity])} />);
    const toggle = screen.getByTestId('transit-point-self-recognition-check-switch');
    expect(toggle).toBeDisabled();
    const note = screen.getByTestId('transit-point-self-recognition-check-note');
    expect(note).toHaveTextContent(SELF_RECOGNITION_NEEDS_RECORDER);
    expect(toggle).toHaveAttribute('aria-describedby', note.id);
  });

  it('writes the switch when it can run', () => {
    const props = panelProps({}, [recorder(true), staticIdentity]);
    render(<TransitPointPanel {...props} />);
    const toggle = screen.getByTestId('transit-point-self-recognition-check-switch');
    expect(toggle).not.toBeChecked();
    expect(
      screen.queryByTestId('transit-point-self-recognition-check-note')
    ).not.toBeInTheDocument();
    fireEvent.click(toggle);
    expect(props.updateField).toHaveBeenCalledWith('self_recognition_check', true);
  });

  it('can still be turned off when it can no longer run', () => {
    const props = panelProps({ self_recognition_check: true }, [recorder(true)]);
    render(<TransitPointPanel {...props} />);
    const toggle = screen.getByTestId('transit-point-self-recognition-check-switch');
    expect(toggle).toBeChecked();
    expect(toggle).not.toBeDisabled();
    expect(screen.getByTestId('transit-point-self-recognition-check-note')).toHaveTextContent(
      SELF_RECOGNITION_NEEDS_IDENTITY
    );
    fireEvent.click(toggle);
    expect(props.updateField).toHaveBeenCalledWith('self_recognition_check', false);
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

  it('keeps a stored switch on across a dashboard save', () => {
    expect(savedPoint({ self_recognition_check: true }).self_recognition_check).toBe(true);
  });

  it('sends nothing for a Transit Point that never had the switch', () => {
    expect(savedPoint({})).not.toHaveProperty('self_recognition_check');
  });

  it('sends an explicit false when the switch is turned off', () => {
    const point = savedPoint({ self_recognition_check: true }, nodes => {
      const node = transitPointNode(nodes);
      node.config = { ...node.config, self_recognition_check: false };
    });
    expect(point.self_recognition_check).toBe(false);
  });

  it('keeps a stored VP injection, so a save does not take the agent identity away', () => {
    const point = savedPoint({
      self_recognition_check: true,
      identity_injection: { inject_vp: true },
    });
    expect(point.identity_injection).toEqual({ inject_vp: true });
    expect(savedPoint({ identity_injection: { inject_vp: false } })).not.toHaveProperty(
      'identity_injection'
    );
  });
});
