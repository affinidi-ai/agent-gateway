import { registry } from '../index';
import { buildSurfaceContext } from '../surfaceContext';
import { INBOUND_JWT_CLAIM_NEEDS_JWT_CALLER } from '../identity/definition';
import type { CanvasNode } from '../types';

const inboundNode = { id: 'identity-inbound', slotId: 'request:identity-inbound' };
const protectedNode = { id: 'identity-protected', slotId: 'response:identity-protected' };

const identity = (placement: { id: string; slotId: string }) =>
  ({
    ...placement,
    type: 'identity',
    label: '',
    configured: true,
    config: { type: 'from_jwt_claim', claim: 'oid' },
  }) as CanvasNode;

const callerAuth = (...methods: string[]) =>
  ({
    id: 'caller-auth',
    type: 'caller-auth',
    label: '',
    configured: true,
    config: { methods: methods.map(method_type => ({ method_type })) },
  }) as CanvasNode;

const accessPoint = {
  id: 'access-point',
  type: 'access-point',
  label: '',
  configured: true,
  config: { route: '/api' },
} as CanvasNode;

const saveErrors = (nodes: CanvasNode[], node: CanvasNode) =>
  registry
    .getDependencyWarnings('identity', node.config, buildSurfaceContext('a2a', nodes), node)
    .filter(w => w.severity === 'error')
    .map(w => w.message);

describe('identity From JWT Claims — Save rules', () => {
  const inbound = identity(inboundNode);

  it('passes on the inbound Identity beside a Caller Context method that is not JWT Bearer', () => {
    expect(
      saveErrors([accessPoint, callerAuth('jwt_bearer', 'api_key'), inbound], inbound)
    ).toEqual([]);
  });

  it('is an error on the inbound Identity when no Caller Context method is JWT Bearer', () => {
    expect(saveErrors([accessPoint, callerAuth('api_key'), inbound], inbound)).toEqual([
      INBOUND_JWT_CLAIM_NEEDS_JWT_CALLER,
    ]);
    expect(saveErrors([accessPoint, inbound], inbound)).toEqual([
      INBOUND_JWT_CLAIM_NEEDS_JWT_CALLER,
    ]);
  });

  it('still needs every Caller Context method to be JWT Bearer on the protected Identity', () => {
    const node = identity(protectedNode);
    expect(saveErrors([accessPoint, callerAuth('jwt_bearer', 'api_key'), node], node)).toHaveLength(
      1
    );
    expect(saveErrors([accessPoint, callerAuth('jwt_bearer'), node], node)).toEqual([]);
  });
});
