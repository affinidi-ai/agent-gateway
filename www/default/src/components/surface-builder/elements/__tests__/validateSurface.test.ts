/**
 * `validateSurfacePayload` unit tests.
 */

import { validateSurfacePayload, hasBlockingIssues } from '../validateSurface';
// Side-effect import: registers every element definition so the
// validator's registry-aware checks (e.g. parent-type classification
// for the chain-leak watchdog) can resolve types.
import '../index';

describe('validateSurfacePayload', () => {
  const ok = () => ({
    name: 'My Surface',
    target: { endpoint: 'https://upstream/y' },
  });

  it('returns no issues for a minimally-valid surface', () => {
    const issues = validateSurfacePayload(ok());
    expect(issues).toEqual([]);
    expect(hasBlockingIssues(issues)).toBe(false);
  });

  it('flags missing surface name as an error', () => {
    const issues = validateSurfacePayload({ ...ok(), name: '' });
    expect(issues.find(i => i.path === 'name')).toMatchObject({ severity: 'error' });
    expect(hasBlockingIssues(issues)).toBe(true);
  });

  it('flags whitespace-only surface name as an error', () => {
    const issues = validateSurfacePayload({ ...ok(), name: '   ' });
    expect(issues.find(i => i.path === 'name')).toMatchObject({ severity: 'error' });
  });

  it('warns on empty target endpoint without blocking', () => {
    const issues = validateSurfacePayload({ ...ok(), target: { endpoint: '' } });
    const ep = issues.find(i => i.path === 'target.endpoint');
    expect(ep).toMatchObject({ severity: 'warning', nodeId: 'target' });
    expect(hasBlockingIssues(issues)).toBe(false);
  });

  it('warns per-transit-point when target_endpoint is empty', () => {
    const payload = {
      ...ok(),
      transit: {
        points: [
          { alias: 'tp-one', target_endpoint: 'https://up/1' },
          { alias: 'tp-two', target_endpoint: '' },
          { alias: 'tp-three', target_endpoint: '   ' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    const tpIssues = issues.filter(i => i.path?.startsWith('transit.points'));
    expect(tpIssues).toHaveLength(2);
    expect(tpIssues[0].path).toBe('transit.points.1.target_endpoint');
    expect(tpIssues[1].path).toBe('transit.points.2.target_endpoint');
    expect(tpIssues.every(i => i.severity === 'warning')).toBe(true);
  });

  it('errors when a transit point alias is missing, malformed, or duplicated', () => {
    const payload = {
      ...ok(),
      transit: {
        points: [
          { alias: '', target_endpoint: 'https://up/1' },
          { alias: 'BAD_ALIAS', target_endpoint: 'https://up/2' },
          { alias: 'good', target_endpoint: 'https://up/3' },
          { alias: 'good', target_endpoint: 'https://up/4' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    const aliasIssues = issues.filter(i => i.path?.endsWith('.alias'));
    expect(aliasIssues).toHaveLength(3);
    expect(aliasIssues.every(i => i.severity === 'error')).toBe(true);
    expect(aliasIssues[0].path).toBe('transit.points.0.alias');
    expect(aliasIssues[1].path).toBe('transit.points.1.alias');
    expect(aliasIssues[2].path).toBe('transit.points.3.alias');
    expect(hasBlockingIssues(issues)).toBe(true);
  });

  it('warns on canvas nodes whose parentId is missing', () => {
    const payload = {
      ...ok(),
      canvas: {
        nodes: [
          { id: 'access-point', parentId: null },
          { id: 'target', parentId: 'access-point' },
          { id: 'orphan', parentId: 'ghost-id' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    const orphan = issues.find(i => i.nodeId === 'orphan');
    expect(orphan).toMatchObject({
      severity: 'warning',
      message: expect.stringContaining('missing parent "ghost-id"'),
    });
  });

  it('warns when target anchor is parented to a non-chain node', () => {
    const payload = {
      ...ok(),
      canvas: {
        nodes: [
          { id: '__surface__' },
          { id: 'access-point', parentId: '__surface__' },
          { id: 'rogue', type: 'npc-endpoint' },
          { id: 'target', parentId: 'rogue' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    const leak = issues.find(i => i.nodeId === 'target');
    expect(leak).toMatchObject({ severity: 'warning' });
    expect(leak!.message).toContain('chain parent leaking');
  });

  it('does NOT warn when target is parented to a chain middleware (legitimate splice output)', () => {
    // Edge-drop middlewares (payment, networking, custom-metadata, …)
    // re-parent the target onto themselves to encode chain order in
    // `parentId` for `deriveEdges` to recover. This is by design and
    // must not trip the structural-leak watchdog.
    const payload = {
      ...ok(),
      canvas: {
        nodes: [
          { id: '__surface__' },
          { id: 'access-point', parentId: '__surface__' },
          { id: 'payment', type: 'payment', parentId: 'access-point' },
          { id: 'target', parentId: 'payment' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    expect(issues.find(i => i.nodeId === 'target')).toBeUndefined();
  });

  it('does NOT warn when target is parented to access-point or surface', () => {
    const payload = {
      ...ok(),
      canvas: {
        nodes: [
          { id: 'access-point', parentId: '__surface__' },
          { id: 'target', parentId: 'access-point' },
        ],
      },
    };
    const issues = validateSurfacePayload(payload);
    expect(issues.find(i => i.nodeId === 'target')).toBeUndefined();
  });

  it('returns a single error for null/undefined payload', () => {
    expect(validateSurfacePayload(null)).toMatchObject([{ severity: 'error' }]);
    expect(validateSurfacePayload(undefined)).toMatchObject([{ severity: 'error' }]);
  });

  describe('workload binding managed-identity requirement', () => {
    const wbTp = (extra: Record<string, unknown> = {}) => ({
      alias: 'tp-one',
      target_endpoint: 'https://up/1',
      workload_binding: { enabled: true, caller_source: 'transit_token' },
      ...extra,
    });

    it('errors when an enabled WB transit point has no managed-identity source', () => {
      const payload = { ...ok(), transit: { points: [wbTp()] } };
      const issues = validateSurfacePayload(payload);
      const wb = issues.find(i => i.path === 'transit.points.0.workload_binding');
      expect(wb).toMatchObject({ severity: 'error' });
      expect(hasBlockingIssues(issues)).toBe(true);
    });

    it('accepts an enabled WB transit point with its own managed_identity', () => {
      const payload = {
        ...ok(),
        transit: { points: [wbTp({ managed_identity: { type: 'from_payload' } })] },
      };
      const issues = validateSurfacePayload(payload);
      expect(issues.find(i => i.path === 'transit.points.0.workload_binding')).toBeUndefined();
    });

    it('accepts an enabled WB transit point when the surface has an identity slot', () => {
      const payload = {
        ...ok(),
        identity_slots: { protected: { type: 'from_payload' } },
        transit: { points: [wbTp()] },
      };
      const issues = validateSurfacePayload(payload);
      expect(issues.find(i => i.path === 'transit.points.0.workload_binding')).toBeUndefined();
    });

    it('accepts an enabled WB transit point when the managed agent DID source is enabled', () => {
      const payload = {
        name: 'My Surface',
        target: { endpoint: 'https://upstream/y', didwebvh_enabled: true },
        transit: { points: [wbTp()] },
      };
      const issues = validateSurfacePayload(payload);
      expect(issues.find(i => i.path === 'transit.points.0.workload_binding')).toBeUndefined();
    });

    it('ignores a disabled WB transit point regardless of identity source', () => {
      const payload = {
        ...ok(),
        transit: {
          points: [
            {
              alias: 'tp-one',
              target_endpoint: 'https://up/1',
              workload_binding: { enabled: false, caller_source: 'transit_token' },
            },
          ],
        },
      };
      const issues = validateSurfacePayload(payload);
      expect(issues.find(i => i.path === 'transit.points.0.workload_binding')).toBeUndefined();
    });
  });
});
