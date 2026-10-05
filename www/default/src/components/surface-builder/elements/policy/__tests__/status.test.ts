import { POLICY_UNCONFIGURED_DASH, policyDefinitionMissing } from '../status';
import {
  POLICY_DEFINITIONS_LOADING_REASON,
  POLICY_DEFINITIONS_LOAD_FAILED_REASON,
  policyDefinitionsBlockingReason,
  policyDefinitionsWarning,
  surfacePolicyBlockingReason,
} from '../status';

describe('policyDefinitionMissing', () => {
  const ids = new Set(['surf-a', 'surf-b']);

  it('returns false for non-policy nodes regardless of config', () => {
    expect(
      policyDefinitionMissing({ type: 'target', config: { policy_definition_id: 'x' } }, ids)
    ).toBe(false);
    expect(policyDefinitionMissing({ type: 'access-point' }, ids)).toBe(false);
  });

  it('returns false for a policy node with no policy selected (empty is handled by incompleteReason)', () => {
    expect(policyDefinitionMissing({ type: 'policy', config: {} }, ids)).toBe(false);
    expect(
      policyDefinitionMissing({ type: 'policy', config: { policy_definition_id: '' } }, ids)
    ).toBe(false);
    expect(policyDefinitionMissing({ type: 'policy', config: null }, ids)).toBe(false);
  });

  it('returns false while the surface-policy id set is still loading (null)', () => {
    expect(
      policyDefinitionMissing({ type: 'policy', config: { policy_definition_id: 'gone' } }, null)
    ).toBe(false);
  });

  it('returns false when the attached policy exists among surface policies', () => {
    expect(
      policyDefinitionMissing({ type: 'policy', config: { policy_definition_id: 'surf-a' } }, ids)
    ).toBe(false);
  });

  it('returns true when the attached policy is not in the surface-policy set (deleted or changed to gateway)', () => {
    expect(
      policyDefinitionMissing(
        { type: 'policy', config: { policy_definition_id: 'gateway-only' } },
        ids
      )
    ).toBe(true);
    expect(
      policyDefinitionMissing(
        { type: 'policy', config: { policy_definition_id: 'surf-a' } },
        new Set()
      )
    ).toBe(true);
  });

  it('exposes a dotted dash pattern distinct from the marching-ants ring', () => {
    expect(POLICY_UNCONFIGURED_DASH).toBe('2 3');
    expect(POLICY_UNCONFIGURED_DASH).not.toBe('6 4');
  });
});

describe('policyDefinitionsBlockingReason', () => {
  it('blocks Save only while the id set is loading', () => {
    expect(policyDefinitionsBlockingReason({ status: 'loading', ids: null })).toBe(
      POLICY_DEFINITIONS_LOADING_REASON
    );
  });

  it('does not block Save once the id set has loaded', () => {
    expect(policyDefinitionsBlockingReason({ status: 'loaded', ids: new Set() })).toBeNull();
  });

  it('does not block Save when the id set failed to load (fail-open, backend validates)', () => {
    expect(
      policyDefinitionsBlockingReason({ status: 'error', ids: null, error: 'HTTP 500' })
    ).toBeNull();
  });
});

describe('policyDefinitionsWarning', () => {
  it('returns null when there is no policy reference, even on load error', () => {
    expect(
      policyDefinitionsWarning({ status: 'error', ids: null, error: 'HTTP 500' }, false)
    ).toBeNull();
  });

  it('returns null while loading or once loaded', () => {
    expect(policyDefinitionsWarning({ status: 'loading', ids: null }, true)).toBeNull();
    expect(policyDefinitionsWarning({ status: 'loaded', ids: new Set() }, true)).toBeNull();
  });

  it('warns (with detail) on load error when a policy is referenced', () => {
    expect(policyDefinitionsWarning({ status: 'error', ids: null, error: 'HTTP 500' }, true)).toBe(
      `${POLICY_DEFINITIONS_LOAD_FAILED_REASON}: HTTP 500`
    );
  });

  it('warns without a trailing colon when the error detail is blank', () => {
    expect(policyDefinitionsWarning({ status: 'error', ids: null, error: '   ' }, true)).toBe(
      POLICY_DEFINITIONS_LOAD_FAILED_REASON
    );
  });
});

describe('surfacePolicyBlockingReason', () => {
  const referencing = [{ type: 'policy', config: { policy_definition_id: 'p1' } }];
  const noReference = [{ type: 'policy', config: {} }];

  it('does not block when no node references a policy definition, even while loading', () => {
    expect(surfacePolicyBlockingReason(noReference, { status: 'loading', ids: null })).toBeNull();
  });

  it('blocks while loading when a policy definition is referenced', () => {
    expect(surfacePolicyBlockingReason(referencing, { status: 'loading', ids: null })).toBe(
      POLICY_DEFINITIONS_LOADING_REASON
    );
  });

  it('does not block once loaded or on load error (backend validates references)', () => {
    expect(
      surfacePolicyBlockingReason(referencing, { status: 'loaded', ids: new Set() })
    ).toBeNull();
    expect(
      surfacePolicyBlockingReason(referencing, { status: 'error', ids: null, error: 'HTTP 500' })
    ).toBeNull();
  });
});
