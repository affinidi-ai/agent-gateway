/**
 * Gateway selection helper tests.
 */

import { isSelectableRemoteGateway, filterSelectableGateways, exposureModeOf } from '../gateways';

describe('isSelectableRemoteGateway', () => {
  it('accepts an active remote gateway', () => {
    expect(isSelectableRemoteGateway({ gateway_type: 'remote', status: 'active' })).toBe(true);
  });

  it('rejects the self gateway even when active', () => {
    expect(isSelectableRemoteGateway({ gateway_type: 'self', status: 'active' })).toBe(false);
  });

  it('rejects a non-active remote gateway', () => {
    expect(isSelectableRemoteGateway({ gateway_type: 'remote', status: 'awaiting-approval' })).toBe(
      false
    );
    expect(isSelectableRemoteGateway({ gateway_type: 'remote', status: 'pending' })).toBe(false);
    expect(isSelectableRemoteGateway({ gateway_type: 'remote', status: 'disabled' })).toBe(false);
    expect(isSelectableRemoteGateway({ gateway_type: 'remote', status: 'failed' })).toBe(false);
  });

  it('rejects when fields are missing', () => {
    expect(isSelectableRemoteGateway({})).toBe(false);
    expect(isSelectableRemoteGateway({ gateway_type: 'remote' })).toBe(false);
    expect(isSelectableRemoteGateway({ status: 'active' })).toBe(false);
  });

  it('is independent of creation_type (bidirectional fabric link)', () => {
    // A `system` peer (auto-created by accepting an inbound connection) is just
    // as routable as a `user` one created via the OOB wizard.
    expect(
      isSelectableRemoteGateway({
        gateway_type: 'remote',
        status: 'active',
        creation_type: 'system',
      } as any)
    ).toBe(true);
    expect(
      isSelectableRemoteGateway({
        gateway_type: 'remote',
        status: 'active',
        creation_type: 'user',
      } as any)
    ).toBe(true);
  });
});

describe('filterSelectableGateways', () => {
  it('keeps only active remote gateways and preserves the element type', () => {
    const gateways = [
      { id: 'a', gateway_type: 'remote', status: 'active' },
      { id: 'b', gateway_type: 'self', status: 'active' },
      { id: 'c', gateway_type: 'remote', status: 'pending' },
      { id: 'd', gateway_type: 'remote', status: 'active' },
    ];
    expect(filterSelectableGateways(gateways).map(g => g.id)).toEqual(['a', 'd']);
  });

  it('returns an empty array for null / undefined / non-array input', () => {
    expect(filterSelectableGateways(null)).toEqual([]);
    expect(filterSelectableGateways(undefined)).toEqual([]);
    expect(filterSelectableGateways({} as any)).toEqual([]);
  });
});

describe('exposureModeOf', () => {
  it('returns the stored mode', () => {
    expect(exposureModeOf({ exposure_mode: 'none', exposed_channels: ['alpha'] })).toBe('none');
    expect(exposureModeOf({ exposure_mode: 'all' })).toBe('all');
    expect(exposureModeOf({ exposure_mode: 'list', exposed_channels: [] })).toBe('list');
  });

  it('derives the earlier meaning for a record without a mode', () => {
    expect(exposureModeOf({ exposed_channels: [] })).toBe('all');
    expect(exposureModeOf({})).toBe('all');
    expect(exposureModeOf({ exposed_channels: ['alpha'] })).toBe('list');
  });

  it('ignores an unknown mode', () => {
    expect(exposureModeOf({ exposure_mode: 'some', exposed_channels: ['alpha'] })).toBe('list');
  });
});
