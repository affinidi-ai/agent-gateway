import type { Identity } from '../../../types';
import { groupIdentityVersions } from '../identityVersions';
import managedFixture from '../../../__fixtures__/backend/identity-row-managed.json';
import managedRotatedFixture from '../../../__fixtures__/backend/identity-row-managed-rotated.json';
import externalCallerFixture from '../../../__fixtures__/backend/identity-row-external-caller.json';

const managed = managedFixture as unknown as Identity;
const rotated = managedRotatedFixture as unknown as Identity;
const caller = externalCallerFixture as unknown as Identity;

const version = (
  base: Identity,
  did: string,
  createdAt: string,
  lastUsedAt: string,
  extra: Partial<Identity> = {}
): Identity => ({
  ...base,
  did,
  identity_hash: `hash-${did}`,
  created_at: createdAt,
  last_used_at: lastUsedAt,
  ...extra,
});

const model = (value: string) => ({ 'agentIdentity.llmInfo.model': value });

describe('groupIdentityVersions', () => {
  it('groups a surface’s payload DIDs under the most recently used one', () => {
    const first = version(managed, 'did:a', '2026-01-01T00:00:00Z', '2026-01-05T00:00:00Z', {
      agent_identity: model('gpt-4o'),
      usage_count: 3,
    });
    const second = version(managed, 'did:b', '2026-01-02T00:00:00Z', '2026-01-03T00:00:00Z', {
      agent_identity: model('gpt-4.1'),
      usage_count: 2,
    });

    const [entry] = groupIdentityVersions([first, second]);

    expect(entry.primary.did).toBe('did:a');
    expect(entry.primary.usage_count).toBe(5);
    expect(entry.primary.last_used_at).toBe('2026-01-05T00:00:00Z');
    expect(entry.dids).toEqual(['did:a', 'did:b']);
    expect(entry.versions.map(v => [v.number, v.did, v.current])).toEqual([
      [2, 'did:b', false],
      [1, 'did:a', true],
    ]);
    expect(entry.versions[0].changes).toEqual([
      { field: 'agentIdentity.llmInfo.model', from: 'gpt-4o', to: 'gpt-4.1' },
    ]);
    expect(entry.versions[1].changes).toEqual([
      { field: 'agentIdentity.llmInfo.model', to: 'gpt-4o' },
    ]);
  });

  it('keeps parallel from_jwt_claim DIDs, external callers and other surfaces apart', () => {
    const jwt = (did: string, value: string) =>
      version(managed, did, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', {
        agent_identity: { credential_type: 'jwt_claim', claim: 'oid', value },
      });
    const otherSurface = version(
      managed,
      'did:other',
      '2026-01-01T00:00:00Z',
      '2026-01-01T00:00:00Z',
      {
        surface_id: 'beta',
      }
    );

    const entries = groupIdentityVersions([
      jwt('did:j1', 'a'),
      jwt('did:j2', 'b'),
      caller,
      managed,
      otherSurface,
    ]);

    expect(entries.map(entry => entry.primary.did)).toEqual([
      'did:j1',
      'did:j2',
      caller.did,
      managed.did,
      'did:other',
    ]);
    expect(entries.every(entry => entry.versions.length === 0)).toBe(true);
  });

  it('groups the Managed Agent’s DIDs of every source and slot on one surface', () => {
    const mtls = version(rotated, 'did:mtls', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', {
      rotations: [],
    });
    const transitPoint = version(
      managed,
      'did:tp',
      '2026-01-02T00:00:00Z',
      '2026-01-09T00:00:00Z',
      {
        slot: { kind: 'transit_point', alias: 'tp-1' },
      }
    );

    const [entry, ...rest] = groupIdentityVersions([managed, mtls, transitPoint]);

    expect(rest).toEqual([]);
    expect(entry.primary.did).toBe('did:tp');
    expect(entry.dids).toEqual([managed.did, 'did:mtls', 'did:tp']);
  });

  it('groups a record without a slot by its surface straight away', () => {
    const legacy = version(managed, 'did:legacy', '2025-12-01T00:00:00Z', '2025-12-02T00:00:00Z', {
      slot: undefined,
    });
    const transitPoint = version(
      managed,
      'did:tp',
      '2026-01-02T00:00:00Z',
      '2026-01-02T00:00:00Z',
      {
        slot: { kind: 'transit_point', alias: 'tp-1' },
      }
    );

    const entries = groupIdentityVersions([legacy, managed, transitPoint]);

    expect(entries.map(entry => entry.dids)).toEqual([['did:legacy', managed.did, 'did:tp']]);
  });

  it('flags an entry when one of its DIDs had older rotations dropped', () => {
    const dropped = version(rotated, 'did:mtls', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', {
      rotations_dropped: true,
    });

    expect(groupIdentityVersions([managed, dropped])[0].rotationsDropped).toBe(true);
    expect(groupIdentityVersions([managed])[0].rotationsDropped).toBe(false);
  });

  it('lists a rotation inside its DID with the fields it changed', () => {
    const [entry] = groupIdentityVersions([rotated]);

    expect(entry.versions.map(v => [v.number, v.kind, v.current])).toEqual([
      [2, 'rotation', true],
      [1, 'did', false],
    ]);
    expect(entry.versions[0].at).toBe('2026-01-02T00:00:00Z');
    expect(entry.versions[0].changes).toEqual([
      { field: 'fingerprint_sha256', from: 'aa', to: 'bb' },
    ]);
    expect(entry.versions[1].changes).toContainEqual({ field: 'fingerprint_sha256', to: 'aa' });
  });

  it('places a rotation of unknown time at its DID’s creation and an API key rotation with no field changes', () => {
    const apiKey = version(managed, 'did:key', '2026-01-01T00:00:00Z', '2026-01-03T00:00:00Z', {
      agent_identity: { credential_type: 'api_key', api_key_id: 'k1' },
      rotations: [{ rotated_at: null }, { rotated_at: '2026-01-02T00:00:00Z' }],
    });

    const [entry] = groupIdentityVersions([apiKey]);

    expect(entry.versions.map(v => [v.number, v.kind, v.at])).toEqual([
      [3, 'rotation', '2026-01-02T00:00:00Z'],
      [2, 'rotation', null],
      [1, 'did', '2026-01-01T00:00:00Z'],
    ]);
    expect(entry.versions[0].changes).toEqual([]);
  });

  it('shows no versions for a single DID that was never rotated', () => {
    const [entry] = groupIdentityVersions([managed]);

    expect(entry.primary).toBe(managed);
    expect(entry.versions).toEqual([]);
  });
});
