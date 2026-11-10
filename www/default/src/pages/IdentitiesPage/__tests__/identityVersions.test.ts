import type { CredentialRotation, Identity } from '../../../types';
import {
  entryVersions,
  groupIdentityVersions,
  membersWithRotations,
  type IdentityEntry,
  type RotationsByHash,
} from '../identityVersions';
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

const rotatedHistory: CredentialRotation[] = [
  { rotated_at: '2026-01-02T00:00:00Z', previous: { fingerprint_sha256: 'aa' } },
];

const versionsOf = (entry: IdentityEntry<Identity>, rotations: RotationsByHash = {}) =>
  entryVersions(entry.members, entry.primary.did, rotations);

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
    expect(entry.hasVersions).toBe(true);
    expect(membersWithRotations(entry.members)).toEqual([]);
    const versions = versionsOf(entry);
    expect(versions.map(v => [v.number, v.did, v.current])).toEqual([
      [2, 'did:b', false],
      [1, 'did:a', true],
    ]);
    expect(versions[0].changes).toEqual([
      { field: 'agentIdentity.llmInfo.model', from: 'gpt-4o', to: 'gpt-4.1' },
    ]);
    expect(versions[1].changes).toEqual([{ field: 'agentIdentity.llmInfo.model', to: 'gpt-4o' }]);
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
    expect(entries.every(entry => !entry.hasVersions && versionsOf(entry).length === 0)).toBe(true);
  });

  it('groups the Managed Agent’s DIDs of every source and slot on one surface', () => {
    const mtls = version(rotated, 'did:mtls', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', {
      rotation_count: undefined,
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

  it('lists a fetched rotation inside its DID with the fields it changed', () => {
    const [entry] = groupIdentityVersions([rotated]);

    expect(entry.hasVersions).toBe(true);
    expect(membersWithRotations(entry.members)).toEqual([rotated]);
    const versions = versionsOf(entry, { [rotated.identity_hash]: rotatedHistory });
    expect(versions.map(v => [v.number, v.kind, v.current])).toEqual([
      [2, 'rotation', true],
      [1, 'did', false],
    ]);
    expect(versions[0].at).toBe('2026-01-02T00:00:00Z');
    expect(versions[0].changes).toEqual([{ field: 'fingerprint_sha256', from: 'aa', to: 'bb' }]);
    expect(versions[1].changes).toContainEqual({ field: 'fingerprint_sha256', to: 'aa' });
  });

  it('builds a single DID’s versions only from fetched rotations of that identity', () => {
    const [entry] = groupIdentityVersions([rotated]);

    expect(versionsOf(entry)).toEqual([]);
    expect(versionsOf(entry, { [rotated.identity_hash]: [] })).toEqual([]);
    expect(versionsOf(entry, { 'another-hash': rotatedHistory })).toEqual([]);
  });

  it('adds each member’s fetched rotations to a multi-DID timeline', () => {
    const older = version(managed, 'did:a', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z');
    const mtls = version(rotated, 'did:mtls', '2026-01-03T00:00:00Z', '2026-01-05T00:00:00Z');
    const [entry] = groupIdentityVersions([older, mtls]);

    expect(membersWithRotations(entry.members)).toEqual([mtls]);
    expect(versionsOf(entry).map(v => [v.number, v.did, v.kind])).toEqual([
      [2, 'did:mtls', 'did'],
      [1, 'did:a', 'did'],
    ]);
    const versions = versionsOf(entry, {
      'hash-did:mtls': [
        { rotated_at: '2026-01-04T00:00:00Z', previous: { fingerprint_sha256: 'aa' } },
      ],
    });
    expect(versions.map(v => [v.number, v.did, v.kind, v.current])).toEqual([
      [3, 'did:mtls', 'rotation', true],
      [2, 'did:mtls', 'did', false],
      [1, 'did:a', 'did', false],
    ]);
    expect(versions[0].changes).toEqual([{ field: 'fingerprint_sha256', from: 'aa', to: 'bb' }]);
  });

  it('places a rotation of unknown time at its DID’s creation and an API key rotation with no field changes', () => {
    const apiKey = version(managed, 'did:key', '2026-01-01T00:00:00Z', '2026-01-03T00:00:00Z', {
      agent_identity: { credential_type: 'api_key', api_key_id: 'k1' },
      rotation_count: 2,
    });

    const [entry] = groupIdentityVersions([apiKey]);
    const versions = versionsOf(entry, {
      'hash-did:key': [{ rotated_at: null }, { rotated_at: '2026-01-02T00:00:00Z' }],
    });

    expect(versions.map(v => [v.number, v.kind, v.at])).toEqual([
      [3, 'rotation', '2026-01-02T00:00:00Z'],
      [2, 'rotation', null],
      [1, 'did', '2026-01-01T00:00:00Z'],
    ]);
    expect(versions[0].changes).toEqual([]);
  });

  it('shows no versions for a single DID that was never rotated', () => {
    const [entry] = groupIdentityVersions([managed]);

    expect(entry.primary).toBe(managed);
    expect(entry.hasVersions).toBe(false);
    expect(membersWithRotations(entry.members)).toEqual([]);
    expect(versionsOf(entry)).toEqual([]);
  });
});
