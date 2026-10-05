import { trustRecorderDefinition } from '../trust-recorder/definition';

describe('trustRecorderDefinition — suppressIncompleteBanner', () => {
  it('suppresses the sidebar incomplete banner on a fresh element (no entries)', () => {
    expect(trustRecorderDefinition.suppressIncompleteBanner).toBeDefined();
    expect(trustRecorderDefinition.suppressIncompleteBanner!({})).toBe(true);
    expect(trustRecorderDefinition.suppressIncompleteBanner!({ entries: [] })).toBe(true);
  });

  it('surfaces the sidebar incomplete banner once at least one entry exists', () => {
    expect(
      trustRecorderDefinition.suppressIncompleteBanner!({
        entries: [
          {
            trust_registry_id: '',
            issuer_did: '',
            authority_did: '',
            include_owned_agent: true,
            custom_resources: [],
          },
        ],
      })
    ).toBe(false);
  });
});

describe('trustRecorderDefinition — incompleteReason (regression)', () => {
  it('flags an empty configuration', () => {
    expect(trustRecorderDefinition.incompleteReason({})).toMatch(/at least one/i);
    expect(trustRecorderDefinition.incompleteReason({ entries: [] })).toMatch(/at least one/i);
  });

  it('flags a missing trust registry', () => {
    expect(
      trustRecorderDefinition.incompleteReason({
        entries: [
          {
            trust_registry_id: '',
            issuer_did: 'did:key:issuer',
            authority_did: 'did:key:authority',
            include_owned_agent: true,
            custom_resources: [],
          },
        ],
      })
    ).toMatch(/trust registry/i);
  });

  it('flags a missing issuer DID', () => {
    expect(
      trustRecorderDefinition.incompleteReason({
        entries: [
          {
            trust_registry_id: 'tr-a',
            issuer_did: '',
            authority_did: 'did:key:authority',
            include_owned_agent: true,
            custom_resources: [],
          },
        ],
      })
    ).toMatch(/issuer/i);
  });

  it('flags a missing authority DID', () => {
    expect(
      trustRecorderDefinition.incompleteReason({
        entries: [
          {
            trust_registry_id: 'tr-a',
            issuer_did: 'did:key:issuer',
            authority_did: '',
            include_owned_agent: true,
            custom_resources: [],
          },
        ],
      })
    ).toMatch(/authority/i);
  });

  it('flags an entry with neither ownedAgent nor any complete custom resource', () => {
    expect(
      trustRecorderDefinition.incompleteReason({
        entries: [
          {
            trust_registry_id: 'tr-a',
            issuer_did: 'did:key:issuer',
            authority_did: 'did:key:authority',
            include_owned_agent: false,
            custom_resources: [],
          },
        ],
      })
    ).toMatch(/ownedAgent|custom resource/i);
  });

  it('returns null for a complete entry using ownedAgent only', () => {
    expect(
      trustRecorderDefinition.incompleteReason({
        entries: [
          {
            trust_registry_id: 'tr-a',
            issuer_did: 'did:key:issuer',
            authority_did: 'did:key:authority',
            include_owned_agent: true,
            custom_resources: [],
          },
        ],
      })
    ).toBeNull();
  });

  it('returns null for a complete entry using a custom resource only', () => {
    expect(
      trustRecorderDefinition.incompleteReason({
        entries: [
          {
            trust_registry_id: 'tr-a',
            issuer_did: 'did:key:issuer',
            authority_did: 'did:key:authority',
            include_owned_agent: false,
            custom_resources: [
              {
                action: 'is',
                resource: 'paymentAgent',
                entity_target: 'agent',
                record_type: 'recognition',
              },
            ],
          },
        ],
      })
    ).toBeNull();
  });
});
