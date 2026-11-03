import { cardEra, diffAgentCards, type CardDiff, type RowKey } from '../agentCardDiff';

const row = (diff: CardDiff, key: RowKey) => {
  const found = diff.rows.find(r => r.key === key);
  if (!found) throw new Error(`no row ${key}`);
  return found;
};
const item = (diff: CardDiff, key: RowKey, path: string) => {
  const found = row(diff, key).items.find(i => i.path === path);
  if (!found) throw new Error(`no item ${path} in ${key}`);
  return found;
};

const mockCard03 = () => ({
  protocolVersion: '0.3.0',
  name: 'Mock agent',
  url: 'https://agent.internal/a2a',
  capabilities: { streaming: true },
  securitySchemes: {
    agent_own_oauth: {
      type: 'oauth2',
      flows: {
        clientCredentials: {
          tokenUrl: 'https://idp.example/token',
          scopes: { 'agent.read': 'Read' },
        },
      },
    },
  },
  security: [{ agent_own_oauth: ['agent.read'] }],
  signatures: [{ protected: 'p', signature: 's' }],
  skills: [{ id: 'echo', name: 'Echo', security: [{ agent_own_oauth: [] }] }],
});

const declaredAfter03 = () => ({
  protocolVersion: '0.3.0',
  name: 'Mock agent',
  url: 'https://gw.example/mock-agent',
  capabilities: { streaming: true },
  securitySchemes: {
    agent_gateway: {
      type: 'oauth2',
      flows: {
        authorizationCode: {
          authorizationUrl: 'https://as.example/authorize',
          tokenUrl: 'https://as.example/token',
          scopes: { 'gw.invoke': 'Invoke' },
        },
      },
    },
  },
  security: [{ agent_gateway: ['gw.invoke'] }],
  skills: [{ id: 'echo', name: 'Echo' }],
});

const card10 = () => ({
  name: 'Agent v1',
  supportedInterfaces: [
    { url: 'https://agent.internal/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0' },
    { url: 'https://agent.internal/grpc', protocolBinding: 'GRPC', protocolVersion: '1.0' },
  ],
  securitySchemes: {
    own: {
      oauth2SecurityScheme: {
        flows: {
          clientCredentials: { tokenUrl: 'https://idp.example/token', scopes: { a: 'A', b: 'B' } },
        },
      },
    },
  },
  securityRequirements: [{ schemes: { own: { list: ['a'] } } }],
});

describe('diffAgentCards, A2A 0.3 card declared by the gateway', () => {
  const diff = diffAgentCards(mockCard03(), declaredAfter03());

  it('reports the sign-in swap item by item', () => {
    expect(row(diff, 'signin').status).toBe('changed');
    expect(item(diff, 'signin', 'securitySchemes.agent_own_oauth').status).toBe('removed');
    expect(item(diff, 'signin', 'securitySchemes.agent_gateway').status).toBe('added');
    const required = item(diff, 'signin', 'security');
    expect(required.status).toBe('changed');
    expect(required.before).toBe('agent_own_oauth');
    expect(required.after).toBe('agent_gateway');
    const skills = item(diff, 'signin', 'skills.security');
    expect(skills.status).toBe('removed');
    expect(skills.before).toBe('1 skill');
    expect(skills.after).toBeNull();
  });

  it('collects scopes from requirements and scheme flows', () => {
    expect(row(diff, 'scope').status).toBe('changed');
    expect(row(diff, 'scope').items.map(i => [i.label, i.status])).toEqual([
      ['agent.read', 'removed'],
      ['gw.invoke', 'added'],
    ]);
  });

  it('marks the dropped signatures as removed', () => {
    const sig = row(diff, 'signature');
    expect(sig.status).toBe('removed');
    expect(sig.items[0]).toMatchObject({ before: '1 signature', after: null });
  });

  it('shows the rewritten endpoint as the primary URL', () => {
    const url = item(diff, 'endpoint', 'url');
    expect(url).toMatchObject({
      status: 'changed',
      primary: true,
      before: 'https://agent.internal/a2a',
      after: 'https://gw.example/mock-agent',
    });
  });

  it('keeps unrelated parts the same, ignoring skill security keys', () => {
    expect(row(diff, 'other').status).toBe('same');
    expect(item(diff, 'other', 'skills[echo]').status).toBe('same');
    expect(item(diff, 'other', 'capabilities.streaming').status).toBe('same');
    expect(item(diff, 'other', 'name').status).toBe('same');
  });

  it('counts changed, added and removed parts', () => {
    expect(diff.changedCount).toBe(4);
    expect(diff.removedCount).toBe(4);
    expect(diff.changeCount).toBe(8);
  });

  it('splits changed parts into added and modified ones', () => {
    const items = diff.rows.flatMap(r => r.items);
    expect(diff.addedCount).toBe(items.filter(i => i.status === 'added').length);
    expect(diff.modifiedCount).toBe(items.filter(i => i.status === 'changed').length);
    expect(diff.addedCount + diff.modifiedCount).toBe(diff.changedCount);
    expect(diff.addedCount).toBeGreaterThan(0);
    expect(diff.modifiedCount).toBeGreaterThan(0);
  });
});

describe('diffAgentCards, A2A 1.0 card', () => {
  it('reads supportedInterfaces, securityRequirements and wrapped schemes', () => {
    const before = card10();
    const after = card10();
    after.supportedInterfaces[0].url = 'https://gw.example/agent';
    after.securityRequirements = [{ schemes: { own: { list: ['b'] } } }];
    const diff = diffAgentCards(before, after);

    expect(item(diff, 'endpoint', 'supportedInterfaces[0].url')).toMatchObject({
      status: 'changed',
      primary: true,
    });
    expect(item(diff, 'endpoint', 'supportedInterfaces[1].url').status).toBe('same');
    expect(row(diff, 'scope').items.map(i => [i.label, i.status])).toEqual([
      ['a', 'same'],
      ['b', 'same'],
    ]);
    expect(row(diff, 'signin').status).toBe('same');
    expect(row(diff, 'signature').status).toBe('absent');
  });

  it('treats a card the gateway left alone as unchanged', () => {
    const diff = diffAgentCards(card10(), card10());
    expect(diff.changeCount).toBe(0);
    expect(diff.addedCount).toBe(0);
    expect(diff.modifiedCount).toBe(0);
    expect(diff.rows.map(r => r.status)).toEqual(['same', 'same', 'absent', 'same', 'same']);
  });

  it('reports interface order changes by index', () => {
    const after = card10();
    after.supportedInterfaces.reverse();
    const diff = diffAgentCards(card10(), after);
    expect(item(diff, 'endpoint', 'supportedInterfaces[0].url')).toMatchObject({
      status: 'changed',
      before: 'https://agent.internal/a2a',
      after: 'https://agent.internal/grpc',
    });
    expect(item(diff, 'endpoint', 'supportedInterfaces[1].url').status).toBe('changed');
  });

  it('reads snake_case keys', () => {
    const before = {
      security_schemes: { s: { type: 'oauth2' } },
      supported_interfaces: [{ url: 'https://a/x' }],
      security_requirements: [{ schemes: { s: { list: ['k'] } } }],
    };
    const diff = diffAgentCards(before, {});
    expect(item(diff, 'signin', 'securitySchemes.s').status).toBe('removed');
    expect(item(diff, 'scope', 'scope.k').status).toBe('removed');
    expect(item(diff, 'endpoint', 'supportedInterfaces[0].url').status).toBe('removed');
  });
});

describe('diffAgentCards, other outcomes', () => {
  it('shows a stripped card as removed sign-in and scopes', () => {
    const after = declaredAfter03();
    delete (after as Record<string, unknown>).securitySchemes;
    delete (after as Record<string, unknown>).security;
    const diff = diffAgentCards(mockCard03(), after);
    expect(row(diff, 'signin').status).toBe('removed');
    expect(row(diff, 'scope').status).toBe('removed');
  });

  it('shows a pass-through card as the same everywhere', () => {
    const diff = diffAgentCards(mockCard03(), mockCard03());
    expect(diff.changeCount).toBe(0);
    expect(row(diff, 'signature').status).toBe('same');
    expect(row(diff, 'signin').status).toBe('same');
  });

  it('ignores key order in objects and order of skills', () => {
    const before = {
      securitySchemes: { s: { type: 'oauth2', flows: { a: 1, b: 2 } } },
      skills: [
        { id: 'a', name: 'A' },
        { id: 'b', name: 'B' },
      ],
    };
    const after = {
      securitySchemes: { s: { flows: { b: 2, a: 1 }, type: 'oauth2' } },
      skills: [
        { name: 'B', id: 'b' },
        { name: 'A', id: 'a' },
      ],
    };
    expect(diffAgentCards(before, after).changeCount).toBe(0);
  });

  it('keeps array order significant outside skills', () => {
    const diff = diffAgentCards({ tags: ['a', 'b'] }, { tags: ['b', 'a'] });
    expect(item(diff, 'other', 'tags').status).toBe('changed');
  });

  it('matches skills by id and reports added, removed and changed skills', () => {
    const diff = diffAgentCards(
      {
        skills: [
          { id: 'a', name: 'A' },
          { id: 'b', name: 'B' },
        ],
      },
      {
        skills: [
          { id: 'b', name: 'B2' },
          { id: 'c', name: 'C' },
        ],
      }
    );
    expect(item(diff, 'other', 'skills[a]').status).toBe('removed');
    expect(item(diff, 'other', 'skills[b]').status).toBe('changed');
    expect(item(diff, 'other', 'skills[c]').status).toBe('added');
    expect(diff.addedCount).toBe(1);
    expect(diff.modifiedCount).toBe(1);
    expect(diff.removedCount).toBe(1);
  });

  it('compares objects one level down', () => {
    const diff = diffAgentCards(
      {
        capabilities: { streaming: true, pushNotifications: true },
        provider: { organization: 'x' },
      },
      { capabilities: { streaming: false }, provider: { organization: 'x' } }
    );
    expect(item(diff, 'other', 'capabilities.streaming').status).toBe('changed');
    expect(item(diff, 'other', 'capabilities.pushNotifications').status).toBe('removed');
    expect(item(diff, 'other', 'provider.organization').status).toBe('same');
  });

  it('counts signatures that stay or change', () => {
    const same = diffAgentCards({ signatures: [{}] }, { signatures: [{}] });
    expect(row(same, 'signature').status).toBe('same');
    const more = diffAgentCards({ signatures: [{}] }, { signatures: [{}, {}] });
    expect(row(more, 'signature').status).toBe('changed');
  });

  it('counts skills that carry their own security', () => {
    const diff = diffAgentCards(
      { skills: [{ id: 'a', security: [{ s: [] }] }, { id: 'b' }] },
      {
        skills: [
          { id: 'a', security: [{ s: [] }] },
          { id: 'b', security: [{ s: [] }] },
        ],
      }
    );
    expect(item(diff, 'signin', 'skills.security')).toMatchObject({
      status: 'changed',
      before: '1 skill',
      after: '2 skills',
    });
  });

  it('stops recursing at depth 64 and still compares', () => {
    const nest = (leaf: string) => {
      let value: unknown = leaf;
      for (let i = 0; i < 100; i += 1) value = { next: value };
      return value;
    };
    expect(diffAgentCards({ deep: nest('x') }, { deep: nest('x') }).changeCount).toBe(0);
    expect(diffAgentCards({ deep: nest('x') }, { deep: nest('y') }).changeCount).toBe(1);
  });
});

describe('diffAgentCards, missing and malformed input', () => {
  it('treats a missing before as everything added', () => {
    const diff = diffAgentCards(null, declaredAfter03());
    expect(row(diff, 'signin').status).toBe('changed');
    expect(item(diff, 'endpoint', 'url').status).toBe('added');
    expect(diff.removedCount).toBe(0);
    expect(diff.changedCount).toBeGreaterThan(0);
    expect(diff.modifiedCount).toBe(0);
    expect(diff.addedCount).toBe(diff.changedCount);
  });

  it('treats a missing after as everything removed', () => {
    const diff = diffAgentCards(mockCard03(), undefined);
    expect(row(diff, 'signin').status).toBe('removed');
    expect(row(diff, 'signature').status).toBe('removed');
    expect(item(diff, 'endpoint', 'url').status).toBe('removed');
    expect(diff.changedCount).toBe(0);
    expect(diff.addedCount).toBe(0);
    expect(diff.modifiedCount).toBe(0);
  });

  it('counts non-objects as empty cards', () => {
    for (const input of ['text', 5, [], true]) {
      const diff = diffAgentCards(input, input);
      expect(diff.changeCount).toBe(0);
      expect(diff.rows.every(r => r.status === 'absent')).toBe(true);
    }
  });

  it('survives malformed parts of a card', () => {
    const diff = diffAgentCards(
      {
        securitySchemes: 'oops',
        security: 'oops',
        signatures: 'oops',
        skills: 'oops',
        endpoints: [null, 4, { url: 5 }],
        supportedInterfaces: 'oops',
      },
      { securitySchemes: [], skills: [null, 'x', { id: 7 }], endpoints: {} }
    );
    expect(row(diff, 'signin').items).toEqual([]);
    expect(row(diff, 'signature').status).toBe('absent');
    expect(row(diff, 'endpoint').status).toBe('absent');
    expect(item(diff, 'other', 'skills').status).toBe('changed');
  });
});

describe('cardEra', () => {
  it('detects 0.3, 1.0, both and unknown', () => {
    expect(cardEra(mockCard03())).toBe('0.3');
    expect(cardEra(card10())).toBe('1.0');
    expect(cardEra({ url: 'https://a', supportedInterfaces: [{ url: 'https://a' }] })).toBe('both');
    expect(cardEra({ name: 'x' })).toBe('unknown');
    expect(cardEra(null)).toBe('unknown');
    expect(cardEra({ protocolVersion: '1.0', securityRequirements: [] })).toBe('1.0');
  });
});
