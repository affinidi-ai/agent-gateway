import { scrubVolatileTemplateFields, findDuplicateListenerRoutes } from '../scrubVolatile';

describe('scrubVolatileTemplateFields', () => {
  it('blanks transit-point listener + identity fields', () => {
    const out = scrubVolatileTemplateFields({
      access_point: { listen_address: '$HOST', route: '$ROUTE' },
      transit: {
        points: [
          {
            id: 'baked-uuid',
            alias: 'baked-alias',
            listen_address: 'https://host',
            listen_path: '/baked/path',
            target_endpoint: 'https://upstream',
            protocol: 'a2a',
          },
        ],
      },
    });
    const tp = (out as any).transit.points[0];
    expect(tp.id).toBeUndefined();
    expect(tp.alias).toBeUndefined();
    expect(tp.listen_address).toBeUndefined();
    expect(tp.listen_path).toBeUndefined();
    expect(tp.target_endpoint).toBe('https://upstream');
    expect(tp.protocol).toBe('a2a');
  });

  it('blanks canvas transit-point listener mirrors but leaves AP and other nodes alone', () => {
    const out = scrubVolatileTemplateFields({
      canvas: {
        nodes: [
          {
            id: 'access-point',
            type: 'access-point',
            config: {
              listen_address: 'https://host',
              route: '/payments/foo',
              name: 'Front door',
            },
          },
          {
            id: 'transit-point-a2a-1',
            type: 'transit-point-a2a',
            config: {
              id: 'tp-uuid',
              alias: 'tp-alias',
              listen_address: 'https://outbound',
              listen_path: '/payments/bar',
              route_prefix: '/payments',
              route_suffix: '/bar',
              target_endpoint: 'https://upstream',
            },
          },
          {
            id: '__human__',
            type: 'human',
            config: { foo: 'bar' },
          },
        ],
      },
    });
    const [ap, tp, human] = (out as any).canvas.nodes;
    // AP structured fields win at apply time, so the canvas mirror
    // isn't scrubbed — kept verbatim.
    expect(ap.config.listen_address).toBe('https://host');
    expect(ap.config.route).toBe('/payments/foo');
    expect(ap.config.name).toBe('Front door');
    expect(tp.config.id).toBeUndefined();
    expect(tp.config.alias).toBeUndefined();
    expect(tp.config.listen_address).toBeUndefined();
    expect(tp.config.listen_path).toBeUndefined();
    expect(tp.config.target_endpoint).toBe('https://upstream');
    expect(human.config).toEqual({ foo: 'bar' });
  });

  it('is a no-op for primitives / null / arrays', () => {
    expect(scrubVolatileTemplateFields(null as any)).toBeNull();
    expect(scrubVolatileTemplateFields(undefined as any)).toBeUndefined();
    expect(scrubVolatileTemplateFields('s' as any)).toBe('s');
  });

  it('does not mutate input', () => {
    const input = {
      transit: { points: [{ id: 'x', alias: 'y' }] },
    };
    const snapshot = JSON.stringify(input);
    scrubVolatileTemplateFields(input);
    expect(JSON.stringify(input)).toBe(snapshot);
  });
});

describe('findDuplicateListenerRoutes', () => {
  it('returns null when AP and TPs are distinct', () => {
    expect(
      findDuplicateListenerRoutes({
        access_point: { listen_address: 'https://h', route: '/a' },
        transit: {
          points: [
            { listen_address: 'https://h', listen_path: '/b', alias: 'tp1' },
            { listen_address: 'https://h', listen_path: '/c', alias: 'tp2' },
          ],
        },
      })
    ).toBeNull();
  });

  it('flags AP vs TP collision', () => {
    const err = findDuplicateListenerRoutes({
      access_point: { listen_address: 'https://h', route: '/dup' },
      transit: { points: [{ listen_address: 'https://h', listen_path: '/dup', alias: 'tp1' }] },
    });
    expect(err).toMatch(/access point/);
    expect(err).toMatch(/tp1/);
  });

  it('flags two TPs sharing the same listener path', () => {
    const err = findDuplicateListenerRoutes({
      access_point: { listen_address: 'https://h', route: '/x' },
      transit: {
        points: [
          { listen_address: 'https://h', listen_path: '/same', alias: 'a' },
          { listen_address: 'https://h', listen_path: '/same', alias: 'b' },
        ],
      },
    });
    expect(err).toMatch(/transit point/);
  });

  it('ignores empty listener fields (treated as "not configured yet")', () => {
    expect(
      findDuplicateListenerRoutes({
        access_point: { listen_address: '', route: '' },
        transit: {
          points: [{ listen_address: '', listen_path: '', alias: 'tp' }],
        },
      })
    ).toBeNull();
  });
});
