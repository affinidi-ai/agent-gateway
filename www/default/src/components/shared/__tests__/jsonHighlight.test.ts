import { tokenizeJson } from '../jsonHighlight';

describe('tokenizeJson', () => {
  it('classifies keys, strings, numbers, booleans and null', () => {
    const json = JSON.stringify({ name: 'ada', count: 3, active: true, note: null }, null, 2);
    const tokens = tokenizeJson(json);
    const typed = tokens.filter(t => t.type !== 'plain');

    const byValue = Object.fromEntries(typed.map(t => [t.value.replace(/"/g, ''), t.type]));
    expect(byValue['name']).toBe('key');
    expect(byValue['ada']).toBe('string');
    expect(byValue['3']).toBe('number');
    expect(byValue['true']).toBe('boolean');
    expect(byValue['null']).toBe('null');
  });

  it('round-trips the exact source when tokens are concatenated', () => {
    const json = JSON.stringify({ a: [1, 'two', false], b: { c: -4.5e2 } }, null, 2);
    expect(
      tokenizeJson(json)
        .map(t => t.value)
        .join('')
    ).toBe(json);
  });

  it('treats a colon-less quoted string as a value, not a key', () => {
    const tokens = tokenizeJson('[ "solo" ]');
    const str = tokens.find(t => t.value === '"solo"');
    expect(str?.type).toBe('string');
  });

  it('returns non-JSON input verbatim as a single plain token', () => {
    const jwt = 'header.payload.signature';
    expect(tokenizeJson(jwt)).toEqual([{ value: jwt, type: 'plain' }]);
  });
});
