import { safeNextTarget } from './loginNextTarget';

const ORIGIN = 'https://gateway.example';
const CLI_TARGET = '/api/auth/cli/authorize?port=52111&state=st&challenge=ch';

test('accepts the dashboard root', () => {
  expect(safeNextTarget('/', ORIGIN)).toBe('/');
});

test('accepts the CLI authorize path and rebuilds it from the resolved URL', () => {
  expect(safeNextTarget(CLI_TARGET, ORIGIN)).toBe(CLI_TARGET);
  expect(
    safeNextTarget('/api/auth/cli/authorize?port=52111&state=a%20b&challenge=ch', ORIGIN)
  ).toBe('/api/auth/cli/authorize?port=52111&state=a%20b&challenge=ch');
});

test('accepts a CLI state that holds an encoded slash or backslash', () => {
  const target = `/api/auth/cli/authorize?port=52111&state=${encodeURIComponent('a/b\\c')}&challenge=ch`;
  expect(target).toBe('/api/auth/cli/authorize?port=52111&state=a%2Fb%5Cc&challenge=ch');

  expect(safeNextTarget(target, ORIGIN)).toBe(target);
});

test.each([
  ['a missing value', null],
  ['an empty value', ''],
  ['an absolute URL', 'https://evil.example/'],
  ['a protocol-relative URL', '//evil.example'],
  ['a backslash host', '/\\evil.example'],
  ['an encoded slash', '/%2fevil.example'],
  ['an encoded backslash', '/%5Cevil.example'],
  ['an encoded slash in the CLI path', '/api/auth/cli%2Fauthorize?port=1'],
  ['an encoded backslash in the CLI path', '/api/auth/cli%5cauthorize?port=1'],
  ['a backslash in the CLI path', '/api/auth/cli\\authorize?port=1'],
  ['a protocol-relative CLI path', '//api/auth/cli/authorize?port=1'],
  ['a dot segment in the CLI path', '/api/auth/../auth/cli/authorize/x?port=1'],
  ['a path outside the allow list', '/settings'],
  ['the CLI path without a query', '/api/auth/cli/authorize'],
  ['the CLI path with an empty query', '/api/auth/cli/authorize?'],
  ['a sub path of the CLI path', '/api/auth/cli/authorize/extra?port=1'],
  ['the root with a query', '/?port=52111'],
  ['a quote', "/api/auth/cli/authorize?port=1'"],
  ['a double quote', '/api/auth/cli/authorize?port=1"'],
  ['an angle bracket', '/api/auth/cli/authorize?port=1<'],
  ['a space', '/api/auth/cli/authorize?port=1 2'],
  ['a control character', '/api/auth/cli/authorize?port=1\n'],
])('rejects %s', (_label, value) => {
  expect(safeNextTarget(value, ORIGIN)).toBeNull();
});
