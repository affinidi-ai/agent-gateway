/**
 * A slice of a JSON string tagged by syntax role, for editor-style colouring
 * without pulling in a highlighting dependency.
 */
export type JsonTokenType = 'key' | 'string' | 'number' | 'boolean' | 'null' | 'plain';

export interface JsonToken {
  value: string;
  type: JsonTokenType;
}

// Matches JSON string literals, numbers, and the keywords true/false/null.
// Punctuation and whitespace fall through as `plain` segments.
const TOKEN_RE =
  /"(?:\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"|\b(?:true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;

/**
 * Splits pretty-printed JSON into typed tokens for syntax highlighting. A quoted
 * string immediately followed by `:` is classified as a `key`, everything else
 * as a `string`. Pure; returns the input verbatim as `plain` when it isn't JSON.
 */
export function tokenizeJson(json: string): JsonToken[] {
  const tokens: JsonToken[] = [];
  let last = 0;

  for (const match of json.matchAll(TOKEN_RE)) {
    const idx = match.index ?? 0;
    const text = match[0];

    if (idx > last) tokens.push({ value: json.slice(last, idx), type: 'plain' });

    let type: JsonTokenType;
    if (text[0] === '"') {
      type = /^\s*:/.test(json.slice(idx + text.length)) ? 'key' : 'string';
    } else if (text === 'true' || text === 'false') {
      type = 'boolean';
    } else if (text === 'null') {
      type = 'null';
    } else {
      type = 'number';
    }

    tokens.push({ value: text, type });
    last = idx + text.length;
  }

  if (last < json.length) tokens.push({ value: json.slice(last), type: 'plain' });
  return tokens;
}
