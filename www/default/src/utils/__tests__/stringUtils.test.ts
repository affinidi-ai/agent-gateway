/**
 * DID Formatting Utility Tests
 */

import { formatDID, formatDateTime, topAndTail } from '../stringUtils';

describe('formatDateTime', () => {
  it('places the year before a single time separator', () => {
    const formatted = formatDateTime(new Date(2026, 8, 9, 15, 45), true);

    expect(formatted).toBe('September 9, 2026 at 15:45');
  });
});

describe('topAndTail', () => {
  // topAndTail respects head and tail lengths
  it('topAndTail_respects_head_and_tail_lengths', () => {
    const result = topAndTail('hello world testing this string', 5, 5);
    expect(result).toBe('hello...tring');
  });

  it('returns original string when shorter than threshold', () => {
    const short = 'hi';
    expect(topAndTail(short, 5, 5)).toBe(short);
  });

  it('returns original string when exactly at threshold boundary', () => {
    // top=3, tail=3: threshold = 3+3+3 = 9. String length 9 → not truncated.
    const s = 'abcdefghi'; // 9 chars
    expect(topAndTail(s, 3, 3)).toBe(s);
  });

  it('truncates when string length exceeds top plus tail plus 3', () => {
    // top=4, tail=4: threshold = 11. Length 12 → truncated.
    const s = '123456789012'; // 12 chars
    expect(topAndTail(s, 4, 4)).toBe('1234...9012');
  });
});

describe('formatDID', () => {
  // formatDID truncates did:web channel DIDs preserving UUID head and tail
  it('formatDID_truncates_did_web_channel_preserving_uuid', () => {
    const did = 'did:web:example.com:channel:550e8400-e29b-41d4-a716-446655440000';
    const result = formatDID(did);
    // Expected: "did::channel:550e8400...55440000"
    expect(result).toBe('did::channel:550e8400...55440000');
  });

  // formatDID truncates did:webvh preserving SCID fragment
  it('formatDID_truncates_did_webvh_preserving_scid_fragment', () => {
    const did = 'did:webvh:z6Mkq1234567890abcdefghij:example.com:agents:alpha';
    const result = formatDID(did);
    // identifier = "z6Mkq1234567890abcdefghij:example.com:agents:alpha" (49 chars > 19)
    // first 8 = "z6Mkq123", last 8 = "ts:alpha"
    expect(result).toBe('did:webvh:z6Mkq123...ts:alpha');
  });

  // formatDID does not truncate short DIDs
  it('formatDID_does_not_truncate_short_dids', () => {
    const short = 'did:web:a';
    expect(formatDID(short)).toBe(short);
  });

  it('returns non-DID strings unchanged', () => {
    expect(formatDID('https://example.com')).toBe('https://example.com');
  });

  it('handles did:web without channel segment unchanged if too short to truncate', () => {
    // 4 parts total: did:web:example.com:path (second-to-last is "path", not "channel")
    const did = 'did:web:example.com:path';
    // identifier = "example.com:path" = 16 chars, 16 <= 19 → no truncation
    expect(formatDID(did)).toBe(did);
  });

  it('truncates did:key style DID when identifier is long', () => {
    const longKey = 'z6Mkexampleexampleexampleexample';
    const did = `did:key:${longKey}`;
    // identifier = longKey = 32 chars > 19 → truncated
    const result = formatDID(did);
    expect(result).toContain('...');
    expect(result.startsWith('did:key:')).toBe(true);
  });
});
