import { avatarImageSrc } from '../avatar';

describe('avatarImageSrc', () => {
  it.each([undefined, null, '', 'avatars/default.png', '/avatars/default.png'])(
    'returns null for the built-in fallback path %s',
    avatarPath => {
      expect(avatarImageSrc(avatarPath)).toBeNull();
    }
  );

  it('normalizes custom avatar paths to absolute paths', () => {
    expect(avatarImageSrc('avatars/carlos.png')).toBe('/avatars/carlos.png');
    expect(avatarImageSrc('/avatars/carlos.png')).toBe('/avatars/carlos.png');
  });
});
