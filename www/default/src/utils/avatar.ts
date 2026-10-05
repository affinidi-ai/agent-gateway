export const DEFAULT_AVATAR_PATH = 'avatars/default.png';

export function avatarImageSrc(avatarPath?: string | null): string | null {
  const normalizedAvatarPath = avatarPath?.replace(/^\/+/, '');

  if (!normalizedAvatarPath || normalizedAvatarPath === DEFAULT_AVATAR_PATH) {
    return null;
  }

  return `/${normalizedAvatarPath}`;
}
