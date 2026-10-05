import React, { useEffect, useState } from 'react';
import { avatarImageSrc } from '../../utils/avatar';

const AVATAR_SIZES = {
  table: 32,
  topbar: 30,
  modal: 100,
  profile: 150,
} as const;

interface UserAvatarProps {
  avatarPath?: string | null;
  src?: string | null;
  alt: string;
  size: keyof typeof AVATAR_SIZES;
  imageClassName?: string;
  fallbackClassName?: string;
}

export const UserAvatar: React.FC<UserAvatarProps> = ({
  avatarPath,
  src,
  alt,
  size,
  imageClassName,
  fallbackClassName,
}) => {
  const [imageFailed, setImageFailed] = useState(false);
  const avatarSize = AVATAR_SIZES[size];
  const imageSrc = src ?? avatarImageSrc(avatarPath);

  useEffect(() => {
    setImageFailed(false);
  }, [avatarPath, src]);

  const sharedStyle = {
    width: `${avatarSize}px`,
    height: `${avatarSize}px`,
    borderRadius: '50%',
  };

  if (imageSrc && !imageFailed) {
    return (
      <img
        data-testid="user-avatar-image"
        src={imageSrc}
        alt={alt}
        className={imageClassName}
        style={{
          ...sharedStyle,
          objectFit: 'cover',
        }}
        onError={() => setImageFailed(true)}
      />
    );
  }

  return (
    <div
      data-testid="user-avatar-fallback"
      role="img"
      aria-label={`${alt} avatar`}
      title={alt}
      className={
        fallbackClassName ??
        'd-inline-flex align-items-center justify-content-center text-white bg-secondary'
      }
      style={{
        ...sharedStyle,
        fontSize: `${Math.max(14, Math.round(avatarSize * 0.42))}px`,
      }}
    >
      <i className="fas fa-user" aria-hidden="true"></i>
    </div>
  );
};
