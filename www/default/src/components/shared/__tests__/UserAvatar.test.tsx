import { fireEvent, render, screen } from '@testing-library/react';
import { UserAvatar } from '../UserAvatar';

describe('UserAvatar', () => {
  it.each([undefined, 'avatars/default.png'])(
    'renders a non-image fallback when avatar path is %s',
    avatarPath => {
      render(<UserAvatar alt="carlos" avatarPath={avatarPath} size="table" />);

      expect(screen.queryByTestId('user-avatar-image')).not.toBeInTheDocument();
      expect(screen.getByTestId('user-avatar-fallback')).toHaveAttribute(
        'aria-label',
        'carlos avatar'
      );
    }
  );

  it('replaces a failed custom avatar image with a non-image fallback', () => {
    render(<UserAvatar alt="carlos" avatarPath="avatars/carlos.png" size="table" />);

    fireEvent.error(screen.getByTestId('user-avatar-image'));

    expect(screen.queryByTestId('user-avatar-image')).not.toBeInTheDocument();
    expect(screen.getByTestId('user-avatar-fallback')).toBeInTheDocument();
  });
});
