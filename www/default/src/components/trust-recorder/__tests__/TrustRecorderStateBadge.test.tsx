import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import type { TrustRecorderState } from '../../../types';
import { TrustRecorderStateBadge } from '../TrustRecorderStateBadge';

describe('TrustRecorderStateBadge', () => {
  it.each<[TrustRecorderState, string, string]>([
    ['recorded', 'Recorded', 'text-bg-success'],
    ['partial', 'Partly recorded', 'text-bg-warning'],
    ['failed', 'Failed', 'text-bg-danger'],
    ['skipped', 'Skipped', 'text-bg-secondary'],
    ['not_attempted', 'Not attempted yet', 'text-bg-light'],
  ])('shows the %s state as text "%s"', (state, label, toneClass) => {
    render(<TrustRecorderStateBadge state={state} testId="badge" />);

    const badge = screen.getByTestId('badge');
    expect(badge).toHaveTextContent(label);
    expect(badge).toHaveClass(toneClass);
  });
});
