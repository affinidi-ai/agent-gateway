import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import WizardProgress from '../WizardProgress';

const STEPS = [
  { key: 'one', label: 'One' },
  { key: 'two', label: 'Two' },
  { key: 'three', label: 'Three' },
];

describe('WizardProgress', () => {
  it('marks earlier steps completed, the current one active and numbers the rest', () => {
    render(<WizardProgress steps={STEPS} currentIndex={1} />);

    const one = screen.getByTestId('wizard-progress-step-one');
    const two = screen.getByTestId('wizard-progress-step-two');
    const three = screen.getByTestId('wizard-progress-step-three');
    expect(one).toHaveClass('completed');
    expect(one).not.toHaveTextContent('1');
    expect(two).toHaveClass('active');
    expect(two).toHaveAttribute('aria-current', 'step');
    expect(two).toHaveTextContent('2Two');
    expect(three).not.toHaveClass('active');
    expect(three).not.toHaveClass('completed');
    expect(three).toHaveTextContent('3Three');
  });

  it('marks the first step active at the start', () => {
    render(<WizardProgress steps={STEPS} currentIndex={0} />);

    expect(screen.getByTestId('wizard-progress-step-one')).toHaveClass('active');
    expect(screen.getByTestId('wizard-progress-step-two')).not.toHaveClass('completed');
  });
});
