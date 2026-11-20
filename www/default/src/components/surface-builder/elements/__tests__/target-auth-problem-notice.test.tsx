import React from 'react';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import TargetAuthProblemNotice, { targetAuthErrorsId } from '../_shared/TargetAuthProblemNotice';

describe('TargetAuthProblemNotice', () => {
  it('names each kind of message in words', () => {
    render(
      <TargetAuthProblemNotice
        testId="notice"
        errors={['Header name must be an HTTP header name']}
        advisories={['Its Target must be an https URL']}
        notes={['The fallback passes a request through']}
      />
    );
    expect(screen.getByTestId('notice-errors')).toHaveTextContent(
      'Error: Header name must be an HTTP header name'
    );
    const advisories = screen.getByTestId('notice-advisories');
    expect(advisories).toHaveTextContent(
      'Advisory: Its Target must be an https URL. Save is allowed: the gateway saves it with a warning'
    );
    expect(advisories).toHaveTextContent(
      'Advisory: The fallback passes a request through. Save is allowed.'
    );
  });

  it('gives the error list the id its inputs point at', () => {
    render(<TargetAuthProblemNotice testId="notice" errors={['Bad header']} />);
    expect(screen.getByTestId('notice-errors')).toHaveAttribute('id', targetAuthErrorsId('notice'));
  });

  it('keeps empty live regions mounted, so a message that appears later is announced', () => {
    render(<TargetAuthProblemNotice testId="notice" errors={[]} />);
    expect(screen.getByRole('alert')).toBeEmptyDOMElement();
    expect(screen.getByRole('status')).toBeEmptyDOMElement();
    expect(screen.queryByTestId('notice-errors')).not.toBeInTheDocument();
    expect(screen.queryByTestId('notice-advisories')).not.toBeInTheDocument();
  });
});
