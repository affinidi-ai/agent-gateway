import React from 'react';
import { Form } from 'react-bootstrap';
import { Link } from '../components/shared/Link';
import { TermsRequirement } from '../termsApi';
import { registrationTermsKey } from './useRegistrationTerms';

interface RegistrationTermsProps {
  requirements: TermsRequirement[];
  selected: Set<string>;
  onToggle: (term: TermsRequirement, checked: boolean) => void;
}

export const RegistrationTerms: React.FC<RegistrationTermsProps> = ({
  requirements,
  selected,
  onToggle,
}) => (
  <>
    {requirements.map(term => (
      <Form.Check
        className="mb-3"
        key={registrationTermsKey(term)}
        id={`registration-terms-${term.terms_type}-${term.version_id}`}
        checked={selected.has(registrationTermsKey(term))}
        onChange={event => onToggle(term, event.target.checked)}
        label={
          <span>
            I agree to {term.title}.{' '}
            <Link
              href={term.url}
              external
              variant="inline"
              testId={`registration-terms-${term.terms_type}-link`}
            >
              View Terms
            </Link>
          </span>
        }
        data-testid={`registration-terms-${term.terms_type}`}
      />
    ))}
  </>
);
