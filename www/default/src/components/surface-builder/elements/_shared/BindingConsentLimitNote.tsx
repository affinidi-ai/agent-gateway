import React from 'react';
import { Form } from 'react-bootstrap';
import { describeConsentLimit } from '../../../../utils/consentLimit';

interface BindingConsentLimitNoteProps {
  /** The binding's own `max_consent_age_secs`; nothing is shown without one. */
  secs: number | undefined;
  testId: string;
}

/** Says a credential binding's own consent time limit, which is set through the API. */
const BindingConsentLimitNote: React.FC<BindingConsentLimitNoteProps> = ({ secs, testId }) =>
  secs === undefined ? null : (
    <Form.Text className="text-muted d-block" data-testid={testId} style={{ fontSize: '10px' }}>
      Consent time limit: {describeConsentLimit(secs)}, set through the API. A consent older than
      this is asked for again.
    </Form.Text>
  );

export default BindingConsentLimitNote;
