import React from 'react';
import { render, screen } from '@testing-library/react';
import PolicyRulesList from '../PolicyRulesList';
import { parsePolicyRules } from '../regoRules';

const noop = () => undefined;

describe('PolicyRulesList', () => {
  it('gives the in-use reason without a rule when none can be named', () => {
    render(
      <PolicyRulesList
        parsed={parsePolicyRules('package p\n\nh if input.x\n\nallow if h\n')}
        canEdit
        valid
        packageMismatch={false}
        empty={false}
        justAdded={null}
        onAdd={noop}
        onWriteRego={noop}
        onRemoveGroup={noop}
        onRemoveRule={noop}
        ruleUse={rule => (rule.head === 'h' ? { kind: 'unnamed' } : null)}
        groupUse={() => null}
        startedFrom={null}
        onSetDefaultDeny={noop}
        onShowRule={noop}
      />
    );
    expect(screen.getByTestId('policy-rules-group-0-rule-0-in-use')).toHaveTextContent(
      /^Another rule uses this; remove that rule first\.$/
    );
    expect(screen.getByTestId('policy-rules-group-0-rule-0-remove-button')).toHaveAttribute(
      'title',
      'Another rule uses this; remove that rule first.'
    );
  });
});
