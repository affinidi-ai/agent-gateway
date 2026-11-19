import React from 'react';
import { render, screen } from '@testing-library/react';
import PolicyRulesList from '../PolicyRulesList';
import { parsePolicyRules, type RuleUse } from '../regoRules';
import type { PolicyType } from '../types';

const noop = () => undefined;

const HTTP_GROUP =
  '# Inserted from template: Allow listed HTTP methods\nallow if input.http.method in {"GET"}\n# End of template: Allow listed HTTP methods\n';

function renderList(
  rego: string,
  {
    otherTypeGroups = [],
    ruleUse = () => null,
  }: {
    otherTypeGroups?: (PolicyType | null)[];
    ruleUse?: (rule: { head: string }) => RuleUse | null;
  } = {}
) {
  render(
    <PolicyRulesList
      parsed={parsePolicyRules(rego)}
      canEdit
      valid
      packageMismatch={false}
      empty={false}
      justAdded={null}
      otherTypeGroups={otherTypeGroups}
      onAdd={noop}
      onWriteRego={noop}
      onRemoveGroup={noop}
      onRemoveRule={noop}
      ruleUse={ruleUse}
      groupUse={() => null}
      startedFrom={null}
      onSetDefaultDeny={noop}
      onShowRule={noop}
    />
  );
}

describe('PolicyRulesList', () => {
  it('gives the in-use reason without a rule when none can be named', () => {
    renderList('package p\n\nh if input.x\n\nallow if h\n', {
      ruleUse: rule => (rule.head === 'h' ? { kind: 'unnamed' } : null),
    });
    expect(screen.getByTestId('policy-rules-group-0-rule-0-in-use')).toHaveTextContent(
      /^Another rule uses this; remove that rule first\.$/
    );
    expect(screen.getByTestId('policy-rules-group-0-rule-0-remove-button')).toHaveAttribute(
      'title',
      'Another rule uses this; remove that rule first.'
    );
  });

  it('marks a group written for the other Type and says to remove it', () => {
    renderList(`package gateway.policy\n\ndefault allow := false\n\n${HTTP_GROUP}`, {
      otherTypeGroups: ['agent_surface'],
    });
    expect(screen.getByTestId('policy-rules-group-0-other-type')).toHaveTextContent(
      "Written for Agent Surface policies. It reads input Gateway policies don't get. Remove it to create this policy."
    );
    expect(screen.getByTestId('policy-rules-group-0-remove-button')).toBeEnabled();
    expect(screen.getByTestId('policy-rules-other-type-banner')).toHaveTextContent(
      'Remove the rules written for Agent Surface policies to create this policy.'
    );
  });

  it('marks no group when every group fits the Type', () => {
    renderList(`package gateway.policy\n\ndefault allow := false\n\n${HTTP_GROUP}`, {
      otherTypeGroups: [null],
    });
    expect(screen.queryByTestId('policy-rules-group-0-other-type')).toBeNull();
    expect(screen.queryByTestId('policy-rules-other-type-banner')).toBeNull();
  });

  it('marks each group with allow rules as having no effect under Default ALLOW', () => {
    renderList(
      `package p\n\ndefault allow := true\n\ndeny_reason := "no"\n\nallow if input.y\n\n${HTTP_GROUP}`
    );
    expect(screen.getByTestId('policy-rules-group-0-no-effect')).toHaveTextContent(
      'No effect while the default is ALLOW.'
    );
    expect(screen.getByTestId('policy-rules-group-1-no-effect')).toBeInTheDocument();
    expect(screen.getByTestId('policy-rules-allow-default-warning')).toBeInTheDocument();
  });

  it('marks no group as having no effect under Default DENY or without allow rules', () => {
    renderList(`package p\n\ndefault allow := false\n\n${HTTP_GROUP}`);
    expect(screen.queryByTestId('policy-rules-group-0-no-effect')).toBeNull();

    renderList('package q\n\ndefault allow := true\n\ndeny_reason := "no"\n');
    expect(screen.queryByTestId(/-no-effect$/)).toBeNull();
  });
});
