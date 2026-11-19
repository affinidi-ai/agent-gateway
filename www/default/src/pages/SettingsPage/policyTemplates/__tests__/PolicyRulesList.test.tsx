import React from 'react';
import { render, screen, within } from '@testing-library/react';
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
    canEdit = true,
    justAdded = null,
    startedFrom = null,
  }: {
    otherTypeGroups?: (PolicyType | null)[];
    ruleUse?: (rule: { head: string }) => RuleUse | null;
    canEdit?: boolean;
    justAdded?: string | null;
    startedFrom?: string | null;
  } = {}
) {
  render(
    <PolicyRulesList
      parsed={parsePolicyRules(rego)}
      canEdit={canEdit}
      valid
      packageMismatch={false}
      empty={false}
      justAdded={justAdded}
      otherTypeGroups={otherTypeGroups}
      onAdd={noop}
      onWriteRego={noop}
      onRemoveGroup={noop}
      onRemoveRule={noop}
      ruleUse={ruleUse}
      groupUse={() => null}
      startedFrom={startedFrom}
      onSetDefaultDeny={noop}
      onShowRule={noop}
    />
  );
}

const TWO_RULES = 'package p\n\ndefault allow := false\n\nh if input.x\n\nallow if h\n';

describe('PolicyRulesList group cards', () => {
  it('heads the rules written in the editor with Your rules, a count and no Remove group', () => {
    renderList(TWO_RULES, { startedFrom: 'Allow listed HTTP methods' });
    const group = screen.getByTestId('policy-rules-group-0');
    expect(group).toHaveTextContent('Your rules · started from Allow listed HTTP methods');
    expect(within(group).getByTestId('policy-rules-group-0-count')).toHaveTextContent(/^2 rules$/);
    expect(screen.queryByTestId('policy-rules-group-0-remove-button')).toBeNull();
    expect(screen.queryByTestId('policy-rules-just-added')).toBeNull();
  });

  it('heads a template group with its name, one rule, Just added and Remove group', () => {
    renderList(`package p\n\ndefault allow := false\n\n${HTTP_GROUP}`, {
      justAdded: 'Allow listed HTTP methods',
    });
    const group = screen.getByTestId('policy-rules-group-0');
    expect(group).toHaveTextContent('From template: Allow listed HTTP methods');
    expect(within(group).getByTestId('policy-rules-group-0-count')).toHaveTextContent(/^1 rule$/);
    expect(within(group).getByTestId('policy-rules-just-added')).toHaveTextContent('Just added');
    expect(
      within(group).getByRole('button', {
        name: 'Remove the rules from Allow listed HTTP methods',
      })
    ).toHaveTextContent('Remove group');
  });

  it('counts no rules and shows no table for a template group left empty', () => {
    renderList(
      'package p\n\n# Inserted from template: Blocked callers\n# End of template: Blocked callers\n'
    );
    const group = screen.getByTestId('policy-rules-group-0');
    expect(screen.getByTestId('policy-rules-group-0-count')).toHaveTextContent(/^0 rules$/);
    expect(group).toHaveTextContent('No rules left from this template.');
    expect(within(group).queryByRole('table')).toBeNull();
  });

  it('lists the rules in a table of Kind, Rule, Line and a remove action', () => {
    renderList(TWO_RULES);
    const table = within(screen.getByTestId('policy-rules-group-0')).getByRole('table');
    expect(
      within(table)
        .getAllByRole('columnheader')
        .map(h => h.textContent)
    ).toEqual(['Kind', 'Rule', 'Line', 'Actions']);
    const row = screen.getByTestId('policy-rules-group-0-rule-1');
    expect(
      within(row)
        .getAllByRole('cell')
        .map(c => c.textContent)
    ).toEqual(['Allows', 'allow if h', '7', '']);
    expect(within(row).getByText('allow if h')).toHaveAttribute('title', 'allow if h');
    expect(
      within(row).getByRole('button', { name: 'Show allow in the Rego, line 7' })
    ).toHaveAttribute('title', 'Show in the Rego');
  });

  it('names each rule remove button and leaves a free rule enabled', () => {
    renderList(TWO_RULES);
    const remove = screen.getByRole('button', { name: 'Remove the rule allow' });
    expect(remove).toBe(screen.getByTestId('policy-rules-group-0-rule-1-remove-button'));
    expect(remove).toBeEnabled();
    expect(remove).toHaveAttribute('title', 'Remove');
    expect(remove).not.toHaveAttribute('aria-describedby');
    expect(screen.queryByTestId('policy-rules-group-0-rule-1-in-use')).toBeNull();
  });

  it('disables the remove button of a rule in use and points it at the visible reason', () => {
    renderList(TWO_RULES, {
      ruleUse: rule => (rule.head === 'h' ? { kind: 'reader', name: 'allow', line: 7 } : null),
    });
    const remove = screen.getByRole('button', { name: 'Remove the rule h' });
    expect(remove).toBeDisabled();
    const reason = screen.getByTestId('policy-rules-group-0-rule-0-in-use');
    expect(remove).toHaveAttribute('aria-describedby', reason.id);
    expect(reason).toBeVisible();
    expect(reason).toHaveTextContent(
      'Another rule uses this (allow, line 7); remove that rule first.'
    );
    expect(screen.getByTestId('policy-rules-group-0-rule-0')).toContainElement(reason);
  });

  it('shows no remove action or actions column without edit rights', () => {
    renderList(`${TWO_RULES}\n${HTTP_GROUP}`, { canEdit: false });
    expect(screen.queryByRole('button', { name: /^Remove/ })).toBeNull();
    const table = within(screen.getByTestId('policy-rules-group-0')).getByRole('table');
    expect(
      within(table)
        .getAllByRole('columnheader')
        .map(h => h.textContent)
    ).toEqual(['Kind', 'Rule', 'Line']);
  });
});

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
