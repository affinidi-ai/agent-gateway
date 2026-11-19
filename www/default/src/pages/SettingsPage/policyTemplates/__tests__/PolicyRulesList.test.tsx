import React from 'react';
import { render, screen, within } from '@testing-library/react';
import PolicyRulesList from '../PolicyRulesList';
import { parsePolicyRules, ruleRoles, summarizeDecision, type RuleUse } from '../regoRules';
import { DecisionBadge } from '../TemplateBadges';
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
    valid = true,
  }: {
    otherTypeGroups?: (PolicyType | null)[];
    ruleUse?: (rule: { head: string }) => RuleUse | null;
    canEdit?: boolean;
    justAdded?: string | null;
    startedFrom?: string | null;
    valid?: boolean;
  } = {}
) {
  const parsed = parsePolicyRules(rego);
  render(
    <PolicyRulesList
      parsed={parsed}
      summary={summarizeDecision(parsed)}
      ruleRole={ruleRoles(parsed)}
      canEdit={canEdit}
      valid={valid}
      packageMismatch={false}
      empty={!rego.trim()}
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

  it('shows no Default ALLOW banner or no-effect note while an allow definition is not plain', () => {
    renderList('package p\n\ndefault allow := true\n\nallow := false if input.x\n');
    expect(screen.queryByTestId('policy-rules-allow-default-warning')).toBeNull();
    expect(screen.queryByTestId(/-no-effect$/)).toBeNull();
    expect(screen.getByTestId('policy-rules-summary')).toHaveTextContent(
      /^The Rules view can't summarise how this policy sets allow\. Read the Rego\.$/
    );
  });

  it('shows no OR note under groups that allow', () => {
    renderList(`package p\n\ndefault allow := false\n\nallow if input.y\n\n${HTTP_GROUP}`);
    expect(screen.queryByTestId('policy-rules-or-note')).toBeNull();
    expect(screen.queryByText(/combine with OR/)).toBeNull();
  });
});

describe('PolicyRulesList decision summary', () => {
  const summary = () => screen.getByTestId('policy-rules-summary');
  const otherwise = () => screen.queryByTestId('policy-rules-summary-otherwise');

  it('sits after the banners and before the groups', () => {
    renderList('package p\n\ndefault allow := true\n\nallow if input.y\n');
    const banner = screen.getByTestId('policy-rules-allow-default-warning');
    const group = screen.getByTestId('policy-rules-group-0');
    expect(
      banner.compareDocumentPosition(summary()) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();
    expect(
      summary().compareDocumentPosition(group) & Node.DOCUMENT_POSITION_FOLLOWING
    ).toBeTruthy();
  });

  it('says it cannot summarise a policy with an allow definition that is not plain', () => {
    renderList('package p\n\ndefault allow := false\n\nallow := false if { input.x }\n');
    expect(summary()).toHaveTextContent(
      /^The Rules view can't summarise how this policy sets allow\. Read the Rego\.$/
    );
    expect(otherwise()).toBeNull();
  });

  it('says a policy that allows by default allows every request', () => {
    renderList('package p\n\ndefault allow := true\n\nallow if input.y\n');
    expect(summary()).toHaveTextContent(
      /^This policy allows every request: the default is ALLOW\.$/
    );
    expect(otherwise()).toBeNull();
  });

  it('says a policy with an unconditional allow rule allows every request, with no DENY', () => {
    renderList('package p\n\ndefault allow := false\n\nallow if { true }\n\nallow if input.y\n');
    expect(summary()).toHaveTextContent(
      /^This policy allows every request: an allow rule has no conditions\.$/
    );
    expect(otherwise()).toBeNull();
  });

  it('says one allow rule decides, otherwise DENY', () => {
    renderList(TWO_RULES);
    expect(summary()).toHaveTextContent(
      /^This policy allows a request when its allow rule matches\. Otherwise: DENY$/
    );
    expect(otherwise()).toHaveTextContent(/^DENY$/);
    expect(otherwise()).toHaveClass('audit-decision', 'audit-decision--deny');
  });

  it('says any of several allow rules decides, across groups', () => {
    renderList(`package p\n\ndefault allow := false\n\nallow if input.y\n\n${HTTP_GROUP}`);
    expect(summary()).toHaveTextContent(
      /^This policy allows a request when any allow rule matches\. Otherwise: DENY$/
    );
  });

  it('says no default is set after the DENY when allow has no default', () => {
    renderList('package p\n\nallow if input.y\n\nallow if input.z\n');
    expect(summary()).toHaveTextContent(
      /^This policy allows a request when any allow rule matches\. Otherwise: DENY \(no default is set\)$/
    );
    expect(otherwise()).toHaveTextContent(/^DENY$/);
  });

  it('says a policy with no allow rule denies every request', () => {
    renderList('package p\n\ndefault allow := false\n\nh if input.x\n');
    expect(summary()).toHaveTextContent(/^This policy denies every request: no rule allows one\.$/);
    expect(otherwise()).toBeNull();
  });

  it('says no default is set when a policy with no allow rule has no default', () => {
    renderList('package p\n\nh if input.x\n');
    expect(summary()).toHaveTextContent(
      /^This policy denies every request: no rule allows one and no default is set\.$/
    );
  });

  it('shows no summary while the Rego does not parse or compile', () => {
    renderList('package p\n\nallow if {\n');
    expect(screen.getByTestId('policy-rules-unparsed')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-rules-summary')).toBeNull();

    renderList(TWO_RULES, { valid: false });
    expect(screen.getByTestId('policy-rules-invalid-banner')).toBeInTheDocument();
    expect(screen.queryByTestId('policy-rules-summary')).toBeNull();
  });

  it('shows no summary for an empty policy', () => {
    renderList('');
    expect(screen.queryByTestId('policy-rules-summary')).toBeNull();
    expect(screen.getByTestId('policy-rules-empty')).toHaveTextContent(
      'An empty policy allows every request.'
    );
  });

  it('says every request is denied when a policy has no rules and no default', () => {
    renderList('package p\n');
    expect(screen.queryByTestId('policy-rules-summary')).toBeNull();
    expect(screen.getByTestId('policy-rules-empty')).toHaveTextContent(
      'No default is set, so every request is denied.'
    );
    expect(screen.getByTestId('policy-rules-empty')).not.toHaveTextContent('applies');
  });

  it('keeps the default decision text when a policy has no rules but a default', () => {
    renderList('package p\n\ndefault allow := false\n');
    expect(screen.getByTestId('policy-rules-empty')).toHaveTextContent(
      'The default decision (deny) applies to every request.'
    );

    renderList('package q\n\ndefault allow := true\n');
    expect(screen.getAllByTestId('policy-rules-empty')[1]).toHaveTextContent(
      'The default decision (allow) applies to every request.'
    );
  });
});

describe('PolicyRulesList allow conditions', () => {
  const conditions = () => screen.queryByTestId('policy-rules-group-0-rule-0-conditions');

  it('lists each condition of an allow rule on its own line, the later ones after "and"', () => {
    renderList(
      'package p\n\ndefault allow := false\n\nallow if {\n  input.x\n  count(\n    input.y\n  ) > 0\n  not input.z\n}\n'
    );
    const list = conditions();
    expect(list?.tagName).toBe('UL');
    expect(list).toHaveClass('list-unstyled');
    const lines = within(list!).getAllByRole('listitem');
    expect(lines.map(l => l.textContent)).toEqual([
      'input.x',
      'and count(input.y) > 0',
      'and not input.z',
    ]);
    lines.forEach((line, k) =>
      expect(line).toHaveAttribute('data-testid', `policy-rules-group-0-rule-0-condition-${k}`)
    );
    expect(within(lines[0]).queryByText('and')).toBeNull();
    expect(within(lines[1]).getByText('and')).toHaveClass('text-muted');
    expect(within(lines[2]).getByText('not input.z').tagName).toBe('CODE');
    expect(lines[1]).toHaveAttribute('title', 'count(input.y) > 0');
    expect(
      within(screen.getByTestId('policy-rules-group-0-rule-0')).queryByText(/^allow if/)
    ).toBeNull();
  });

  it.each([
    ['a single condition', 'allow if input.x', 'allow if input.x'],
    [
      'else',
      'allow if {\n  input.x\n  input.y\n} else := false',
      'allow if { input.x; input.y } else := false',
    ],
    [
      'a head that is not plain',
      'allow := input.v if {\n  input.x\n  input.y\n}',
      'allow := input.v if { input.x; input.y }',
    ],
    [
      'a with clause on the next line',
      'allow if {\n  input.x\n  f(input.y)\n  with input.a as 1\n}',
      'allow if { input.x; f(input.y) with input.a as 1 }',
    ],
  ])('keeps the rule on one line for %s', (_label, rule, summary) => {
    renderList(`package p\n\ndefault allow := false\n\n${rule}\n`);
    expect(conditions()).toBeNull();
    const code = within(screen.getByTestId('policy-rules-group-0-rule-0')).getByText(summary);
    expect(code).toHaveClass('policy-rules__summary');
    expect(code).toHaveAttribute('title', summary);
  });
});

describe('DecisionBadge', () => {
  it('says what each default decision does in its tooltip', () => {
    render(<DecisionBadge decision="allow" />);
    expect(screen.getByText('Default ALLOW')).toHaveAttribute(
      'title',
      'Allows requests that no allow rule decides'
    );
    render(<DecisionBadge decision="deny" />);
    expect(screen.getByText('Default DENY')).toHaveAttribute(
      'title',
      'Denies requests that no rule allows'
    );
  });
});

describe('PolicyRulesList role badges', () => {
  const kind = (rule: number) => screen.getByTestId(`policy-rules-group-0-rule-${rule}-kind`);

  it('marks a rule allow reads as Used by allow, without edit rights too', () => {
    renderList(
      'package p\n\ndefault allow := false\n\ndeny contains "no path" if not input.http.path\n\nallow if count(deny) == 0\n',
      { canEdit: false }
    );
    expect(kind(0)).toHaveTextContent(/^Used by allow$/);
    expect(kind(0)).toHaveAttribute(
      'title',
      'allow reads this rule, directly or through other rules'
    );
    expect(kind(0)).toHaveClass('policy-rules__kind');
    expect(kind(1)).toHaveTextContent(/^Allows$/);
    expect(screen.queryByText('Helper')).toBeNull();
  });

  it('marks a rule only deny_reason reads as Not used by allow', () => {
    renderList(
      'package p\n\ndefault allow := false\n\ndeny contains "x" if input.y\n\ndeny_reason := concat(", ", deny)\n\nallow if input.z\n'
    );
    expect(kind(0)).toHaveTextContent(/^Not used by allow$/);
    expect(kind(0)).toHaveAttribute(
      'title',
      "allow doesn't read this rule, so it doesn't change whether a request is allowed"
    );
    expect(kind(1)).toHaveTextContent(/^Deny reason$/);
    expect(kind(2)).toHaveTextContent(/^Allows$/);
  });
});
