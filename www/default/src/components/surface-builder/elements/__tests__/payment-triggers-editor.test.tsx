import React, { useState } from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import PaymentTriggersEditor from '../payment/PaymentTriggersEditor';
import {
  describeTriggers,
  mcpMatchHasNoPatterns,
  questionableMcpPatterns,
  triggerPatternAdvice,
} from '../payment/triggers';
import type { PaymentNodeConfig } from '../payment/types';
import type { CanvasNode } from '../types';

const node: CanvasNode = { id: 'pay', type: 'payment', label: 'Payment', configured: true };

let latest: PaymentNodeConfig = {};

const Harness: React.FC<{
  initial?: PaymentNodeConfig;
  protocol: 'mcp' | 'a2a';
  hasAttemptedSave?: boolean;
}> = ({ initial = {}, protocol, hasAttemptedSave }) => {
  const [config, setConfig] = useState<PaymentNodeConfig>(initial);
  latest = config;
  const apply = (fields: Record<string, unknown>) => setConfig(c => ({ ...c, ...fields }));
  return (
    <PaymentTriggersEditor
      node={node}
      config={config}
      updateField={(field, value) => apply({ [field]: value })}
      updateFields={apply}
      protocol={protocol}
      hasAttemptedSave={hasAttemptedSave}
    />
  );
};

describe('triggerPatternAdvice', () => {
  it.each([
    '^premium_',
    'get_(weather|news)$',
    '(?<name>x)',
    '(?i)^premium_',
    '(?s)a.b',
    '(?x)a b',
    '(?U)a+',
    '(?is)abc',
    '(?i:abc)d',
    '(?P<name>abc)',
    '\\\\1',
  ])('has no advice for the gateway-valid pattern %s', p => {
    expect(triggerPatternAdvice(p)).toBeNull();
  });

  it.each(['(?=ahead)', '(?!ahead)x', '(?<=behind)x', '(?<!behind)x', '(a)\\1'])(
    'warns that the gateway has no lookaround or backreferences for %s',
    p => {
      expect(triggerPatternAdvice(p)).toBe(
        'Lookaround and backreferences are not supported by the gateway.'
      );
    }
  );

  it('does not hand a very long pattern to the browser, whatever it holds', () => {
    const advice =
      'This pattern is too long for the browser to check. The gateway checks it when you save.';

    expect(triggerPatternAdvice('a'.repeat(1001))).toBe(advice);
    expect(triggerPatternAdvice('(a+)+$'.repeat(300))).toBe(advice);
    expect(triggerPatternAdvice('a'.repeat(1000))).toBeNull();
  });

  it.each(['(unclosed', 'a)', '[a-'])('says the browser could not read %s', p => {
    expect(triggerPatternAdvice(p)).toBe(
      'The browser could not read this pattern. The gateway checks it when you save.'
    );
  });
});

describe('questionableMcpPatterns', () => {
  it('lists only the MCP patterns the browser doubts', () => {
    expect(
      questionableMcpPatterns({
        mcp_payment_triggers: { mode: 'match', patterns: ['(?i)ok', '(?=x)', '(open', ' '] },
      })
    ).toEqual(['(?=x)', '(open']);
  });

  it('never checks A2A message text, nor a mode that has no patterns', () => {
    expect(
      questionableMcpPatterns({
        a2a_method_filters: [{ method: 'message/send', message_patterns: ['(bad', '(?=x)'] }],
      })
    ).toEqual([]);
    expect(questionableMcpPatterns({ mcp_payment_triggers: { mode: 'all' } })).toEqual([]);
    expect(questionableMcpPatterns(undefined)).toEqual([]);
  });
});

describe('PaymentTriggersEditor — MCP', () => {
  it('switches between all, match and exclude modes', () => {
    render(<Harness protocol="mcp" />);

    const mode = screen.getByTestId('payment-triggers-mcp-mode');
    expect(mode).toHaveValue('all');
    expect(latest).toEqual({});

    fireEvent.change(mode, { target: { value: 'match' } });
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'match', patterns: [] });

    fireEvent.change(mode, { target: { value: 'all' } });
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'all' });
    expect(screen.queryByTestId('payment-triggers-mcp-pattern-0')).not.toBeInTheDocument();

    fireEvent.change(mode, { target: { value: 'exclude' } });
    fireEvent.change(screen.getByTestId('payment-triggers-mcp-pattern-0'), {
      target: { value: '^free_' },
    });
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'exclude', patterns: ['^free_'] });
  });

  it('adds and removes patterns', () => {
    render(
      <Harness
        protocol="mcp"
        initial={{ mcp_payment_triggers: { mode: 'match', patterns: ['a'] } }}
      />
    );

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-add-pattern-button'));
    fireEvent.change(screen.getByTestId('payment-triggers-mcp-pattern-1'), {
      target: { value: 'b' },
    });
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'match', patterns: ['a', 'b'] });

    fireEvent.click(screen.getByTestId('payment-triggers-mcp-remove-pattern-button-0'));
    expect(latest.mcp_payment_triggers).toEqual({ mode: 'match', patterns: ['b'] });
  });

  it('warns about a pattern the browser doubts and keeps the pattern editable', () => {
    render(
      <Harness
        protocol="mcp"
        initial={{ mcp_payment_triggers: { mode: 'match', patterns: ['ok', '(?=x)'] } }}
      />
    );

    expect(screen.queryByTestId('payment-triggers-mcp-pattern-warning-0')).not.toBeInTheDocument();
    expect(screen.getByTestId('payment-triggers-mcp-pattern-warning-1')).toHaveTextContent(
      'Lookaround and backreferences are not supported by the gateway.'
    );
    expect(screen.getByTestId('payment-triggers-mcp-pattern-1')).not.toHaveClass('is-invalid');
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('shows no warning for a pattern written in the gateway syntax', () => {
    render(
      <Harness
        protocol="mcp"
        initial={{ mcp_payment_triggers: { mode: 'match', patterns: ['(?i)^premium_'] } }}
      />
    );

    expect(screen.getByTestId('payment-triggers-mcp-pattern-0')).toHaveValue('(?i)^premium_');
    expect(screen.queryByTestId('payment-triggers-mcp-pattern-warning-0')).not.toBeInTheDocument();
  });

  it('requires a pattern for Match after a save attempt', () => {
    render(
      <Harness
        protocol="mcp"
        hasAttemptedSave
        initial={{ mcp_payment_triggers: { mode: 'match', patterns: [' '] } }}
      />
    );

    expect(screen.getByTestId('payment-triggers-mcp-error')).toHaveTextContent(
      'At least one tool pattern is required'
    );
  });

  it('does not require a pattern when no trigger is set, or for exclude', () => {
    const { unmount } = render(<Harness protocol="mcp" hasAttemptedSave />);
    expect(screen.queryByTestId('payment-triggers-mcp-error')).not.toBeInTheDocument();
    unmount();

    render(
      <Harness
        protocol="mcp"
        hasAttemptedSave
        initial={{ mcp_payment_triggers: { mode: 'exclude', patterns: [] } }}
      />
    );
    expect(screen.queryByTestId('payment-triggers-mcp-error')).not.toBeInTheDocument();
  });

  it('says every tool call is charged while no trigger is set, without writing one', () => {
    render(<Harness protocol="mcp" />);

    expect(screen.getByTestId('payment-triggers-mcp-scope')).toHaveTextContent(
      'No trigger is set, so every tools/call on this surface will require payment.'
    );
    expect(latest).toEqual({});
  });

  it('describes a chosen trigger without the no-trigger wording', () => {
    render(<Harness protocol="mcp" initial={{ mcp_payment_triggers: { mode: 'all' } }} />);

    expect(screen.getByTestId('payment-triggers-mcp-scope')).toHaveTextContent(
      'Every tools/call on this surface will require payment.'
    );
    expect(screen.getByTestId('payment-triggers-mcp-scope')).not.toHaveTextContent('No trigger');
  });

  it('disables the triggers while every request is charged', () => {
    render(<Harness protocol="mcp" />);

    fireEvent.click(screen.getByTestId('payment-triggers-require-all'));
    expect(latest.require_all).toBe(true);
    expect(screen.getByTestId('payment-triggers-mcp-mode')).toBeDisabled();
  });
});

describe('PaymentTriggersEditor — A2A', () => {
  it('does not change the config when it is opened, and says what is charged', () => {
    render(<Harness protocol="a2a" />);

    expect(latest).toEqual({});
    expect(screen.getByTestId('payment-triggers-a2a-defaults-note')).toHaveTextContent(
      'No filters set: message/send and message/stream are charged.'
    );
    expect(screen.getByTestId('payment-triggers-a2a-message-send-scope')).toHaveTextContent(
      'Every message/send message is charged, because no text is set.'
    );
    expect(screen.getByTestId('payment-triggers-a2a-message-stream-scope')).toHaveTextContent(
      'Every message/stream message is charged, because no text is set.'
    );
  });

  it('writes the default filters only when asked to', () => {
    render(<Harness protocol="a2a" />);

    fireEvent.click(screen.getByTestId('payment-triggers-a2a-add-defaults-button'));

    expect(latest.a2a_method_filters).toEqual([
      { method: 'message/send', message_patterns: [] },
      { method: 'message/stream', message_patterns: [] },
    ]);
    expect(screen.queryByTestId('payment-triggers-a2a-defaults-note')).not.toBeInTheDocument();
  });

  it('keeps both message methods charged when text is added while nothing is set', () => {
    render(<Harness protocol="a2a" />);

    fireEvent.change(screen.getByTestId('payment-triggers-a2a-message-send-pattern-0'), {
      target: { value: 'refund' },
    });

    expect(latest.a2a_method_filters).toEqual([
      { method: 'message/send', message_patterns: ['refund'] },
      { method: 'message/stream', message_patterns: [] },
    ]);
  });

  it('keeps the message methods charged when a control method is added while nothing is set', () => {
    render(<Harness protocol="a2a" />);

    fireEvent.click(screen.getByTestId('payment-triggers-a2a-control-toggle-button'));
    fireEvent.click(screen.getByTestId('payment-triggers-a2a-method-tasks-get'));

    expect(latest.a2a_method_filters?.map(f => f.method)).toEqual([
      'message/send',
      'message/stream',
      'tasks/get',
    ]);
  });

  it('edits the text of a message method', () => {
    render(
      <Harness
        protocol="a2a"
        initial={{ a2a_method_filters: [{ method: 'message/send', message_patterns: [] }] }}
      />
    );

    fireEvent.click(screen.getByTestId('payment-triggers-a2a-message-send-add-pattern-button'));
    expect(screen.getByTestId('payment-triggers-a2a-message-send-pattern-1')).toHaveValue('');
    fireEvent.change(screen.getByTestId('payment-triggers-a2a-message-send-pattern-0'), {
      target: { value: 'refund' },
    });
    expect(latest.a2a_method_filters).toEqual([
      { method: 'message/send', message_patterns: ['refund', ''] },
    ]);
  });

  it('says a message method outside the filters is not charged', () => {
    render(
      <Harness
        protocol="a2a"
        initial={{ a2a_method_filters: [{ method: 'message/send', message_patterns: [] }] }}
      />
    );

    expect(screen.queryByTestId('payment-triggers-a2a-defaults-note')).not.toBeInTheDocument();
    expect(screen.getByTestId('payment-triggers-a2a-message-stream-scope')).toHaveTextContent(
      'message/stream is not charged, because it is not in the filters.'
    );
  });

  it('says every message is charged until some text is set', () => {
    render(
      <Harness
        protocol="a2a"
        initial={{
          a2a_method_filters: [
            { method: 'message/send', message_patterns: [] },
            { method: 'message/stream', message_patterns: [] },
          ],
        }}
      />
    );

    const send = screen.getByTestId('payment-triggers-a2a-message-send-scope');
    const stream = screen.getByTestId('payment-triggers-a2a-message-stream-scope');
    expect(send).toHaveTextContent(
      'Every message/send message is charged, because no text is set.'
    );

    fireEvent.change(screen.getByTestId('payment-triggers-a2a-message-send-pattern-0'), {
      target: { value: 'refund' },
    });
    expect(send).toHaveTextContent(
      'Only message/send messages containing one of these texts are charged.'
    );
    expect(stream).toHaveTextContent('Every message/stream message is charged');

    fireEvent.change(screen.getByTestId('payment-triggers-a2a-message-send-pattern-0'), {
      target: { value: '   ' },
    });
    expect(send).toHaveTextContent('Every message/send message is charged');
  });

  it('labels the rows as text a message contains and never treats them as a regex', () => {
    render(
      <Harness
        protocol="a2a"
        initial={{
          a2a_method_filters: [{ method: 'message/send', message_patterns: ['(bad', '(?=x)'] }],
        }}
      />
    );

    const first = screen.getByTestId('payment-triggers-a2a-message-send-pattern-0');
    const second = screen.getByTestId('payment-triggers-a2a-message-send-pattern-1');
    expect(first).toHaveValue('(bad');
    expect(first).toHaveAttribute('aria-label', 'Text 1');
    expect(second).toHaveValue('(?=x)');
    expect(second).toHaveAttribute('aria-label', 'Text 2');
    expect(
      screen.getByTestId('payment-triggers-a2a-message-send-add-pattern-button')
    ).toHaveTextContent('Add Text');
    expect(screen.queryByTestId('payment-triggers-a2a-message-send-pattern-warning-0')).toBeNull();
    expect(screen.queryByTestId('payment-triggers-a2a-message-send-pattern-warning-1')).toBeNull();
    expect(screen.getByTestId('payment-triggers-editor')).toHaveTextContent(
      'matched as plain, case-sensitive text, not as a regular expression'
    );
  });

  it('toggles control methods', () => {
    render(
      <Harness
        protocol="a2a"
        initial={{ a2a_method_filters: [{ method: 'message/send', message_patterns: [] }] }}
      />
    );

    fireEvent.click(screen.getByTestId('payment-triggers-a2a-control-toggle-button'));
    fireEvent.click(screen.getByTestId('payment-triggers-a2a-method-tasks-get'));
    expect(latest.a2a_method_filters).toContainEqual({
      method: 'tasks/get',
      message_patterns: [],
    });

    fireEvent.click(screen.getByTestId('payment-triggers-a2a-method-tasks-get'));
    expect(latest.a2a_method_filters?.map(f => f.method)).not.toContain('tasks/get');
  });
});

describe('describeTriggers', () => {
  it('states the effective behaviour when nothing is set', () => {
    expect(describeTriggers({}, 'mcp')).toBe('No trigger is set: every tool call is charged');
    expect(describeTriggers({}, 'a2a')).toBe(
      'No filters set: message/send and message/stream are charged'
    );
    expect(describeTriggers({ a2a_method_filters: [] }, 'a2a')).toBe(
      'No filters set: message/send and message/stream are charged'
    );
  });

  it('describes chosen triggers', () => {
    expect(describeTriggers({ require_all: true }, 'mcp')).toBe('Every request is charged');
    expect(describeTriggers({ mcp_payment_triggers: { mode: 'all' } }, 'mcp')).toBe(
      'Every tool call is charged'
    );
    expect(
      describeTriggers({ mcp_payment_triggers: { mode: 'match', patterns: ['a', ' '] } }, 'mcp')
    ).toBe('Tools matching 1 pattern');
    expect(describeTriggers({ mcp_payment_triggers: { mode: 'match', patterns: [] } }, 'mcp')).toBe(
      'Match needs at least one pattern'
    );
    expect(
      describeTriggers(
        { a2a_method_filters: [{ method: 'message/send', message_patterns: [] }] },
        'a2a'
      )
    ).toBe('1 A2A method charged');
  });
});

describe('mcpMatchHasNoPatterns', () => {
  it('is true only for a Match trigger without a non-blank pattern', () => {
    expect(mcpMatchHasNoPatterns({ mode: 'match', patterns: [] })).toBe(true);
    expect(mcpMatchHasNoPatterns({ mode: 'match', patterns: ['  '] })).toBe(true);
    expect(mcpMatchHasNoPatterns({ mode: 'match', patterns: ['a'] })).toBe(false);
    expect(mcpMatchHasNoPatterns({ mode: 'exclude', patterns: [] })).toBe(false);
    expect(mcpMatchHasNoPatterns({ mode: 'all' })).toBe(false);
    expect(mcpMatchHasNoPatterns(undefined)).toBe(false);
  });
});
