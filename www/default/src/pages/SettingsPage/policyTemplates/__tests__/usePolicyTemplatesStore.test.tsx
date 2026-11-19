import React from 'react';
import { act, renderHook, waitFor } from '@testing-library/react';
import {
  PolicyTemplateServicesContext,
  type PolicyTemplateServices,
} from '../policyTemplateServices';
import type { PolicyTemplateStore } from '../policyTemplateStore';
import { usePolicyTemplates } from '../usePolicyTemplates';
import type { PolicyTemplate, PolicyType } from '../types';

const template = (name: string, builtin: boolean): PolicyTemplate => ({
  id: builtin ? `${name}:agent_surface` : `org:${name}`,
  name,
  summary: '',
  description: '',
  category: 'baseline',
  policy_type: 'agent_surface',
  rego: 'package surface.policy\n\ndefault allow := false\n',
  parameters: [],
  reads: [],
  examples: [],
  builtin,
});

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(r => (resolve = r));
  return { promise, resolve };
}

function renderWithStore(store: PolicyTemplateStore, policyType: PolicyType = 'agent_surface') {
  const services: PolicyTemplateServices = {
    store,
    notifyUndo: jest.fn(),
    simulate: jest.fn(),
  };
  const wrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
    <PolicyTemplateServicesContext.Provider value={services}>
      {children}
    </PolicyTemplateServicesContext.Provider>
  );
  return renderHook(({ type }) => usePolicyTemplates(type), {
    wrapper,
    initialProps: { type: policyType },
  });
}

describe('usePolicyTemplates with a provided store', () => {
  it('lists the provided store, split into built-in and organisation templates', async () => {
    const store: PolicyTemplateStore = {
      list: jest.fn().mockResolvedValue([template('a', true), template('b', false)]),
      save: jest.fn(),
      subscribe: () => () => {},
    };
    const { result } = renderWithStore(store);
    expect(result.current.loading).toBe(true);
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.builtin.map(t => t.name)).toEqual(['a']);
    expect(result.current.organization.map(t => t.name)).toEqual(['b']);
    expect(store.list).toHaveBeenCalledWith('agent_surface');
  });

  it('lists again when the store says it changed, and drops a list a newer one overtook', async () => {
    const first = deferred<PolicyTemplate[]>();
    const second = deferred<PolicyTemplate[]>();
    let notify = () => {};
    const store: PolicyTemplateStore = {
      list: jest.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise),
      save: jest.fn(),
      subscribe: listener => {
        notify = listener;
        return () => {};
      },
    };
    const { result } = renderWithStore(store);

    act(() => notify());
    await act(async () => second.resolve([template('newer', true)]));
    await act(async () => first.resolve([template('older', true)]));

    expect(result.current.builtin.map(t => t.name)).toEqual(['newer']);
    expect(result.current.loading).toBe(false);
  });

  it('shows the error of a list that fails', async () => {
    const store: PolicyTemplateStore = {
      list: jest.fn().mockRejectedValue(new Error('Templates are unavailable')),
      save: jest.fn(),
      subscribe: () => () => {},
    };
    const { result } = renderWithStore(store);
    await waitFor(() => expect(result.current.error).toBe('Templates are unavailable'));
    expect(result.current.builtin).toEqual([]);
  });

  it('stops listening to the store on unmount', async () => {
    const unsubscribe = jest.fn();
    const store: PolicyTemplateStore = {
      list: jest.fn().mockResolvedValue([]),
      save: jest.fn(),
      subscribe: () => unsubscribe,
    };
    const { unmount, result } = renderWithStore(store);
    await waitFor(() => expect(result.current.loading).toBe(false));
    unmount();
    expect(unsubscribe).toHaveBeenCalledTimes(1);
  });
});
