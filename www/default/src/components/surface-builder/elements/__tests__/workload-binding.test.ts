import {
  defaultWorkloadBindingConfig,
  validateWorkloadBinding,
  workloadBindingApiToForm,
  workloadBindingFormToApi,
} from '../workload-binding/config';
import type { WorkloadBindingFormConfig } from '../workload-binding/config';

describe('workload-binding config converters', () => {
  it('default config is a disabled transit-token binding', () => {
    expect(defaultWorkloadBindingConfig()).toEqual({
      enabled: false,
      caller_source: 'transit_token',
      caller_context_fields: [],
      chain_caller_credentials: false,
    });
  });

  it('omits the wire value entirely when disabled', () => {
    const cfg = defaultWorkloadBindingConfig();
    expect(workloadBindingFormToApi(cfg)).toBeUndefined();
    expect(workloadBindingFormToApi(null)).toBeUndefined();
  });

  it('serializes an enabled binding with allowlisted caller fields', () => {
    const cfg: WorkloadBindingFormConfig = {
      enabled: true,
      caller_source: 'transit_token',
      caller_context_fields: ['sub', 'email'],
      chain_caller_credentials: false,
    };
    expect(workloadBindingFormToApi(cfg)).toEqual({
      enabled: true,
      caller_source: 'transit_token',
      caller_context_fields: ['sub', 'email'],
    });
  });

  it('omits caller_context_fields when empty and chain flag when false', () => {
    const cfg: WorkloadBindingFormConfig = {
      enabled: true,
      caller_source: 'authorization_bearer_jwt',
      caller_context_fields: [],
      chain_caller_credentials: false,
    };
    const api = workloadBindingFormToApi(cfg)!;
    expect(api).toEqual({ enabled: true, caller_source: 'authorization_bearer_jwt' });
    expect('caller_context_fields' in api).toBe(false);
    expect('chain_caller_credentials' in api).toBe(false);
  });

  it('includes chain flag only when enabled', () => {
    const cfg: WorkloadBindingFormConfig = {
      enabled: true,
      caller_source: 'transit_token',
      caller_context_fields: ['sub'],
      chain_caller_credentials: true,
    };
    expect(workloadBindingFormToApi(cfg)).toEqual({
      enabled: true,
      caller_source: 'transit_token',
      caller_context_fields: ['sub'],
      chain_caller_credentials: true,
    });
  });

  it('never emits legacy agent_fields / user_fields / mask shape', () => {
    const cfg: WorkloadBindingFormConfig = {
      enabled: true,
      caller_source: 'transit_token',
      caller_context_fields: ['sub'],
      chain_caller_credentials: false,
    };
    const api = workloadBindingFormToApi(cfg)!;
    expect('agent_fields' in api).toBe(false);
    expect('user_fields' in api).toBe(false);
    expect('mask' in api).toBe(false);
  });

  it('hydrates the wire shape back into form state', () => {
    const form = workloadBindingApiToForm({
      enabled: true,
      caller_source: 'authorization_bearer_jwt',
      caller_context_fields: ['sub', 'iss'],
      chain_caller_credentials: true,
    });
    expect(form).toEqual({
      enabled: true,
      caller_source: 'authorization_bearer_jwt',
      caller_context_fields: ['sub', 'iss'],
      chain_caller_credentials: true,
    });
  });

  it('hydrates a null/missing value to the default config', () => {
    expect(workloadBindingApiToForm(null)).toEqual(defaultWorkloadBindingConfig());
    expect(workloadBindingApiToForm(undefined)).toEqual(defaultWorkloadBindingConfig());
  });

  it('normalizes an unknown caller_source to transit_token', () => {
    const form = workloadBindingApiToForm({ enabled: true, caller_source: 'nonsense' });
    expect(form.caller_source).toBe('transit_token');
  });

  it('round-trips a did caller_source through form → api → form', () => {
    const cfg: WorkloadBindingFormConfig = {
      enabled: true,
      caller_source: 'did',
      caller_context_fields: ['did'],
      chain_caller_credentials: false,
    };
    const api = workloadBindingFormToApi(cfg)!;
    expect(api).toEqual({
      enabled: true,
      caller_source: 'did',
      caller_context_fields: ['did'],
    });
    expect(workloadBindingApiToForm(api)).toEqual(cfg);
  });

  it('round-trips form → api → form', () => {
    const cfg: WorkloadBindingFormConfig = {
      enabled: true,
      caller_source: 'authorization_bearer_jwt',
      caller_context_fields: ['sub', 'email'],
      chain_caller_credentials: true,
    };
    const api = workloadBindingFormToApi(cfg)!;
    expect(workloadBindingApiToForm(api)).toEqual(cfg);
  });

  describe('validation', () => {
    const base = (fields: string[]): WorkloadBindingFormConfig => ({
      enabled: true,
      caller_source: 'transit_token',
      caller_context_fields: fields,
      chain_caller_credentials: false,
    });

    it('accepts arbitrary allowlisted claim names', () => {
      expect(validateWorkloadBinding(base(['sub', 'custom_org_claim', 'role']))).toEqual([]);
    });

    it('rejects a blank caller field', () => {
      const errs = validateWorkloadBinding(base(['sub', '  ']));
      expect(errs).toHaveLength(1);
      expect(errs[0].message).toMatch(/blank/i);
    });

    it('rejects nested path syntax', () => {
      const errs = validateWorkloadBinding(base(['profile.email']));
      expect(errs).toHaveLength(1);
      expect(errs[0].message).toMatch(/nested path/i);
    });

    it('rejects duplicate caller fields', () => {
      const errs = validateWorkloadBinding(base(['sub', 'sub']));
      expect(errs).toHaveLength(1);
      expect(errs[0].message).toMatch(/duplicate/i);
    });
  });
});
