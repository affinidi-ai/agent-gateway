import {
  networkingConfigFromWire,
  networkingConfigToWire,
  networkingDefinition,
} from '../networking/definition';

const incomplete = (c: any) => networkingDefinition.incompleteReason!(c);

describe('networking configFromPayload', () => {
  it('is registered on the definition', () => {
    expect(networkingDefinition.configFromPayload).toBeDefined();
  });

  it('hydrates the exact shape Boris sends', () => {
    const wire = {
      timeout: { request_secs: 30, connect_secs: 5, idle_secs: 90 },
      retry: { max_attempts: 3, backoff_multiplier: 2 },
      circuit_breaker: { failure_threshold: 5, timeout_secs: 30 },
    };
    const flat = networkingDefinition.configFromPayload!(wire);
    expect(flat).toEqual({
      timeout_secs: '30',
      connect_timeout_secs: '5',
      idle_timeout_secs: '90',
      retry_enabled: true,
      retry_max: '3',
      retry_backoff_multiplier: '2',
      circuit_breaker_enabled: true,
      cb_threshold: '5',
      cb_recovery_secs: '30',
    });
    expect(incomplete(flat)).toBeNull();
    expect(networkingConfigToWire(flat)).toEqual(wire);
  });

  it('round-trips a full wire payload including mirror and status codes', () => {
    const wire = {
      timeout: { request_secs: 20, connect_secs: 4, idle_secs: 60 },
      retry: {
        max_attempts: 4,
        initial_backoff_ms: 100,
        max_backoff_ms: 5000,
        backoff_multiplier: 1.5,
        retryable_status_codes: [502, 503],
      },
      circuit_breaker: {
        failure_threshold: 6,
        timeout_secs: 45,
        success_threshold: 2,
        window_secs: 60,
      },
      mirror: {
        endpoint: 'https://shadow.example',
        percentage: 25,
        wait_for_response: false,
        timeout_secs: 5,
      },
    };
    const flat = networkingConfigFromWire(wire);
    expect(flat.mirror_async).toBe(true);
    expect(networkingConfigToWire(flat)).toEqual(wire);
  });

  it('round-trips representative flat configs', () => {
    const flats = [
      { timeout_secs: '30' },
      { retry_enabled: true, retry_max: '2', retry_status_codes: '502,503' },
      {
        circuit_breaker_enabled: true,
        cb_threshold: '7',
        cb_recovery_secs: '10',
        cb_window_secs: '20',
      },
      {
        mirror_enabled: true,
        mirror_endpoint: 'https://m.example',
        mirror_percentage: '50',
        mirror_async: false,
        mirror_timeout_secs: '3',
      },
    ];
    for (const x of flats) {
      expect(networkingConfigFromWire(networkingConfigToWire(x))).toEqual(x);
    }
  });

  it('keeps empty and missing payloads incomplete, without invented defaults', () => {
    for (const w of [undefined, null, {}, 'x']) {
      const flat = networkingDefinition.configFromPayload!(w);
      expect(flat).toEqual({});
      expect(incomplete(flat)).not.toBeNull();
    }
  });
});
