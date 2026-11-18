import { apiClient } from '../../api';

export interface SimulateResult {
  allow: boolean;
  reason?: string;
  policy_type: string;
  version?: number;
  content_hash: string;
  query: string;
}

/** Pull the `error` field out of a JSON error body; falls back to the raw text. */
const extractErrorMessage = (body: string): string => {
  try {
    const parsed = JSON.parse(body) as { error?: string };
    return parsed.error ?? body;
  } catch {
    return body;
  }
};

/**
 * Dry-run Rego against one input via `POST /policy-definitions/{id}/simulate`, without
 * touching any runtime engine or live traffic. `policy` replaces the stored Rego.
 */
export async function simulatePolicy(
  policyId: string,
  policyType: 'gateway' | 'agent_surface',
  policy: string,
  input: unknown
): Promise<SimulateResult> {
  const resp = await apiClient.fetch(
    `/api/v1/policy-definitions/${encodeURIComponent(policyId)}/simulate`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input, policy, policy_type: policyType }),
    }
  );
  if (!resp.ok) {
    const detail = await resp.text().catch(() => '');
    throw new Error(extractErrorMessage(detail) || `Dry-run failed: ${resp.statusText}`);
  }
  return (await resp.json()) as SimulateResult;
}
