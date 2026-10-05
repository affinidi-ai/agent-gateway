import type { CopilotDirectLineBackend } from './types';

export const A2A_PROXY_BACKEND_LABELS: Record<CopilotDirectLineBackend['kind'], string> = {
  copilot_direct_line: 'Copilot Direct Line',
};

export const A2A_PROXY_BACKEND_DESCRIPTIONS: Record<CopilotDirectLineBackend['kind'], string> = {
  copilot_direct_line: 'Adapt A2A message/send requests to Microsoft Direct Line.',
};

export function getA2aProxyBackendLabel(kind: CopilotDirectLineBackend['kind']): string {
  return A2A_PROXY_BACKEND_LABELS[kind] || kind;
}
