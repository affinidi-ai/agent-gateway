import React from 'react';

interface AgentCardLocationHelpProps {
  endpoint?: string | null;
  customPath?: string | null;
}

function endpointOrigin(endpoint: string): string {
  try {
    return new URL(endpoint).origin;
  } catch {
    return endpoint;
  }
}

export const DEFAULT_AGENT_CARD_PATH = '.well-known/agent-card.json';

/** Canonical "what is an agent card" explainer for Access Point's own
 * agent-card location field. (Transit Point only reuses the
 * `AgentCardLocationHelp` preview component below, not this explainer text,
 * since it resolves a different agent's card for a different reason.) */
export const AGENT_CARD_EXPLAINER =
  'An agent card is a small file describing your agent: its name, capabilities, and how to ' +
  'talk to it.';

export const AgentCardLocationHelp: React.FC<AgentCardLocationHelpProps> = ({
  endpoint,
  customPath,
}) => {
  const target = typeof endpoint === 'string' ? endpoint : '';
  const path = customPath || DEFAULT_AGENT_CARD_PATH;
  const pathWithSlash = path.startsWith('/') ? path : `/${path}`;

  if (target.startsWith('http://') || target.startsWith('https://')) {
    return (
      <>
        Agent card will be fetched from: <code>{`${endpointOrigin(target)}${pathWithSlash}`}</code>
      </>
    );
  }

  return <>Path relative to configured endpoint origin (e.g., {path})</>;
};
