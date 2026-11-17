import React from 'react';
import { agentName } from './delegatedAccess';

/**
 * An agent as both delegation tabs show it: its name in one chip, with the whole DID as the
 * tooltip. A long name wraps after a dot or a slash, and inside a word only when one part is
 * wider than the cell.
 */
const AgentName: React.FC<{ did: string }> = ({ did }) => {
  const name = agentName(did);
  const parts = name.match(/[^./]*[./]|[^./]+$/g) ?? [name];
  return (
    <code className="d-inline-block text-muted text-break" title={did}>
      {parts.map((part, index) => (
        <React.Fragment key={index}>
          {index > 0 && <wbr />}
          {part}
        </React.Fragment>
      ))}
    </code>
  );
};

export default AgentName;
