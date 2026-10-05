import React from 'react';

/**
 * Inline "Add <thing>" shortcut link that always opens in a new tab so the
 * user doesn't lose the in-progress form / wizard state they came from.
 *
 * Locked verb rulebook (see .changelog/wip):
 *  - On-product destinations use `Add <thing>` (e.g. "Add API key").
 *  - External destinations use `Open <thing>` (e.g. "Open Agent-Pay").
 */
interface AddResourceLinkProps {
  /** Absolute in-app path (e.g. `/surfaces/new`) or full external URL. */
  to: string;
  /** Link label (typically `Add <thing>` or `Open <thing>`). */
  children: React.ReactNode;
  /** Optional test id for RTL. */
  testid?: string;
  /** Optional extra classes (e.g. `alert-link`, `fw-bold`). */
  className?: string;
}

const AddResourceLink: React.FC<AddResourceLinkProps> = ({ to, children, testid, className }) => (
  <a href={to} target="_blank" rel="noreferrer noopener" className={className} data-testid={testid}>
    {children}
  </a>
);

export default AddResourceLink;
