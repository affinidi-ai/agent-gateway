import React, { useEffect, useState } from 'react';
import { getIssuers } from '../../../../utils/issuersCache';
import InfoBanner from '../../../shared/InfoBanner';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';

export type SurfaceIssuerProblem = 'unset' | 'deleted';

const WARNING_COPY: Record<SurfaceIssuerProblem, { title: string; action: string }> = {
  unset: {
    title: 'No Issuer is selected for this surface',
    action: "Select one in the Surface's Issuer setting.",
  },
  deleted: {
    title: "This surface's Issuer no longer exists",
    action: "Select an existing Issuer in the Surface's Issuer setting.",
  },
};

async function issuerExists(issuerId: string): Promise<boolean> {
  let issuers = await getIssuers();
  if (!issuers.some(issuer => issuer.id === issuerId)) {
    issuers = await getIssuers({ refresh: true });
  }
  return issuers.some(issuer => issuer.id === issuerId);
}

/**
 * The reason the surface being edited has no usable Issuer, or null. A selected Issuer is
 * reported as deleted only once the Issuer list has loaded without it; a failed or pending
 * load never warns.
 */
export function useSurfaceIssuerProblem(): SurfaceIssuerProblem | null {
  const meta = useOptionalSurfaceMeta();
  const issuerId = meta?.issuerId ?? '';
  const [deletedIssuerId, setDeletedIssuerId] = useState<string | null>(null);

  useEffect(() => {
    if (!issuerId) return undefined;
    let cancelled = false;
    issuerExists(issuerId)
      .then(exists => {
        if (!cancelled) setDeletedIssuerId(exists ? null : issuerId);
      })
      .catch(() => {
        if (!cancelled) setDeletedIssuerId(null);
      });
    return () => {
      cancelled = true;
    };
  }, [issuerId]);

  if (!meta) return null;
  if (!issuerId) return 'unset';
  return deletedIssuerId === issuerId ? 'deleted' : null;
}

interface NoSurfaceIssuerWarningProps {
  testid: string;
  problem: SurfaceIssuerProblem;
  children: React.ReactNode;
}

const NoSurfaceIssuerWarning: React.FC<NoSurfaceIssuerWarningProps> = ({
  testid,
  problem,
  children,
}) => (
  <div role="status" data-testid={testid}>
    <InfoBanner
      title={WARNING_COPY[problem].title}
      icon="fa-exclamation-triangle"
      variant="warning"
      collapsible={false}
      className="mt-2"
      summary={
        <>
          {children} {WARNING_COPY[problem].action}
        </>
      }
    />
  </div>
);

export default NoSurfaceIssuerWarning;
