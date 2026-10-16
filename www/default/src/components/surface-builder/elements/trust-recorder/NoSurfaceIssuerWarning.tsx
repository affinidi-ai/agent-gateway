import React from 'react';
import InfoBanner from '../../../shared/InfoBanner';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';

/** True while a surface is being edited and no Issuer is selected for it. */
export function useSurfaceIssuerMissing(): boolean {
  const meta = useOptionalSurfaceMeta();
  return !!meta && !meta.issuerId;
}

interface NoSurfaceIssuerWarningProps {
  testid: string;
  children: React.ReactNode;
}

const NoSurfaceIssuerWarning: React.FC<NoSurfaceIssuerWarningProps> = ({ testid, children }) => (
  <div role="status" data-testid={testid}>
    <InfoBanner
      title="No Issuer is selected for this surface"
      icon="fa-exclamation-triangle"
      variant="warning"
      collapsible={false}
      className="mt-2"
      summary={<>{children} Select one in the Surface&apos;s Issuer setting.</>}
    />
  </div>
);

export default NoSurfaceIssuerWarning;
