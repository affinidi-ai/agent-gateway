import React from 'react';
import CaptureStep from '../../../onboard/CaptureStep';
import { extractAgentIdentitySchema } from '../../../../utils/schemaUtils';
import { showToast } from '../../../../utils/toaster';

export type SupportedProtocol = 'a2a' | 'ap2' | 'mcp';

interface Props {
  metaField: string;
  protocol: SupportedProtocol;
  onSchemaAdopted: (schema: any) => void;
  onCancel: () => void;
}

/**
 * Onboarding entry surfaced inside the Agent Identity fullscreen editor.
 * Reuses the channel-onboarding `CaptureStep` (skipping the wizard's
 * protocol-selector step because the surface already pins the protocol)
 * and, when the user clicks "Use This Schema", extracts the protocol-native
 * identity payload schema from the captured payload and hands it back to the
 * parent panel for adoption.
 */
const IdentityOnboardingView: React.FC<Props> = ({
  metaField,
  protocol,
  onSchemaAdopted,
  onCancel,
}) => {
  const handleCaptured = (payload: any) => {
    try {
      const serialized = extractAgentIdentitySchema(payload, metaField, protocol);
      const schema = JSON.parse(serialized);
      onSchemaAdopted(schema);
    } catch (e: any) {
      showToast('error', e?.message || 'Failed to extract identity schema from payload');
    }
  };

  return (
    <>
      <p className="text-muted small mb-3">
        Capture a real request from your agent so the gateway can learn its identity payload
        automatically. You&apos;ll pick which fields identify the agent in the next step.
      </p>
      <CaptureStep bare protocol={protocol} onPayloadCaptured={handleCaptured} onBack={onCancel} />
    </>
  );
};

export default IdentityOnboardingView;
