import React from 'react';
import { AppButton } from '../shared/AppButton';
import { AUDIT_PAYLOAD_TYPES } from '../../utils/auditIntegrations';

interface AuditIntegrationCardProps {
  type: string;
  onUseTemplate: () => void;
  disabled?: boolean;
}

/** Explains what a Governance Audit integration receives and offers the audit payload template. */
const AuditIntegrationCard: React.FC<AuditIntegrationCardProps> = ({
  type,
  onUseTemplate,
  disabled = false,
}) => (
  <div className="card shadow mb-4" data-testid="integration-audit-card">
    <div className="card-header py-3">
      <h6 className="m-0 font-weight-bold text-primary">
        <i className="fas fa-clipboard-list me-2" aria-hidden="true"></i>
        Governance Audit
      </h6>
    </div>
    <div className="card-body" style={{ fontSize: '0.9em' }}>
      <p className="mb-2" data-testid="integration-audit-scope-note">
        Only the events selected under &ldquo;Events to send&rdquo; are sent here, whether or not
        the VP Audit Log keeps them.
      </p>
      <p className="mb-2">
        Use{' '}
        <code>
          ${'{'}AUDIT_RECORD{'}'}
        </code>{' '}
        as a whole JSON value to send the full record, including its signed VP, as a JSON object.{' '}
        <code>EVENT_TYPE</code> is <code>audit.&lt;category&gt;</code>.
      </p>
      <p className="mb-2">
        Only users with the <code>audit.view</code> permission can see or change these integrations,
        and they always apply to the whole appliance.
      </p>
      <p className="mb-2" data-testid="integration-audit-volume-note">
        Every record is one delivery. Email and Slack work too, but send one message per record, so
        prefer Stream or Webhook for busy appliances.
      </p>
      <p className="mb-2 text-warning" data-testid="integration-audit-data-warning">
        <i className="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>
        Records leave the appliance with the caller&rsquo;s email and name, request details and the
        signed VP (<code>AUDIT_RECORD</code>, <code>AUDIT_VP_JWT</code>). Send them only to a
        destination cleared for that data.
      </p>
      <p className="mb-0" data-testid="integration-audit-delivery-note">
        Records are delivered at least once, so a record may arrive again after a restart;
        deduplicate on <code>event_id</code>. If the destination stops accepting records, it falls
        behind and catches up in order once it recovers; its oldest records are skipped only when
        the backlog grows past its cap. Disabling the integration pauses it: it lets go of the
        records it has not received, and once re-enabled it receives only new records. Skipped
        records are counted by <code>agent_gateway_audit_sink_skipped_total</code>.
      </p>
      {AUDIT_PAYLOAD_TYPES.includes(type) && (
        <AppButton
          variant="outline-primary"
          className="w-100 mt-3"
          onClick={onUseTemplate}
          disabled={disabled}
          data-testid="integration-audit-template-button"
          iconStart={<i className="fas fa-file-import me-1" aria-hidden="true"></i>}
        >
          Use audit record template
        </AppButton>
      )}
    </div>
  </div>
);

export default AuditIntegrationCard;
