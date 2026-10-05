import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Badge } from '../../components/shared/Badge';
import { EmptyState } from '../../components/shared/EmptyState';
import { DOCS_URL } from '../../config/docs';

interface PaywallPoliciesTabProps {
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
}

const PaywallPoliciesTab: React.FC<PaywallPoliciesTabProps> = ({ onFilteredCountChange }) => {
  const navigate = useNavigate();

  useEffect(() => {
    onFilteredCountChange?.(0);
  }, [onFilteredCountChange]);

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-credit-card"></i> Paywall Policies
          <Badge value={0} tone="primary" className="ms-2" ariaLabel="0 paywall policies" />
        </h6>
      </div>
      <div className="card-body">
        <EmptyState
          icon="fa-credit-card"
          title="No paywall policies yet"
          body="Paywall policies attach x402 (a pay-per-request protocol) pricing to surfaces. Add an Agent Surface with a paywall to start charging for access."
          docsHref={DOCS_URL.payments}
          ctaLabel="Add Agent Surface"
          onCtaClick={() => navigate('/surfaces')}
        />
      </div>
    </div>
  );
};

export default PaywallPoliciesTab;
