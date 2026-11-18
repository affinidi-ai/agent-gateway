import React from 'react';

interface PolicySectionTitleProps {
  /** Step number, shown on the create form only. */
  step?: number;
  title: string;
  /** Shown on the right of the title row. */
  children?: React.ReactNode;
}

/** The title row of a policy editor section. */
const PolicySectionTitle: React.FC<PolicySectionTitleProps> = ({ step, title, children }) => (
  <div className="policy-section-title">
    <h6 className="m-0 font-weight-bold">
      {step !== undefined && (
        <span className="policy-section-title__step" aria-hidden="true">
          {step}
        </span>
      )}
      {title}
    </h6>
    {children && <div className="policy-section-title__actions">{children}</div>}
  </div>
);

export default PolicySectionTitle;
