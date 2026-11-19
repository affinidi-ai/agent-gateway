import React from 'react';

interface PolicySectionTitleProps {
  title: string;
  /** Font Awesome icon class, e.g. `fa-key`. */
  icon: string;
  /** Shown on the right of the title row. */
  children?: React.ReactNode;
}

/** The title row of a policy editor section. */
const PolicySectionTitle: React.FC<PolicySectionTitleProps> = ({ title, icon, children }) => (
  <div className="policy-section-title">
    <h6 className="m-0 font-weight-bold text-primary">
      <i className={`fas ${icon}`} aria-hidden="true" />
      {title}
    </h6>
    {children && <div className="policy-section-title__actions">{children}</div>}
  </div>
);

export default PolicySectionTitle;
