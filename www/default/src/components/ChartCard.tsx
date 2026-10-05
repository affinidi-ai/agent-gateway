import React from 'react';
import { ChartCardProps } from '../types';

const ChartCard: React.FC<ChartCardProps> = ({
  title,
  children,
  className = '',
  headerActions,
}) => {
  return (
    <div className={`col-lg-12 mb-4 ${className}`}>
      <div className="card shadow">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">{title}</h6>
          {headerActions && <div>{headerActions}</div>}
        </div>
        <div className="card-body">{children}</div>
      </div>
    </div>
  );
};

export default ChartCard;
