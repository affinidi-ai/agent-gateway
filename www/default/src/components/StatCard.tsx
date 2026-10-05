import React from 'react';
import { StatCardProps } from '../types';

const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  icon,
  color,
  subtitle,
  onClick,
  badge,
  testId,
}) => {
  const handleClick = () => {
    if (onClick) {
      onClick();
    }
  };

  const badgeStyle: React.CSSProperties =
    badge?.color === 'danger'
      ? {
          fontSize: '0.7rem',
          animation: 'pulse-danger 2s ease-in-out infinite',
        }
      : {
          fontSize: '0.7rem',
        };

  return (
    <div className="col-xl-3 col-md-6 mb-4">
      <div
        className={`card stat-card ${color} shadow h-100 py-2${onClick ? ' clickable' : ''}`}
        onClick={handleClick}
        style={onClick ? { cursor: 'pointer' } : {}}
        data-testid={testId}
      >
        <div className="card-body">
          <div className="row no-gutters align-items-center">
            <div className="col me-2">
              <div className={`text-xs font-weight-bold text-${color} text-uppercase mb-1`}>
                {title}
                {badge && (
                  <>
                    <span className={`badge badge-${badge.color} ms-2`} style={badgeStyle}>
                      <i className="fas fa-exclamation-circle"></i> {badge.text}
                    </span>
                    {badge.color === 'danger' && (
                      <style>{`
                        @keyframes pulse-danger {
                          0%, 100% {
                            opacity: 1;
                            transform: scale(1);
                            box-shadow: 0 0 0 0 rgba(220, 53, 69, 0.7);
                          }
                          50% {
                            opacity: 0.9;
                            transform: scale(1.05);
                            box-shadow: 0 0 8px 2px rgba(220, 53, 69, 0.4);
                          }
                        }
                      `}</style>
                    )}
                  </>
                )}
                {subtitle && (
                  <small
                    className="text-muted d-block"
                    style={{
                      fontSize: '0.65rem',
                      fontWeight: 'normal',
                      textTransform: 'none',
                      cursor: onClick ? 'pointer' : 'default',
                    }}
                    title={onClick ? 'Click to change settings' : undefined}
                  >
                    {subtitle}
                  </small>
                )}
              </div>
              <div className="h5 mb-0 font-weight-bold text-gray-800">
                {value === null || value === undefined ? <span className="loading"></span> : value}
              </div>
            </div>
            <div className="col-auto">
              <i className={`fas ${icon} fa-2x`}></i>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default StatCard;
