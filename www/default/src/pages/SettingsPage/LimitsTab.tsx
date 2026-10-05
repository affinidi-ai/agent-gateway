import React from 'react';
import { useLimits } from '../../hooks/useLimits';

const pct = (current: number, limit: number) =>
  limit > 0 ? Math.min(100, Math.round((current / limit) * 100)) : 0;

/**
 * Read-only view of every configured appliance resource limit with its current
 * usage. Built dynamically from GET /v1/limits, so new dimensions appear here
 * automatically.
 */
const LimitsTab: React.FC = () => {
  const { items, loading } = useLimits();

  if (loading) {
    return <div className="text-muted p-3">Loading limits…</div>;
  }

  if (items.length === 0) {
    return (
      <div className="alert alert-info">
        No resource limits are configured. All entity types are currently uncapped.
      </div>
    );
  }

  return (
    <div className="card shadow-sm">
      <div className="card-body">
        <p className="text-muted">
          Reaching a limit prevents creating more of that entity until you upgrade your appliance
          tier.
        </p>
        <div className="table-responsive">
          <table className="table align-middle">
            <thead>
              <tr>
                <th>Limit</th>
                <th style={{ width: '30%' }}>Usage</th>
                <th className="text-end">Current</th>
                <th className="text-end">Limit</th>
              </tr>
            </thead>
            <tbody>
              {items.map(item => {
                const atLimit = item.current >= item.limit;
                const p = pct(item.current, item.limit);
                const barClass = atLimit ? 'bg-danger' : p >= 80 ? 'bg-warning' : 'bg-success';
                return (
                  <tr key={item.id}>
                    <td>
                      <div className="fw-semibold">{item.name}</div>
                      <div className="text-muted small">{item.description}</div>
                    </td>
                    <td>
                      <div className="progress" style={{ height: 8 }}>
                        <div
                          className={`progress-bar ${barClass}`}
                          role="progressbar"
                          style={{ width: `${p}%` }}
                          aria-valuenow={item.current}
                          aria-valuemin={0}
                          aria-valuemax={item.limit}
                        />
                      </div>
                    </td>
                    <td className="text-end">
                      <span className={atLimit ? 'text-danger fw-bold' : ''}>{item.current}</span>
                    </td>
                    <td className="text-end">{item.limit}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default LimitsTab;
