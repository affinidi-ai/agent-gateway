import React, { useCallback, useEffect, useState } from 'react';
import IssuersPage from '../IssuersPage';
import EditIssuerPage from '../EditIssuerPage';

interface IssuersTabProps {
  initialViewId?: string | null;
  onViewChange?: (viewId: string | null) => void;
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
}

const IssuersTab: React.FC<IssuersTabProps> = ({
  initialViewId = null,
  onViewChange,
  externalSearchTerm,
  onFilteredCountChange,
}) => {
  const [viewId, setViewId] = useState<string | null>(initialViewId);

  useEffect(() => {
    setViewId(initialViewId);
  }, [initialViewId]);

  const updateViewId = useCallback(
    (nextViewId: string | null) => {
      setViewId(nextViewId);
      onViewChange?.(nextViewId);
    },
    [onViewChange]
  );

  const handleDone = useCallback(() => updateViewId(null), [updateViewId]);

  if (viewId !== null) {
    return <EditIssuerPage embeddedId={viewId} onDone={handleDone} />;
  }

  return (
    <IssuersPage
      onEdit={id => updateViewId(id)}
      onAdd={() => updateViewId('new')}
      externalSearchTerm={externalSearchTerm}
      onFilteredCountChange={onFilteredCountChange}
    />
  );
};

export default IssuersTab;
