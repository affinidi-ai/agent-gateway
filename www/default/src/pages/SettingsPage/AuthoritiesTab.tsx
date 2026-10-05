import React, { useCallback, useEffect, useState } from 'react';
import AuthoritiesPage from '../AuthoritiesPage';
import EditAuthorityPage from '../EditAuthorityPage';

interface AuthoritiesTabProps {
  initialViewId?: string | null;
  onViewChange?: (viewId: string | null) => void;
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
}

const AuthoritiesTab: React.FC<AuthoritiesTabProps> = ({
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
    return <EditAuthorityPage embeddedId={viewId} onDone={handleDone} />;
  }

  return (
    <AuthoritiesPage
      onEdit={id => updateViewId(id)}
      onAdd={() => updateViewId('new')}
      externalSearchTerm={externalSearchTerm}
      onFilteredCountChange={onFilteredCountChange}
    />
  );
};

export default AuthoritiesTab;
