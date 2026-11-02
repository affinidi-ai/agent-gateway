import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAgentPayFlag } from '../utils/featureFlags';

interface AgentPayRouteProps {
  children: React.ReactElement;
  /** Where to go while the flag is off. */
  fallback?: string;
}

/** Renders `children` only while `agent_pay_delegation` is on; waits for the settings first. */
const AgentPayRoute: React.FC<AgentPayRouteProps> = ({ children, fallback = '/connections' }) => {
  const { enabled, loaded } = useAgentPayFlag();
  if (!loaded) return null;
  return enabled ? children : <Navigate to={fallback} replace />;
};

export default AgentPayRoute;
