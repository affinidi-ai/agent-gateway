import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAgentPayFlag } from '../utils/featureFlags';

interface AgentPayRouteProps {
  children: React.ReactElement;
}

/** Renders `children` only while `agent_pay_delegation` is on, else goes to Connections; waits for the settings first. */
const AgentPayRoute: React.FC<AgentPayRouteProps> = ({ children }) => {
  const { enabled, loaded } = useAgentPayFlag();
  if (!loaded) return null;
  return enabled ? children : <Navigate to="/connections" replace />;
};

export default AgentPayRoute;
