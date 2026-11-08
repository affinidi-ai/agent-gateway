import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';

/** Sends the visitor to `to` and carries over the query string and hash of the old address. */
const RedirectKeepingQuery: React.FC<{ to: string }> = ({ to }) => {
  const { search, hash } = useLocation();
  return <Navigate to={`${to}${search}${hash}`} replace />;
};

export default RedirectKeepingQuery;
