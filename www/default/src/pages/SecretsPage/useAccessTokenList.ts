import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../api';
import { getErrorMessage } from '../../utils/apiError';
import { showToast } from '../../utils/toaster';
import { usePermissions } from '../../context/PermissionsContext';
import type { AccessTokenMeta } from '../../types';

const PAGE_SIZE = 10;

export function useAccessTokenList(searchTerm: string) {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const [tokens, setTokens] = useState<AccessTokenMeta[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showRevoked, setShowRevoked] = useState(false);
  const [page, setPage] = useState(1);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setTokens(await apiClient.listAccessTokens());
    } catch (loadError) {
      setError(getErrorMessage(loadError, 'Failed to load access tokens'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => setPage(1), [searchTerm, showRevoked]);

  const filtered = useMemo(() => {
    const term = searchTerm.trim().toLowerCase();
    return tokens.filter(token => {
      if (!showRevoked && token.revoked_at) return false;
      if (!term) return true;
      return (
        token.name.toLowerCase().includes(term) ||
        token.description.toLowerCase().includes(term) ||
        token.id.toLowerCase().includes(term) ||
        token.scopes.some(scope => scope.toLowerCase().includes(term))
      );
    });
  }, [tokens, searchTerm, showRevoked]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const paged = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  const openCreate = () => navigate('/access-tokens/new');
  const openEdit = (token: AccessTokenMeta) => navigate(`/access-tokens/${token.id}`);
  const revoke = async (id: string) => {
    try {
      await apiClient.revokeAccessToken(id);
      showToast('success', 'Access token revoked');
      load();
    } catch (revokeError) {
      showToast('error', getErrorMessage(revokeError, 'Failed to revoke access token'));
    }
  };

  return {
    tokens,
    loading,
    error,
    showRevoked,
    setShowRevoked,
    page,
    setPage,
    filtered,
    paged,
    totalPages,
    currentPage,
    canEdit: hasPermission('access_tokens.edit'),
    canRevoke: hasPermission('access_tokens.delete'),
    load,
    openCreate,
    openEdit,
    revoke,
  };
}
