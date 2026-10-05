/**
 * `useSurfaceTemplates` — lazy fetch + cache of the surface templates
 * list, plus CRUD helpers.
 *
 * The hook owns the entire list (builtins + user templates) so the
 * panel can show them in one place. Mutations refresh the cached list
 * on success so the UI stays in sync without a second round-trip.
 */

import { useCallback, useEffect, useState } from 'react';
import { apiClient, type SurfaceTemplate } from '../../../api';

export interface UseSurfaceTemplatesResult {
  templates: SurfaceTemplate[];
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  create: (tpl: Partial<SurfaceTemplate>) => Promise<SurfaceTemplate>;
  update: (id: string, tpl: Partial<SurfaceTemplate>) => Promise<SurfaceTemplate>;
  remove: (id: string) => Promise<void>;
  importTemplate: (payload: unknown) => Promise<SurfaceTemplate>;
  exportTemplate: (id: string) => Promise<string>;
}

export function useSurfaceTemplates(): UseSurfaceTemplatesResult {
  const [templates, setTemplates] = useState<SurfaceTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const enabledTemplates = templates.filter(
    t => !(t.tags ?? []).some(tag => tag.toLowerCase().includes('disabled'))
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await apiClient.listSurfaceTemplates();
      setTemplates(list);
    } catch (e: any) {
      setError(e?.message ?? 'Failed to load surface templates');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const create = useCallback(
    async (tpl: Partial<SurfaceTemplate>) => {
      const created = await apiClient.createSurfaceTemplate(tpl);
      await refresh();
      return created;
    },
    [refresh]
  );

  const update = useCallback(
    async (id: string, tpl: Partial<SurfaceTemplate>) => {
      const updated = await apiClient.updateSurfaceTemplate(id, tpl);
      await refresh();
      return updated;
    },
    [refresh]
  );

  const remove = useCallback(
    async (id: string) => {
      await apiClient.deleteSurfaceTemplate(id);
      await refresh();
    },
    [refresh]
  );

  const importTemplate = useCallback(
    async (payload: unknown) => {
      const imported = await apiClient.importSurfaceTemplate(payload);
      await refresh();
      return imported;
    },
    [refresh]
  );

  const exportTemplate = useCallback(async (id: string) => {
    return apiClient.exportSurfaceTemplate(id);
  }, []);

  return {
    templates: enabledTemplates,
    loading,
    error,
    refresh,
    create,
    update,
    remove,
    importTemplate,
    exportTemplate,
  };
}
