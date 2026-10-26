import React, { useEffect, useRef, useState } from 'react';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import AuditDetailPanel from './AuditDetailPanel';
import AuditForwardButton from './AuditForwardButton';
import AuditFilters from './AuditFilters';
import AuditInfoBanner from './AuditInfoBanner';
import AuditList from './AuditList';
import { useAuditLog } from './useAuditLog';

const AuditPage: React.FC = () => {
  const audit = useAuditLog();
  const [infoOpen, setInfoOpen] = useState(false);

  // Compute decision counts from entries
  const decisionCounts = audit.entries.reduce<Record<string, number>>((acc, entry) => {
    const decision = entry.policy_decision?.decision || '';
    if (decision) {
      acc[decision] = (acc[decision] ?? 0) + 1;
    }
    return acc;
  }, {});
  const pageRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const shellRef = useRef<HTMLDivElement>(null);

  // While stacked, the filters and the card header stay pinned under the
  // topbar (dashboard.css). Publish their heights so the header sits under the
  // filters and a scrolled-to entry or detail panel lands below both; the
  // filters wrap, so the heights change with the width.
  useEffect(() => {
    const page = pageRef.current;
    const filters = page?.querySelector<HTMLElement>('.audit-filters');
    const header = page?.querySelector<HTMLElement>('.audit-card-header');
    if (!page || !filters || !header || typeof ResizeObserver === 'undefined') return;
    const publish = () => {
      page.style.setProperty('--audit-filters-height', `${filters.offsetHeight}px`);
      page.style.setProperty('--audit-header-height', `${header.offsetHeight}px`);
    };
    publish();
    const observer = new ResizeObserver(publish);
    observer.observe(filters);
    observer.observe(header);
    return () => observer.disconnect();
  }, []);

  const selectedIdx = audit.expandedIdx ?? 0;
  const selectedEntry = audit.filteredEntries[selectedIdx] ?? null;

  const changePage = (updater: number | ((p: number) => number)) => {
    audit.setExpandedIdx(null);
    audit.setPage(updater);
  };

  const scrollSelectedIntoView = () => {
    const node = listRef.current?.querySelector(`[data-testid="audit-item-${selectedIdx}"]`);
    node?.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' });
  };

  // When the layout stacks the list above the detail (the shell is a column),
  // bring the detail panel into view; side by side it is already on screen.
  const selectEntry = (idx: number) => {
    audit.setExpandedIdx(idx);
    const shell = shellRef.current;
    if (shell && window.getComputedStyle(shell).flexDirection === 'column') {
      const panel = shell.querySelector('[data-testid="audit-detail-panel"]');
      panel?.scrollIntoView?.({ block: 'start', behavior: 'smooth' });
    }
  };

  return (
    <div className="container-fluid audit-page" data-testid="page-audit" ref={pageRef}>
      <AuditFilters
        searchInput={audit.searchInput}
        onSearchChange={audit.setSearchInput}
        onSearchSubmit={audit.submitSearch}
        onClearText={audit.clearTextFilter}
        category={audit.category}
        selectedCats={audit.selectedCats}
        categoryCounts={audit.categoryCounts}
        onToggleCategory={audit.toggleCategory}
        onSelectAllCategories={audit.selectAllCategories}
        decisionFilter={audit.decisionFilter}
        onDecisionChange={audit.setDecisionFilter}
        decisionCounts={decisionCounts}
        flowFilter={audit.flowFilter}
        onFlowChange={audit.setFlowFilter}
        scopeFilter={audit.scopeFilter}
        onScopeChange={audit.setScopeFilter}
      />

      <div className="card shadow audit-card">
        <div className="card-header audit-card-header py-3 d-flex justify-content-between align-items-center flex-wrap">
          <h6 className="m-0 font-weight-bold text-primary mr-3">
            <i className="fas fa-clipboard-list mr-1"></i> Audit Log
            {audit.total > 0 && (
              <Badge
                value={audit.total}
                className="ms-2"
                data-testid="audit-total-badge"
                ariaLabel={`${audit.total} total audit entries`}
              />
            )}
          </h6>
          <div className="d-flex gap-2">
            <AuditForwardButton />
            <AppButton
              variant="primary"
              size="md"
              disabled={audit.total === 0}
              onClick={audit.reload}
              data-testid="audit-refresh"
              iconStart={<i className="fas fa-sync-alt me-1" aria-hidden="true" />}
            >
              Refresh
            </AppButton>
          </div>
        </div>

        <div className="card-body audit-card-body">
          <AuditInfoBanner open={infoOpen} onToggle={() => setInfoOpen(o => !o)} />
          <div className="audit-shell" ref={shellRef}>
            <div className="audit-shell-list" ref={listRef}>
              <AuditList
                isLoading={audit.isLoading}
                filteredEntries={audit.filteredEntries}
                selectedIdx={selectedIdx}
                onSelect={selectEntry}
                page={audit.page}
                totalPages={audit.totalPages}
                onPageChange={changePage}
              />
            </div>
            <AuditDetailPanel
              entry={selectedEntry}
              filteredEntries={audit.filteredEntries}
              onTitleClick={scrollSelectedIntoView}
              onQuickFilter={audit.applyQuickFilter}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default AuditPage;
