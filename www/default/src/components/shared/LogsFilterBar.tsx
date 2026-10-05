import React from 'react';
import { FilterChipGroup } from './filters';
import type { FilterOption } from './filters';
import { AppButton } from './AppButton';
import SearchInput from './SearchInput';

export interface LogsFilterBarProps {
  /** Level chips (All + each severity) with live counts. Multi-select. */
  levelChips: FilterOption[];
  selectedLevels: Set<string>;
  onToggleLevel: (value: string) => void;
  /** Source chips (All + each surface/channel) with live counts. Single-select. */
  sourceChips: FilterOption[];
  selectedSource: string;
  onSelectSource: (value: string) => void;
  /** One-click "problems" preset: Level = Error + Warning. */
  onProblemsOnly: () => void;
  problemsActive: boolean;
  /** Whether the buffer currently has any error/warning lines (gates the Problems button). */
  problemsAvailable: boolean;
  /** Reset every facet back to "All". */
  onClearFilters: () => void;
  anyFilterActive: boolean;
  /** For the "showing X of Y" summary. */
  filteredCount: number;
  totalCount: number;
  /** Find-in-page search + match stepper. */
  searchQuery: string;
  onSearchChange: (v: string) => void;
  matchCount: number;
  currentMatch: number; // 1-based index of the focused match (0 when none)
  onPrevMatch: () => void;
  onNextMatch: () => void;
}

/**
 * LogsFilterBar — Level (severity) + Source (surface/channel) faceted filters for the
 * Gateway Logs stream. Purely client-side over the in-memory buffer, so selections apply
 * to the live WebSocket stream with no page refresh. Reuses the shared FilterChipGroup so
 * it matches the Audit page's filter styling.
 */
const LogsFilterBar: React.FC<LogsFilterBarProps> = ({
  levelChips,
  selectedLevels,
  onToggleLevel,
  sourceChips,
  selectedSource,
  onSelectSource,
  onProblemsOnly,
  problemsActive,
  problemsAvailable,
  onClearFilters,
  anyFilterActive,
  filteredCount,
  totalCount,
  searchQuery,
  onSearchChange,
  matchCount,
  currentMatch,
  onPrevMatch,
  onNextMatch,
}) => (
  <div
    className="d-flex align-items-center flex-wrap px-3 py-2 border-bottom"
    style={{ gap: '1.5rem', rowGap: '0.5rem' }}
    data-testid="logs-filter-bar"
  >
    {/* Free-text search with a find-in-page match stepper.
        Enter → next match, Shift+Enter → previous (browser find-in-page convention). */}
    <div
      className="d-flex align-items-center"
      style={{ gap: '0.5rem' }}
      onKeyDown={e => {
        if (e.key === 'Enter') {
          e.preventDefault();
          if (matchCount > 0) (e.shiftKey ? onPrevMatch : onNextMatch)();
        }
      }}
    >
      <SearchInput
        value={searchQuery}
        onChange={onSearchChange}
        width="240px"
        placeholder="Search logs…"
        wrapperStyle={{ display: 'inline-block' }}
      />
      {searchQuery && (
        <div className="d-flex align-items-center" style={{ gap: '0.25rem' }}>
          <small
            className={matchCount === 0 ? 'text-danger' : 'text-muted'}
            style={{ minWidth: '3.5rem', textAlign: 'center' }}
            data-testid="logs-match-counter"
            title="Enter for next match, Shift+Enter for previous"
          >
            {matchCount === 0 ? 'No matches' : `${currentMatch} / ${matchCount}`}
          </small>
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary py-0 px-1"
            onClick={onPrevMatch}
            disabled={matchCount === 0}
            title="Previous match"
            aria-label="Previous match"
          >
            <i className="fas fa-chevron-up" aria-hidden="true" />
          </button>
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary py-0 px-1"
            onClick={onNextMatch}
            disabled={matchCount === 0}
            title="Next match"
            aria-label="Next match"
          >
            <i className="fas fa-chevron-down" aria-hidden="true" />
          </button>
        </div>
      )}
    </div>

    {/* Level facet — multi-select (an A2A 401 shows as WARN, not ERROR, so allow Error+Warning together) */}
    <div className="d-flex align-items-center" style={{ gap: '0.4rem' }}>
      <span className="fw-semibold text-body">Level:</span>
      <FilterChipGroup
        chips={levelChips}
        selected={selectedLevels}
        onSelect={onToggleLevel}
        multiple={true}
      />
    </div>

    {/* Source facet — single-select surface/channel derived from [CHANNEL:*] prefixes */}
    {sourceChips.length > 1 && (
      <div className="d-flex align-items-center" style={{ gap: '0.4rem' }}>
        <span className="fw-semibold text-body">Source:</span>
        <FilterChipGroup
          chips={sourceChips}
          selected={selectedSource}
          onSelect={onSelectSource}
          multiple={false}
        />
      </div>
    )}

    {/* Problems preset — anchored right after the filters so it never moves. */}
    <AppButton
      variant={problemsActive ? 'danger' : 'outline-danger'}
      size="sm"
      onClick={onProblemsOnly}
      disabled={!problemsAvailable}
      title={
        problemsAvailable
          ? 'Show only errors and warnings'
          : 'No errors or warnings in the current logs'
      }
      iconStart={<i className="fas fa-exclamation-triangle" aria-hidden="true" />}
    >
      Problems
    </AppButton>

    {/* Clear filters — dynamic, only while a filter is active. */}
    {anyFilterActive && (
      <button
        type="button"
        className="btn btn-link btn-sm p-0 text-decoration-none"
        onClick={onClearFilters}
        data-testid="logs-clear-filters"
      >
        Clear filters
      </button>
    )}

    {/* Result summary — aligned to the far right. */}
    <small className="text-muted ms-auto" data-testid="logs-filter-summary">
      {anyFilterActive ? `${filteredCount} of ${totalCount}` : `${totalCount}`} log
      {totalCount !== 1 ? 's' : ''}
    </small>
  </div>
);

export default LogsFilterBar;
