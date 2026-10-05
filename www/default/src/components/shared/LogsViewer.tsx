import React, { useState, useRef, useEffect, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useApp } from '../../context/AppContext';
import { LogEntry } from '../../types';
import { formatLogTimestamp } from '../../utils/stringUtils';
import { UI_COLORS } from '../../utils/uiPalette';
import { AppButton } from './AppButton';
import LogsFilterBar from './LogsFilterBar';
import type { FilterOption } from './filters';
import './LogsViewer.css';

interface LogsViewerProps {
  filterPrefix?: string;
  title: string;
  subtitle?: string;
  /** Optional `FieldHelp` node rendered next to the title. */
  titleHelp?: React.ReactNode;
  stripAllPrefixes?: boolean; // If true, strip all [CHANNEL:*] and [PIPE:*] prefixes
  height?: string; // Custom height for the log content area
  headerActions?: React.ReactNode; // Extra buttons rendered to the left of Pause
  controlSize?: 'sm' | 'md'; // Size for the header control buttons
  disableControlsWhenEmpty?: boolean; // Disable controls when there are no displayed logs
  showFilters?: boolean; // If true, render the Level/Source filter bar (main Logs page only)
  filterStorageKey?: string; // localStorage key to persist filter selection across reloads
}

// Canonical severity ordering for the Level facet. Values match LogEntry.level (upper-cased).
const LEVEL_ORDER = ['ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE'];
const LEVEL_LABELS: Record<string, string> = {
  ERROR: 'Error',
  WARN: 'Warning',
  INFO: 'Info',
  DEBUG: 'Debug',
  TRACE: 'Trace',
};

// Extract the surface/channel source from a raw log message ([CHANNEL:name], else [PIPE:name]).
const extractSource = (message: string): string | null => {
  const channel = message.match(/\[CHANNEL:([^\]]+)\]/);
  if (channel) return channel[1];
  const pipe = message.match(/\[PIPE:([^\]]+)\]/);
  return pipe ? pipe[1] : null;
};

const isProblemLevel = (level: string): boolean => {
  const l = level.toUpperCase();
  return l === 'ERROR' || l === 'WARN';
};

// ANSI SGR color escape sequences (ESC[...m). The ESC control char is referenced via an
// escape sequence in a variable (as ansiToHtml does) rather than embedded literally in a
// regex, keeping the source readable and free of invisible control characters.
const ESC = '\u001b';
const ANSI_REGEX = new RegExp(`${ESC}\\[[0-9;]*m`, 'g');

// Plain text of a message with ANSI color escapes removed (used for search matching).
const stripAnsi = (text: string): string => text.replace(ANSI_REGEX, '');

// Strip the display prefixes so search matches what the user actually sees.
const cleanMessage = (
  message: string,
  stripAllPrefixes: boolean,
  filterPrefix?: string
): string => {
  if (stripAllPrefixes) {
    return message
      .replace(/\[CHANNEL:[^\]]+\]\s*/g, '')
      .replace(/\[PIPE:[^\]]+\]\s*/g, '')
      .trim();
  }
  if (filterPrefix && message.includes(filterPrefix)) {
    return message.replace(filterPrefix, '').trim();
  }
  return message;
};

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Wrap search matches in <mark> without corrupting the HTML: only the text segments
// between tags are touched, tag markup is left intact.
const highlightHtml = (html: string, query: string): string => {
  if (!query) return html;
  const re = new RegExp(`(${escapeRegExp(query)})`, 'gi');
  return html
    .split(/(<[^>]+>)/g)
    .map(part =>
      part.startsWith('<') ? part : part.replace(re, '<mark class="log-highlight">$1</mark>')
    )
    .join('');
};

// Escape HTML to prevent XSS
const escapeHtml = (text: string): string => {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
};

// Get color for log level
const getLevelColor = (level: string): string => {
  switch (level.toUpperCase()) {
    case 'ERROR':
      return UI_COLORS.danger;
    case 'WARN':
      return UI_COLORS.warning;
    case 'INFO':
      return UI_COLORS.primary;
    case 'DEBUG':
      return UI_COLORS.success;
    case 'TRACE':
      return UI_COLORS.neutralMuted;
    default:
      return UI_COLORS.neutral;
  }
};

// Convert ANSI color codes to HTML spans with colors
const ansiToHtml = (text: string): string => {
  // ANSI color code mapping to CSS colors
  const ansiColors: Record<string, string> = {
    // Foreground colors (vivid for dark terminal background)
    '30': '#000000', // black
    '31': '#ff5555', // red
    '32': '#50fa7b', // green
    '33': '#f1fa8c', // yellow
    '34': '#6272a4', // blue
    '35': '#ff79c6', // magenta
    '36': '#8be9fd', // cyan
    '37': '#f8f8f2', // white

    // Bright colors
    '90': '#6272a4', // bright black (gray)
    '91': '#ff6e6e', // bright red
    '92': '#69ff94', // bright green
    '93': '#ffffa5', // bright yellow
    '94': '#d6acff', // bright blue
    '95': '#ff92df', // bright magenta
    '96': '#a4ffff', // bright cyan
    '97': '#ffffff', // bright white
  };

  // Default color for logs
  let currentColor = '#00ff00';
  let currentStyle = '';
  let result = '';

  // Split by ANSI escape sequences
  const escapeChar = '\u001b';
  const ansiRegex = new RegExp(`(${escapeChar}\\[[0-9;]*m)`, 'g');
  const parts = text.split(ansiRegex);

  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];

    // Check if this is an ANSI escape sequence
    const ansiMatchRegex = new RegExp(`${escapeChar}\\[([0-9;]*)m`);
    const ansiMatch = part.match(ansiMatchRegex);

    if (ansiMatch) {
      // Parse the codes
      const codes = ansiMatch[1].split(';').filter(c => c !== '');

      for (const code of codes) {
        if (code === '0' || code === '') {
          // Reset all attributes
          currentColor = '#00ff00';
          currentStyle = '';
        } else if (code === '1') {
          // Bold
          currentStyle = 'font-weight: bold;';
        } else if (code === '2') {
          // Dim/faint - make slightly transparent
          currentStyle = 'opacity: 0.6;';
        } else if (code === '22') {
          // Normal intensity
          currentStyle = '';
        } else if (ansiColors[code]) {
          // Color code
          currentColor = ansiColors[code];
        }
      }
    } else if (part) {
      // Regular text - wrap in span with current color
      const escapedText = escapeHtml(part);
      if (currentStyle) {
        result += `<span style="color: ${currentColor}; ${currentStyle}">${escapedText}</span>`;
      } else {
        result += `<span style="color: ${currentColor};">${escapedText}</span>`;
      }
    }
  }

  return result || `<span style="color: #00ff00;">${escapeHtml(text)}</span>`;
};

const LogsViewer: React.FC<LogsViewerProps> = ({
  filterPrefix,
  title,
  subtitle,
  titleHelp,
  stripAllPrefixes = false,
  height,
  headerActions,
  controlSize = 'sm',
  disableControlsWhenEmpty = false,
  showFilters = false,
  filterStorageKey,
}) => {
  const { state, actions, getCurrentStats } = useApp();
  const navigate = useNavigate();
  const [isPaused, setIsPaused] = useState(false);
  const [isAutoScroll, setIsAutoScroll] = useState(true);
  const [displayedLogs, setDisplayedLogs] = useState<LogEntry[]>([]);
  const [pendingLogs, setPendingLogs] = useState<LogEntry[]>([]);
  const [forceRefresh, setForceRefresh] = useState(false);
  const logContentRef = useRef<HTMLPreElement>(null);
  const lastLogLinesRef = useRef<LogEntry[]>([]);
  // When > 0, only show logs with file_position above this watermark (set on Clear)
  const [clearWatermark, setClearWatermark] = useState(0);

  // --- Level/Source filter state (only used when showFilters is true) ---
  // Empty level set = "All"; empty source string = "All".
  const [selectedLevels, setSelectedLevels] = useState<Set<string>>(() => {
    if (!showFilters || !filterStorageKey) return new Set();
    try {
      const raw = localStorage.getItem(`${filterStorageKey}:levels`);
      return raw ? new Set(JSON.parse(raw) as string[]) : new Set();
    } catch {
      return new Set();
    }
  });
  const [selectedSource, setSelectedSource] = useState<string>(() => {
    if (!showFilters || !filterStorageKey) return '';
    try {
      return localStorage.getItem(`${filterStorageKey}:source`) || '';
    } catch {
      return '';
    }
  });

  // Persist filter selection so a reload keeps the developer's chosen view
  useEffect(() => {
    if (!showFilters || !filterStorageKey) return;
    try {
      localStorage.setItem(`${filterStorageKey}:levels`, JSON.stringify([...selectedLevels]));
      localStorage.setItem(`${filterStorageKey}:source`, selectedSource);
    } catch {
      // localStorage may be unavailable (private mode) — filtering still works in-session
    }
  }, [showFilters, filterStorageKey, selectedLevels, selectedSource]);

  // --- Search / find-in-page state (only surfaced when showFilters is true) ---
  const [searchQuery, setSearchQuery] = useState('');
  const [currentMatchIdx, setCurrentMatchIdx] = useState(0);
  // DOM nodes per rendered line index, so we can scroll a match into view
  const lineRefs = useRef<Map<number, HTMLDivElement>>(new Map());

  // Get log timestamp format from settings (default to 'local')
  const logTimestampFormat = state.settings?.log_timestamp_format || 'local';

  // Get all log entries from current stats (filtered view)
  const stats = getCurrentStats();
  const allLogEntries = useMemo(
    () => stats?.proxy_info?.log_entries || [],
    [stats?.proxy_info?.log_entries]
  );

  // Filter logs by the provided prefix - keep as LogEntry objects
  const logEntries = useMemo(() => {
    if (!allLogEntries || allLogEntries.length === 0) {
      return [];
    }

    // If no filter prefix is provided, return all logs
    if (!filterPrefix) {
      return allLogEntries;
    }

    // Filter logs that have the specified prefix in the message
    return allLogEntries.filter((entry: LogEntry) => entry.message.includes(filterPrefix));
  }, [allLogEntries, filterPrefix]);

  // Apply clear watermark: only show logs written after the clear point
  const visibleLogEntries = useMemo(() => {
    if (clearWatermark > 0) {
      return logEntries.filter(e => e.file_position > clearWatermark);
    }
    return logEntries;
  }, [logEntries, clearWatermark]);

  // Apply the Level/Source facets (no-op when showFilters is false or nothing is selected)
  const filteredLogEntries = useMemo(() => {
    if (!showFilters) return visibleLogEntries;
    const levelOn = selectedLevels.size > 0;
    const sourceOn = selectedSource !== '';
    if (!levelOn && !sourceOn) return visibleLogEntries;
    return visibleLogEntries.filter(e => {
      if (levelOn && !selectedLevels.has(e.level.toUpperCase())) return false;
      if (sourceOn && extractSource(e.message) !== selectedSource) return false;
      return true;
    });
  }, [visibleLogEntries, showFilters, selectedLevels, selectedSource]);

  // Chip options with live counts, derived from the visible buffer (pre-facet) so users can
  // see how many entries each level/source would match before switching to it.
  const levelChips = useMemo<FilterOption[]>(() => {
    const counts: Record<string, number> = {};
    for (const e of visibleLogEntries) {
      const lvl = e.level.toUpperCase();
      counts[lvl] = (counts[lvl] || 0) + 1;
    }
    // Always offer the canonical levels; append any unexpected levels seen in the buffer.
    const levels = [...LEVEL_ORDER, ...Object.keys(counts).filter(l => !LEVEL_ORDER.includes(l))];
    return [
      { value: '', label: 'All', count: visibleLogEntries.length },
      ...levels
        // Hide TRACE unless it actually appears (rarely broadcast)
        .filter(l => l !== 'TRACE' || counts[l])
        .map(l => ({ value: l, label: LEVEL_LABELS[l] || l, count: counts[l] || 0 })),
    ];
  }, [visibleLogEntries]);

  const sourceChips = useMemo<FilterOption[]>(() => {
    const counts: Record<string, number> = {};
    for (const e of visibleLogEntries) {
      const src = extractSource(e.message);
      if (src) counts[src] = (counts[src] || 0) + 1;
    }
    // Always include the active source (even if absent from the current buffer, e.g. restored
    // from localStorage on reload) so the facet stays visible and the filter can be cleared.
    if (selectedSource && counts[selectedSource] === undefined) {
      counts[selectedSource] = 0;
    }
    return [
      { value: '', label: 'All', count: visibleLogEntries.length },
      ...Object.keys(counts)
        .sort()
        .map(src => ({ value: src, label: src, count: counts[src] })),
    ];
  }, [visibleLogEntries, selectedSource]);

  const anyFilterActive = showFilters && (selectedLevels.size > 0 || selectedSource !== '');
  const problemsActive =
    selectedLevels.size === 2 && selectedLevels.has('ERROR') && selectedLevels.has('WARN');

  const toggleLevel = useCallback((value: string) => {
    if (value === '') {
      setSelectedLevels(new Set());
      return;
    }
    setSelectedLevels(prev => {
      const next = new Set(prev);
      if (next.has(value)) next.delete(value);
      else next.add(value);
      return next;
    });
  }, []);

  const handleProblemsOnly = useCallback(() => {
    setSelectedLevels(prev => {
      const isProblems = prev.size === 2 && prev.has('ERROR') && prev.has('WARN');
      return isProblems ? new Set() : new Set(['ERROR', 'WARN']);
    });
  }, []);

  const clearFilters = useCallback(() => {
    setSelectedLevels(new Set());
    setSelectedSource('');
  }, []);

  // Initialize displayed logs on first load
  useEffect(() => {
    if (displayedLogs.length === 0 && filteredLogEntries.length > 0) {
      setDisplayedLogs(filteredLogEntries);
      lastLogLinesRef.current = filteredLogEntries;
    }
  }, [filteredLogEntries, displayedLogs.length]);

  // Handle log updates - store new logs in pending if paused, otherwise display immediately
  useEffect(() => {
    // Skip update if filtered entries haven't actually changed (deep equality check)
    if (
      lastLogLinesRef.current.length === filteredLogEntries.length &&
      lastLogLinesRef.current.every(
        (entry, index) => entry.file_position === filteredLogEntries[index].file_position
      )
    ) {
      return;
    }

    lastLogLinesRef.current = filteredLogEntries;

    if (isPaused && !forceRefresh) {
      // When paused, don't update displayed logs but store the latest logs as pending
      setPendingLogs(filteredLogEntries);
    } else {
      // When not paused, or when forcing refresh, update displayed logs and clear any pending logs
      setDisplayedLogs(filteredLogEntries);
      setPendingLogs([]);
      if (forceRefresh) {
        setForceRefresh(false);
      }
    }
  }, [filteredLogEntries, isPaused, forceRefresh]);

  // Auto-scroll to bottom when new logs arrive (suspended while the user is searching, so
  // stepping through matches isn't yanked back to the tail)
  useEffect(() => {
    if (isAutoScroll && logContentRef.current && !isPaused && !searchQuery) {
      logContentRef.current.scrollTop = logContentRef.current.scrollHeight;
    }
  }, [displayedLogs, isAutoScroll, isPaused, searchQuery]);

  const togglePause = () => {
    if (isPaused) {
      // When resuming, show all pending logs
      setDisplayedLogs(pendingLogs.length > 0 ? pendingLogs : filteredLogEntries);
      setPendingLogs([]);
    }
    setIsPaused(!isPaused);
  };

  const refreshLogs = () => {
    // Set force refresh to true so that even if paused, we show the latest logs
    // Also reset the clear watermark so all logs are visible again
    setClearWatermark(0);
    setForceRefresh(true);
    actions.loadDashboardStats(true);
  };

  // Deduplicate consecutive identical log entries (same file_position)
  const dedupedLogs = useMemo(() => {
    const out: LogEntry[] = [];
    let last: LogEntry | null = null;
    for (const entry of displayedLogs) {
      if (!last || entry.file_position !== last.file_position) {
        out.push(entry);
        last = entry;
      }
    }
    return out;
  }, [displayedLogs]);

  // Precompute the query-independent part of each line (timestamp, level color, ANSI→HTML
  // message) once per buffer change. Typing in the search box then only re-runs the cheap
  // highlight pass over these, instead of re-parsing ANSI for the whole buffer per keystroke.
  const baseRows = useMemo(
    () =>
      dedupedLogs.map(entry => ({
        filePosition: entry.file_position,
        timestamp: formatLogTimestamp(entry.timestamp, logTimestampFormat),
        level: entry.level,
        levelColor: getLevelColor(entry.level),
        baseMessageHtml: ansiToHtml(cleanMessage(entry.message, stripAllPrefixes, filterPrefix)),
        isProblem: isProblemLevel(entry.level),
      })),
    [dedupedLogs, logTimestampFormat, stripAllPrefixes, filterPrefix]
  );

  // Indices of rendered lines whose message contains the search query. Matched against the
  // same (prefix-stripped, ANSI-stripped) message text that highlightHtml marks, so the match
  // counter and the visible <mark> highlights never disagree. (Filter by level via the Level
  // facet, not free-text search.)
  const matchingLineIndices = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return [] as number[];
    const hits: number[] = [];
    dedupedLogs.forEach((entry, i) => {
      const text = stripAnsi(
        cleanMessage(entry.message, stripAllPrefixes, filterPrefix)
      ).toLowerCase();
      if (text.includes(q)) hits.push(i);
    });
    return hits;
  }, [dedupedLogs, searchQuery, stripAllPrefixes, filterPrefix]);

  const matchCount = matchingLineIndices.length;

  // Reset to the first match whenever the query changes
  useEffect(() => {
    setCurrentMatchIdx(0);
  }, [searchQuery]);

  // Scroll the current match into view as the user types or steps
  useEffect(() => {
    if (!searchQuery || matchCount === 0) return;
    const idx = Math.min(currentMatchIdx, matchCount - 1);
    const node = lineRefs.current.get(matchingLineIndices[idx]);
    node?.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }, [searchQuery, currentMatchIdx, matchCount, matchingLineIndices]);

  const gotoNextMatch = useCallback(() => {
    setCurrentMatchIdx(i => (matchCount ? (i + 1) % matchCount : 0));
  }, [matchCount]);

  const gotoPrevMatch = useCallback(() => {
    setCurrentMatchIdx(i => (matchCount ? (i - 1 + matchCount) % matchCount : 0));
  }, [matchCount]);

  // The line index currently focused by the match stepper (for a distinct highlight)
  const currentMatchLine =
    searchQuery && matchCount > 0
      ? matchingLineIndices[Math.min(currentMatchIdx, matchCount - 1)]
      : -1;

  const emptyStateMessage = anyFilterActive
    ? 'No logs match the current filters. Tip: an auth 401 often appears as a WARN ("Source authentication failed … deferring to policy"), not an ERROR — try including Warning.'
    : `No logs available${subtitle ? ` for ${subtitle}` : ''}`;

  // Whether the current buffer has any error/warning lines — drives the Audit call-to-action
  const hasProblems = useMemo(
    () => showFilters && visibleLogEntries.some(e => isProblemLevel(e.level)),
    [showFilters, visibleLogEntries]
  );

  const openAudit = useCallback((url: string) => navigate(url), [navigate]);

  // Render each log entry as its own line element so search matches can be highlighted and
  // scrolled into view.
  const renderRows = () => {
    if (baseRows.length === 0) {
      return (
        <div style={{ color: UI_COLORS.neutralMuted }}>
          {emptyStateMessage}
          {showFilters && (
            <>
              {' '}
              <button
                type="button"
                className="log-audit-link"
                onClick={() => openAudit('/audit?decision=deny')}
                data-testid="logs-empty-open-audit"
              >
                <i className="fas fa-list-check" aria-hidden="true" /> Open Audit for the decision
                trail →
              </button>
            </>
          )}
        </div>
      );
    }
    const query = searchQuery.trim();
    return baseRows.map((row, i) => {
      const messageHtml = highlightHtml(row.baseMessageHtml, query);
      return (
        <div
          key={`${row.filePosition}-${i}`}
          ref={node => {
            if (node) lineRefs.current.set(i, node);
            else lineRefs.current.delete(i);
          }}
          className={`log-line${i === currentMatchLine ? ' log-line--current' : ''}${
            row.isProblem ? ' log-line--problem' : ''
          }`}
        >
          <span style={{ color: UI_COLORS.neutralMuted }}>{row.timestamp}</span>{' '}
          <span style={{ color: row.levelColor, fontWeight: 'bold' }}>{row.level}</span>{' '}
          <span dangerouslySetInnerHTML={{ __html: messageHtml }} />
        </div>
      );
    });
  };

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-file-alt"></i> {title} {subtitle && `- ${subtitle}`} {titleHelp}
        </h6>
        <div className="d-flex align-items-center logs-controls">
          {headerActions}
          <AppButton
            variant="outline-danger"
            size={controlSize}
            disabled={disableControlsWhenEmpty && displayedLogs.length === 0}
            onClick={() => {
              // Record the highest file_position as watermark; only logs after this will be shown
              const maxPos = logEntries.reduce((max, e) => Math.max(max, e.file_position), 0);
              setClearWatermark(maxPos);
              setDisplayedLogs([]);
              setPendingLogs([]);
              lastLogLinesRef.current = [];
            }}
            title="Clear displayed logs"
            iconStart={<i className="fas fa-trash-alt" aria-hidden="true"></i>}
          >
            Clear
          </AppButton>
          <AppButton
            variant="secondary"
            size={controlSize}
            disabled={disableControlsWhenEmpty && displayedLogs.length === 0}
            onClick={togglePause}
            title={
              isPaused && pendingLogs.length > displayedLogs.length
                ? `${pendingLogs.length - displayedLogs.length} new logs available`
                : ''
            }
            iconStart={
              <i className={`fas fa-${isPaused ? 'play' : 'pause'}`} aria-hidden="true"></i>
            }
          >
            {isPaused
              ? pendingLogs.length > displayedLogs.length
                ? `Resume (${pendingLogs.length - displayedLogs.length} new)`
                : 'Resume'
              : 'Pause'}
          </AppButton>
          <AppButton
            variant="primary"
            size={controlSize}
            onClick={refreshLogs}
            iconStart={<i className="fas fa-sync-alt" aria-hidden="true"></i>}
          >
            Refresh
          </AppButton>
          {!showFilters && (
            <small className="text-muted ms-2">
              {displayedLogs.length} log{displayedLogs.length !== 1 ? 's' : ''}
            </small>
          )}
        </div>
      </div>
      <div className="card-body p-0">
        {showFilters && (
          <LogsFilterBar
            levelChips={levelChips}
            selectedLevels={selectedLevels}
            onToggleLevel={toggleLevel}
            sourceChips={sourceChips}
            selectedSource={selectedSource}
            onSelectSource={setSelectedSource}
            onProblemsOnly={handleProblemsOnly}
            problemsActive={problemsActive}
            problemsAvailable={hasProblems}
            onClearFilters={clearFilters}
            anyFilterActive={anyFilterActive}
            filteredCount={filteredLogEntries.length}
            totalCount={visibleLogEntries.length}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            matchCount={matchCount}
            currentMatch={matchCount > 0 ? Math.min(currentMatchIdx, matchCount - 1) + 1 : 0}
            onPrevMatch={gotoPrevMatch}
            onNextMatch={gotoNextMatch}
          />
        )}
        {hasProblems && (
          <div className="logs-audit-banner" data-testid="logs-audit-banner" role="note">
            <i className="fas fa-triangle-exclamation logs-audit-banner__icon" aria-hidden="true" />
            <span className="logs-audit-banner__text">
              <strong>Seeing errors or warnings?</strong> Logs show <em>what</em> happened — for{' '}
              <em>why</em> a request was allowed or blocked (the policy decision,{' '}
              <code>deny_reason</code>, 401/403), open the Audit trail.
            </span>
            <button
              type="button"
              className="logs-audit-banner__cta"
              onClick={() => openAudit('/audit?decision=deny')}
              data-testid="logs-audit-banner-cta"
            >
              Open Audit <i className="fas fa-arrow-right" aria-hidden="true" />
            </button>
          </div>
        )}
        <pre
          ref={logContentRef}
          className="log-viewer"
          style={{
            height: height || 'calc(100vh - 250px)',
            minHeight: height ? undefined : '400px',
          }}
        >
          {renderRows()}
        </pre>
      </div>
    </div>
  );
};

export default LogsViewer;
