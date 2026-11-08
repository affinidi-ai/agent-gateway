/**
 * The messages of a response's `Warning` headers (code 299). A `Headers` object
 * joins repeated headers with a comma, so each `299 - "text"` entry is read out
 * of the joined value; a quote or backslash in the text is escaped.
 */
export function parseWarningHeader(value: string | null | undefined): string[] {
  if (!value) return [];
  const out: string[] = [];
  const entry = /(?:^|,\s*)299\s+\S+\s+"((?:[^"\\]|\\.)*)"/g;
  let match: RegExpExecArray | null;
  while ((match = entry.exec(value)) !== null) {
    out.push(match[1].replace(/\\(["\\])/g, '$1'));
  }
  return out;
}

/** What the page shows for the save's warnings: the header ones, up to `limit`, then a count. */
export function joinWarnings(warnings: readonly string[], limit = 3, maxLength = 300): string {
  const shown = warnings
    .slice(0, limit)
    .map(w => (w.length > maxLength ? `${w.slice(0, maxLength - 3)}...` : w));
  const more = warnings.length - shown.length;
  return `${shown.join('\n')}${more > 0 ? `\nand ${more} more` : ''}`;
}
