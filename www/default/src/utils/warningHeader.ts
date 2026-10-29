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
