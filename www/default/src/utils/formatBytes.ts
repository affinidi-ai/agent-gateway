const UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];

/**
 * A byte count in the binary unit that keeps the number short: `312 MiB`,
 * `1.5 GiB`, `0 B`. The dashboard's sizes all come from the gateway as bytes
 * and are all powers of 1024, so they are labelled as such.
 */
export const formatBytes = (bytes: number): string => {
  let value = Math.max(0, bytes);
  let unit = 0;
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const rounded = value >= 100 || unit === 0 ? Math.round(value) : Math.round(value * 10) / 10;
  return `${rounded} ${UNITS[unit]}`;
};
