import { Chart as ChartJS } from 'chart.js';

// Tuned for the dashboard's dark-theme background (~#1e1e1e). Light enough to
// be legible without overpowering the data series.
const DARK = {
  text: 'rgba(241, 245, 249, 0.78)',
  grid: 'rgba(255, 255, 255, 0.14)',
  border: 'rgba(255, 255, 255, 0.22)',
};

const LIGHT = {
  text: '#666',
  grid: 'rgba(0, 0, 0, 0.1)',
  border: 'rgba(0, 0, 0, 0.1)',
};

export function applyChartTheme(isDark: boolean): void {
  const t = isDark ? DARK : LIGHT;
  ChartJS.defaults.color = t.text;
  ChartJS.defaults.borderColor = t.border;
  if (ChartJS.defaults.scale) {
    ChartJS.defaults.scale.grid = {
      ...(ChartJS.defaults.scale.grid || {}),
      color: t.grid,
    };
    ChartJS.defaults.scale.ticks = {
      ...(ChartJS.defaults.scale.ticks || {}),
      color: t.text,
    };
    ChartJS.defaults.scale.border = {
      ...(ChartJS.defaults.scale.border || {}),
      color: t.border,
    };
  }
  ChartJS.instances &&
    Object.values(ChartJS.instances).forEach(c => {
      try {
        c.update('none');
      } catch {
        /* noop */
      }
    });
}
