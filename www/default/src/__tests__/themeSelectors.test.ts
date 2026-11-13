import fs from 'fs';
import path from 'path';

const SOURCE_ROOT = path.join(__dirname, '..');

function stylesheets(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      return entry.name === '__tests__' ? [] : stylesheets(full);
    }
    return /\.css$/.test(entry.name) ? [full] : [];
  });
}

test('dashboard stylesheets follow the dashboard theme, not the operating system colour scheme', () => {
  const users = stylesheets(SOURCE_ROOT)
    .filter(file => /prefers-color-scheme/.test(fs.readFileSync(file, 'utf8')))
    .map(file => path.relative(SOURCE_ROOT, file));

  expect(users).toEqual([]);
});
