import fs from 'fs';
import path from 'path';

/**
 * The gateway no longer serves these: integrations are an endpoint plus an event set, delivered
 * for every resource, so no page attaches integrations to gateways, connection points, users or
 * identities, and the old config and runtime variable routes are gone.
 */
const REMOVED = [
  { what: 'GET /v1/integrations/config', pattern: /integrations\/config\b/ },
  { what: 'GET /v1/integrations/runtime-variables', pattern: /integrations\/runtime-variables/ },
  { what: 'per-gateway integrations', pattern: /gateways\/\$\{[^}]+\}\/integrations/ },
  { what: 'user integrations', pattern: /users\/integrations/ },
  { what: 'identity integrations', pattern: /identities\/integrations/ },
  { what: 'integration attachments', pattern: /integration_integrations/ },
  {
    what: 'connection point integration fields',
    pattern: /integration_variables|\bintegration_id\b/,
  },
];

const SOURCE_ROOT = path.join(__dirname, '..');

function sourceFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      return entry.name === '__tests__' || entry.name === 'generated' ? [] : sourceFiles(full);
    }
    return /\.(ts|tsx)$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name) ? [full] : [];
  });
}

test.each(REMOVED)('no dashboard code uses $what', ({ pattern }) => {
  const users = sourceFiles(SOURCE_ROOT)
    .filter(file => pattern.test(fs.readFileSync(file, 'utf8')))
    .map(file => path.relative(SOURCE_ROOT, file));

  expect(users).toEqual([]);
});
