import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { isMain } from './is-main.mjs';

const HERE = import.meta.dirname;

test('the entry point matches by path and through a symlink; another file does not', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'is-main-'));
  try {
    const link = path.join(dir, 'link.mjs');
    fs.symlinkSync(import.meta.filename, link);
    assert.equal(isMain(import.meta, ['node', import.meta.filename]), true);
    assert.equal(isMain(import.meta, ['node', link]), true);
    assert.equal(isMain(import.meta, ['node', path.join(HERE, 'client-parity.mjs')]), false);
    assert.equal(isMain(import.meta, ['node']), false);
    assert.equal(isMain(import.meta, ['node', path.join(dir, 'absent.mjs')]), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a script started through a symlink still runs its main block', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'is-main-'));
  try {
    const link = path.join(dir, 'client-parity.mjs');
    fs.symlinkSync(path.join(HERE, 'client-parity.mjs'), link);
    const run = spawnSync(process.execPath, [link], { encoding: 'utf8' });
    assert.equal(run.status, 2);
    assert.match(run.stderr, /--direct is required/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
