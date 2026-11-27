import fs from 'node:fs';

// Whether the module whose `import.meta` is passed is the script node was
// started with. Node resolves a symlinked entry point to its real path in
// `import.meta.filename` but keeps the path as given in `process.argv[1]`, so a
// checkout under a symlink (such as macOS's /var and /tmp) never matches by
// plain comparison and its script would exit silently without running.
export function isMain(meta, argv = process.argv) {
  if (!argv[1]) return false;
  try {
    return fs.realpathSync(argv[1]) === fs.realpathSync(meta.filename);
  } catch {
    return false;
  }
}
