# CLAUDE.md

Claude Code reads this file instead of `AGENTS.md` when both exist, and older versions
cannot read `AGENTS.md` at all, so this file imports it. `AGENTS.md` is the canonical rule
file; put rules, architecture and commands there, not here.

@AGENTS.md

## Claude-specific notes

- On those versions nested `AGENTS.md` files are not loaded either. Before editing
  anything under `www/default/`, read [`www/default/AGENTS.md`](www/default/AGENTS.md).
