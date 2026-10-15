# CLAUDE.md

Claude Code before v2.1.277, and Claude Code on Bedrock, Vertex or Foundry, does not read
`AGENTS.md` on its own, so this file imports it. `AGENTS.md` is the canonical rule file;
put rules, architecture and commands there, not here.

@AGENTS.md

## Claude-specific notes

- On those versions nested `AGENTS.md` files are not loaded either. Before editing
  anything under `www/default/`, read [`www/default/AGENTS.md`](www/default/AGENTS.md).
