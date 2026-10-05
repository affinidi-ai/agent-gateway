# Contributing

Affinidi Agent Gateway is a single Rust binary (`agent-gateway`) with a dashboard under
`www/default/`. To propose a change, first discuss it by creating a new
[GitHub issue](https://github.com/affinidi-ai/agent-gateway/issues/new).

## Development Requirements

- Rust `1.95.0` or newer, 2024 Edition (the minimum is declared in [`Cargo.toml`](Cargo.toml))
- Node.js and npm (to build and run the dashboard under `www/default/`)

Runtime state uses an in-memory DashMap cache backed by filesystem JSON storage — there is no
external database or Redis dependency. For source setup and the day-to-day run targets, see
[`docs/development/GETTING_STARTED.md`](docs/development/GETTING_STARTED.md) and
[`docs/development/DEVELOPMENT.md`](docs/development/DEVELOPMENT.md).

To find your way around the code, start with [`ARCHITECTURE.md`](ARCHITECTURE.md). For the
recurring change shapes, such as adding a protocol, a source authentication method, or a
management endpoint, see
[`docs/development/MAKING_CHANGES.md`](docs/development/MAKING_CHANGES.md).

## Changelog Fragments

**Every change requires a changelog fragment — never edit [`CHANGELOG.md`](CHANGELOG.md) directly**
(CI generates it on release). Create or append to `.changelog/wip/<branch>.yaml`, where the filename
is the current branch with every `/` replaced by `_` (read `.git/HEAD` for the branch name). Each
entry needs a `title` (imperative, 80 characters or less) and a `description`. User-visible work goes
under `added` / `changed` / `fixed` / `removed` / `security` / `breaking`; tests, docs, CI, and
refactors go under `internal`.

## Code Quality Expectations

1. Make the smallest correct change and leave the code better than you found it — DRY, no dead code,
   single-responsibility functions.
2. Cover changes with tests, positive and negative cases, and assert returned values rather than
   just the absence of errors. [`docs/development/TESTING.md`](docs/development/TESTING.md) sets out
   the four layers and which one a given change belongs in.
3. Avoid comments unless a linter requires them or the intent is genuinely non-obvious; code should
   be self-explanatory. Never leave implementation-history breadcrumbs (plan numbers, phases,
   requirement labels).
4. Use clear, unambiguous names — avoid single letters like `i` or abbreviations.
5. Keep docs in sync with code in the same change (see [`docs/README.md`](docs/README.md)).

## Before Opening A Pull Request

Run the local checks and make sure CI passes:

1. `cargo clippy --all-targets --all-features` — fix all warnings and errors
2. `cargo fmt --all`
3. `cargo test --no-fail-fast --all-targets --all-features`
4. If `www/default/` files changed: `cd www/default && npx prettier --write src && npm run lint`

For faster inner-loop feedback, use `cargo test --no-run` for a compile check and
`cargo test --bin agent-gateway "<module name>"` to run a single module's tests.

## Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as
contributors and maintainers pledge to make participation in our project and
our community a harassment-free experience for everyone, regardless of age, body
size, disability, ethnicity, gender identity and expression, level of experience,
nationality, personal appearance, race, religion, or sexual identity and
orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment
include:

- Using welcoming and inclusive language
- Being respectful of differing viewpoints and experiences
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members
- Avoiding obvious comments about things like code styling and indentation.
  **If you see yourself wanting to do that more than once - open an issue to update the
  clippy/rustfmt/prettier rules to address this concern once and for all. Code reviews should be
  about logic, not indenting or adding more newlines.**

Examples of unacceptable behavior by participants include:

- The use of sexualized language or imagery and unwelcome sexual attention or
  advances
- Trolling, insulting/derogatory comments, and personal or political attacks
- Public or private harassment
- Publishing others' private information, such as a physical or electronic
  address, without explicit permission
- Other conduct which could reasonably be considered inappropriate in a
  professional setting
