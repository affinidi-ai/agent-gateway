# Releasing

Agent Gateway's version, `CHANGELOG.md`, and GitHub Release are produced entirely by two
workflows: [`release.yml`](../../.github/workflows/release.yml) ("Prepare release") and
[`publish-release.yml`](../../.github/workflows/publish-release.yml) ("Publish release"). There
is no manual version bump and no tag created by hand.

## Required environment and secrets

Both workflows run under the `release` GitHub Environment and need a GitHub App token to open
the release PR and push the tag:

| Secret                  | Purpose                                                            |
| ------------------------ | ------------------------------------------------------------------ |
| `RELEASE_BOT_APP_ID`     | App ID of the GitHub App used to mint the release PR/push token    |
| `RELEASE_BOT_PRIVATE_KEY`| That App's private key                                              |

## Prepare release

Run manually from the Actions tab: `Prepare release` → `Run workflow`, choosing `patch`, `minor`,
or `major`. It must be run from `main` and refuses to start if a `release/*` PR is already open.
It then:

1. Validates every `.changelog/wip/*.yaml` fragment.
2. Computes the next version. If the version already in `Cargo.toml` has no matching tag yet
   (the first release, or a previous prepare run that was never merged), it releases that version
   as-is instead of bumping past it; otherwise it bumps from the last tagged version by the chosen
   increment, or by whatever the fragments imply (`breaking` entries force a major/minor bump,
   `added` entries force at least a minor bump) if a larger bump is implied than requested.
3. Bumps `Cargo.toml` and `Cargo.lock` to that version.
4. Folds every fragment into a new `CHANGELOG.md` section and archives the fragments under
   `.changelog/history/<version>/`.
5. Opens a `release/vX.Y.Z` pull request with a review checklist.

Review that PR like any other change: edit the rendered `CHANGELOG.md` section if the wording
needs work, confirm `Cargo.toml` and `Cargo.lock` both show the new version, then merge it.

## Publish release

Merging a `release/vX.Y.Z` PR triggers "Publish release" automatically; it does not run for any
other push to `main`, even one that happens to touch `Cargo.toml` or `CHANGELOG.md` (detected
from the merge commit's message, so an unrelated merge cannot publish). It then:

1. Checks out the exact commit that triggered the run (not whatever `main`'s tip is by the time
   the job starts), so the binary it builds always matches the commit it tags.
2. Builds the release binary (`cargo build --release --bin agent-gateway`).
3. Tags that commit `vX.Y.Z` and pushes the tag. Re-running the job after a partial failure does
   not fail on "tag already exists": it skips re-tagging if the tag already points at the same
   commit, and only errors if it points somewhere else.
4. Creates the GitHub Release from the reviewed `CHANGELOG.md` section, attaching the binary.

## Changelog fragments

See [Changelog fragments in `AGENTS.md`](../../AGENTS.md#changelog-fragments) for how to write
and categorize a fragment; the categories folded into `CHANGELOG.md` are `added`, `changed`,
`fixed`, `removed`, `security`, and `breaking`.
