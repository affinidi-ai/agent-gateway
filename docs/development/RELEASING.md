# Releasing

Agent Gateway's version, `CHANGELOG.md`, and GitHub Release are produced entirely by two
workflows: [`release.yml`](../../.github/workflows/release.yml) ("Prepare release") and
[`publish-release.yml`](../../.github/workflows/publish-release.yml) ("Publish release"). There
is no manual version bump and no tag created by hand.

## Required environment and secrets

Both workflows run under the `release` GitHub Environment and need a GitHub App token to create
the release branch, commit and PR, and to push the tag:

| Secret                  | Purpose                                                            |
| ------------------------ | ------------------------------------------------------------------ |
| `RELEASE_BOT_APP_ID`     | App ID of the GitHub App used to mint the release PR/push token    |
| `RELEASE_BOT_PRIVATE_KEY`| That App's private key                                              |

The `release` environment is a security boundary and must be configured in GitHub repository
settings; workflow YAML cannot restrict which branches may read environment secrets. Configure it
with:

- **Deployment branches and tags:** `Protected branches only`, with `main` protected by the
   repository branch ruleset. Do not use an unrestricted environment or a wildcard custom branch
   policy.
- **Required reviewers:** require the release owners to approve deployments to `release`.
- **Environment secrets:** store `RELEASE_BOT_APP_ID` and `RELEASE_BOT_PRIVATE_KEY` only in this
   environment, not as repository-wide secrets.
- **GitHub App installation:** use a dedicated release App installed only on this repository with
   the minimum permissions needed by these workflows: contents write and pull requests write.

The branch-policy portion can be configured with the GitHub CLI after replacing `OWNER/REPO`:

```sh
gh api --method PUT repos/OWNER/REPO/environments/release --input - <<'JSON'
{
   "deployment_branch_policy": {
      "protected_branches": true,
      "custom_branch_policies": false
   }
}
JSON
```

Required reviewers are configured in the environment's **Protection rules** UI. Verify the result
with `gh api repos/OWNER/REPO/environments/release`; the response should show a protected-branch
deployment policy and the configured reviewer rules rather than `null` and `[]`.

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
5. Commits those changes to `release/vX.Y.Z` through the GitHub GraphQL API
   (`createCommitOnBranch`), so GitHub signs the commit as the release App and it shows as
   Verified, then opens a pull request titled `chore(release): prepare vX.Y.Z` from that branch
   with a review checklist. An existing `release/vX.Y.Z` branch is force-reset to `main` first,
   discarding anything on it.

Review that PR like any other change: edit the rendered `CHANGELOG.md` section if the wording
needs work, confirm `Cargo.toml` and `Cargo.lock` both show the new version, then squash-merge
it. `main` requires signed commits and every branch requires conventional commit messages, and an
unsigned commit on the release branch blocks the merge even though GitHub signs the squash commit.
Make wording edits in GitHub's web editor, which signs them, or push them as signed commits, with
a conventional message such as `docs(release): reword vX.Y.Z notes`. The squash merge takes the
PR title as its message, so keep it in the `chore(release): …` form if you edit it.

## Publish release

Squash-merging a `release/vX.Y.Z` PR triggers "Publish release" automatically; it does not run
for any other push to `main`, even one that happens to touch `Cargo.toml` or `CHANGELOG.md` (it
looks up the pull request associated with the pushed commit and publishes only when its head
branch starts with `release/` and its base is `main`, so an unrelated merge cannot publish). It
then:

1. Checks out the exact commit that triggered the run (not whatever `main`'s tip is by the time
   the job starts), so the binary it builds always matches the commit it tags.
2. Builds the release binary (`cargo build --release --locked --bin agent-gateway`).
3. Tags that commit `vX.Y.Z` and pushes the tag. Re-running the job after a partial failure does
   not fail on "tag already exists": it skips re-tagging if the tag already points at the same
   commit, and only errors if it points somewhere else.
4. Creates the GitHub Release from the reviewed `CHANGELOG.md` section, attaching the
   `agent-gateway-linux-x86_64` binary and its SHA256 checksum. GitHub's generated PR-title
   notes are disabled, and the binary receives a build-provenance attestation.

## Changelog fragments

See [Changelog fragments in `AGENTS.md`](../../AGENTS.md#changelog-fragments) for how to write
and categorize a fragment; the categories folded into `CHANGELOG.md` are `added`, `changed`,
`fixed`, `removed`, `security`, and `breaking`.
