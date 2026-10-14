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
2. Computes the next version. If the version in `Cargo.toml` has no matching tag yet (the first
   release), it releases that version as-is. Otherwise it applies the chosen increment to the
   `Cargo.toml` version. The run fails if the pending fragments need a bigger increment than the
   chosen one: `breaking` entries need at least `minor` before 1.0.0 and `major` from 1.0.0, and
   `added` entries need at least `minor`. Choose a larger increment, or change the fragments.
3. Bumps `Cargo.toml` and `Cargo.lock` to that version.
4. Folds every fragment into a new `CHANGELOG.md` section and archives the fragments under
   `.changelog/history/<version>/`.
5. Opens a `release/vX.Y.Z` pull request with a review checklist.

Review that PR like any other change: edit the rendered `CHANGELOG.md` section if the wording
needs work, confirm `Cargo.toml` and `Cargo.lock` both show the new version, then merge it.

## Publish release

"Publish release" runs on a push to `main` that touches `Cargo.toml` or `CHANGELOG.md`, but only
publishes when the pushed commit is the merge of a pull request that was opened by a bot from a
`release/v*` branch of this repository. A `gate` job checks that through the GitHub API, so an
unrelated merge (a Dependabot bump, a hand-edited `CHANGELOG.md`) never reaches the `release`
environment or its secrets. The `publish` job then:

1. Checks out the exact commit that triggered the run (not whatever `main`'s tip is by the time
   the job starts), without persisting credentials, so the binary it builds always matches the
   commit it tags.
2. Skips everything when the release already has its binary asset, or when `CHANGELOG.md` has no
   reviewed section for the version.
3. Builds the release binary (`cargo build --release --locked --bin agent-gateway`) with no access
   to the release app token, which is minted afterwards, then attaches a SHA256 checksum and
   attests the binary's build provenance.
4. Tags that commit `vX.Y.Z` and pushes the tag. If the tag already exists on the same commit it
   is reused; if it points elsewhere the job fails.
5. Creates the GitHub Release from the reviewed `CHANGELOG.md` section, attaching the
   `agent-gateway-linux-x86_64` binary and its SHA256 checksum. GitHub's generated PR-title
   notes are disabled.

Because the skip decision depends on the Release's assets rather than the tag, re-running the
workflow after a partial failure (for example the tag was pushed but the Release was not created)
finishes the release.

The release app must be allowed to create tags: add it as a bypass actor on the `tags_managed`
ruleset.

## Changelog fragments

See [Changelog fragments in `AGENTS.md`](../../AGENTS.md#changelog-fragments) for how to write
and categorize a fragment; the categories folded into `CHANGELOG.md` are `added`, `changed`,
`fixed`, `removed`, `security`, and `breaking`.
