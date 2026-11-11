# Releasing

Agent Gateway's version, `CHANGELOG.md`, and GitHub Release are produced entirely by two
workflows: [`release.yml`](../../.github/workflows/release.yml) ("Prepare release") and
[`publish-release.yml`](../../.github/workflows/publish-release.yml) ("Publish release"). There
is no manual version bump and no tag created by hand.

A release is two reviewed steps and one automatic step:

```text
Prepare release (manual, pick patch / minor / major)
  -> PR "chore(release): prepare vX.Y.Z" (bot-opened, reviewed, merged to main)
       -> Publish release: build binary, checksum, attest, tag vX.Y.Z, GitHub Release
            -> the tag starts Container image:
                 build amd64 + arm64, probe, scan, push by digest,
                 merge into one manifest, tag X.Y.Z / X.Y / latest, attest
```

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
2. Computes the next version. If the version in `Cargo.toml` has no matching tag yet (the first
   release), it releases that version as-is. Otherwise it applies the chosen increment to the
   `Cargo.toml` version. The run fails if the pending fragments need a bigger increment than the
   chosen one: `breaking` entries need at least `minor` before 1.0.0 and `major` from 1.0.0, and
   `added` entries need at least `minor`. Choose a larger increment, or change the fragments.
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

"Publish release" runs on a push to `main` that touches `Cargo.toml` or `CHANGELOG.md`, but only
publishes when the pushed commit is the squash-merge of a pull request that was opened by the release app (`affinidi-semantic-release[bot]`) from a
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

## Container image

[`docker.yml`](../../.github/workflows/docker.yml) builds the `Dockerfile` and publishes it to the
GitHub Container Registry as `ghcr.io/affinidi-ai/agent-gateway`. Nothing is pushed to any other
registry.

- **Pull requests** that touch the `Dockerfile`, the Rust or dashboard sources, `Cargo.toml`,
  `Cargo.lock`, or `scripts/ci/` build the `linux/amd64` image and boot-probe it
  (`scripts/ci/boot-probe.sh` runs the entrypoint with `--help` and requires a clean exit). Nothing
  is pushed, and the job runs with a read-only token: only the tag-triggered build job holds
  `packages: write`. The boot probe also fails if the binary links a shared library the image lacks, or
  if the `xmlsec1` CLI cannot run.
- **A `v*` tag**, created by "Publish release", builds `linux/amd64` and `linux/arm64` natively and
  pushes each by digest. Each pushed image is pulled back, boot-probed and scanned, so a blocking
  scan stops the build job before the `publish` job can create a version tag. Then a `publish` job
  merges the digests into one multi-arch manifest (`scripts/ci/publish-manifest.sh`) tagged
  `X.Y.Z`, `X.Y` and, for a release that is not a pre-release, `latest`, and attests the manifest's
  build provenance. Verify an image with
  `gh attestation verify oci://ghcr.io/affinidi-ai/agent-gateway:X.Y.Z --repo affinidi-ai/agent-gateway`.

Every run scans the `Dockerfile` for misconfigurations and the built image for vulnerabilities and
embedded secrets with a pinned Trivy container (`scripts/ci/trivy-scan.sh`). The image is passed to
the scanner as a tarball, so no Docker socket or registry credential reaches it. HIGH and CRITICAL
findings, ignoring vulnerabilities that have no fix yet, are listed in the run's job summary and
block the run, so a release image with a fixable finding never gets a version tag. Setting the
repository variable `TRIVY_ENFORCE` to `false` turns them into warnings, for example while a
finding in a pinned base image waits for a fix. A fixable finding in the base image clears by
rebuilding, because the runtime stage runs `apt-get upgrade`. The image runs as the non-root `lowPrivUser`.

The runtime image is built from a digest-pinned `debian:bookworm-slim` and carries only the shared
libraries the binary links, `xmlsec1`, and the bootstrap CLIs, with no compilers, `-dev` packages
or `git`. Dependabot proposes updates to the pinned base image.

A manual run of the workflow (**Run workflow** on the Actions tab) builds both architectures and
boot-probes and scans them without pushing anything. Only a `v*` tag pushes an image, and only the
release app can create one. GitHub offers a manual run only for a workflow file that exists on the
default branch.

The build uses no layer cache, so each run compiles from scratch. The first publish creates the
package; set its visibility to public in the organization's package settings if GitHub does not
inherit it from the repository.

The arm64 job builds with `CARGO_BUILD_FLAGS=-j2` and `CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1`
because the crate runs out of memory on the arm64 runner with the defaults. It takes roughly
twice as long as amd64 (about 40 minutes against about 24); amd64 is unchanged.

### Testing the publish path before a release

A version tag can only be created by the release app, so a branch cannot publish one and no manual
run pushes an image. To exercise the whole publish path from a branch, temporarily list the branch
under `on.push.branches` in `docker.yml` and add a tag rule such as
`type=sha,prefix=dryrun-,enable=${{ github.ref_type == 'branch' }}` to the `Derive tags` step, so the
manifest is tagged only `dryrun-<short sha>`. Make the `publish` job's condition match, revert both
changes afterwards, and remove the tag and the untagged digests it leaves behind from the package.

### Trying an image locally

The package is private until it is made public, so sign in to GHCR with a token that has
`read:packages`:

```sh
gh auth token | docker login ghcr.io -u "$(gh api user --jq .login)" --password-stdin
docker pull ghcr.io/affinidi-ai/agent-gateway:<tag>
docker buildx imagetools inspect ghcr.io/affinidi-ai/agent-gateway:<tag>
docker run --rm ghcr.io/affinidi-ai/agent-gateway:<tag> --help
docker run --rm --entrypoint id ghcr.io/affinidi-ai/agent-gateway:<tag>
```

The manifest should list `linux/amd64` and `linux/arm64`, and `id` should report the non-root
`lowPrivUser`. To run the gateway, generate the Docker environment and start it with that tag:

```sh
make config-docker
TAG=ghcr.io/affinidi-ai/agent-gateway:<tag> ./scripts/d-run.sh
```

Then check `https://localhost:8443/api/v1/health`. Open the dashboard at exactly
`https://localhost:8443`, because passkey login is pinned to that origin. Remove the container with
`docker rm -f agent-gateway`.

## Changelog fragments

See [Changelog fragments in `AGENTS.md`](../../AGENTS.md#changelog-fragments) for how to write
and categorize a fragment; the categories folded into `CHANGELOG.md` are `added`, `changed`,
`fixed`, `removed`, `security`, and `breaking`.
