# Workflow Design Notes

This directory contains the GitHub Actions workflows for Lite-Plus-agent. Keep this
document updated when changing release, snapshot, or Docker publishing behavior.

The important design split is:

- Stable releases use normal GitHub releases and semver tags.
- Snapshot builds use GitHub prereleases named `Snapshot-yymmddhhMM`.
- The Docker snapshot image intentionally uses the mutable tag `snapshot`.
- Stable auto-update must not consume snapshot prereleases.

## Workflow Summary

| Workflow | Trigger | Main output | Prerelease handling |
| --- | --- | --- | --- |
| `build.yml` | Push to `main` | CI build artifacts for the pushed commit | Not a release workflow |
| `snapshot.yml` | Manual dispatch only | One snapshot prerelease plus `ghcr.io/...:snapshot` | Creates prereleases only |
| `release.yml` | Published GitHub release | Release binary assets | Skips prereleases |
| `release-docker.yml` | Published GitHub release, manual dispatch | Stable Docker image tags | Skips prerelease release events |
| `generate-release-notes.yml` | Published GitHub release, manual dispatch | Generated release notes | Skips prerelease release events |
| `follow-lite-agent.yml` | Hourly schedule, manual dispatch | Merge a new Lite-agent stable tag, bump `lite_plus_agent` by one patch, publish Plus-agent | Ignores Snapshot / prerelease / draft |

## Common Build Conventions

Binary names must remain compatible with the updater, installer scripts, and
Dockerfile:

- Release and snapshot assets are named `Lite-Plus-agent-${GOOS}-${GOARCH}`.
- Windows assets append `.exe`.
- The Dockerfile expects prebuilt Linux binaries named
  `Lite-Plus-agent-${TARGETOS}-${TARGETARCH}` in the Docker build context.

The agent version and update repository are embedded with:

```sh
-ldflags="-s -w -X github.com/nuomiiiii/lite-agent/update.CurrentVersion=${VERSION}+${GITHUB_SHA::7} -X github.com/nuomiiiii/lite-agent/update.Repo=${GITHUB_REPOSITORY}"
```

Do not remove this without changing the agent update and reporting logic. Stable
release binaries use semver build metadata for the seven-character internal
identifier, for example `2.1.61+be3daa4`. Semver comparison ignores that
identifier, so a `2.1.6+xxxxxxx` agent upgrades to public release `2.1.61`
without repeatedly updating once installed. The agent uses
`update.CurrentVersion` for update checks and reports it as part of basic info.
Embedding `update.Repo` keeps fork builds on the fork's releases even
if the source default changes during an upstream merge.

Build, snapshot, stable release, and Docker publishing all install Go `1.26.10`
explicitly. Do not use `go-version-file: go.mod`, do not set `check-latest: true`,
and do not let Actions pick a newer or older toolchain. After setup, confirm
`go env GOVERSION` is `go1.26.10` and set `GOTOOLCHAIN=local`. Keep `go.mod`
on `go 1.26.10` with `toolchain go1.26.10`.

## `build.yml`

Purpose: quick build validation on `main`.

Trigger:

- Runs on every push to `main`.
- A single `git push` containing multiple commits creates one workflow run for
  the pushed ref tip. Multiple separate pushes can create multiple runs.

Jobs:

- Builds a matrix of Windows, Linux, macOS, and FreeBSD targets.
- Excludes unsupported combinations:
  - `windows/arm`
  - `darwin/386`
  - `darwin/arm`
- Uploads build artifacts to the workflow run.

This workflow does not publish GitHub releases or Docker images.

## `snapshot.yml`

Purpose: publish the latest development build from `main`.

Trigger:

- Manual `workflow_dispatch` only. Pushing `main` does not publish a snapshot.
- `release:` and `[skip snapshot]` are no longer used to suppress snapshots.

Race protection:

- Uses concurrency group `snapshot-${{ github.ref }}` with
  `cancel-in-progress: true`.
- Validates that the workflow is running for `refs/heads/main`.
- Validates that `GITHUB_SHA` is still the current `origin/main` commit before
  building.
- Re-checks current `origin/main` before publishing the prerelease.
- Re-checks current `origin/main` before publishing the Docker image.

This means that several separate pushes in a row may start several runs, but the
latest run is the one intended to publish. If an older run has already published,
the newer run deletes older snapshot prereleases after it publishes.

Snapshot version format:

```text
Snapshot-yymmddhhMM
```

The timestamp is UTC. The generated value is embedded into the binaries as
`update.CurrentVersion`.

Binary release job:

- Builds the same OS/architecture matrix as the normal release workflow.
- Uploads all binaries as workflow artifacts.
- Creates a GitHub release with `--prerelease`.
- Uploads all `Lite-Plus-agent-*` artifacts to that prerelease.

Snapshot retention:

- After creating the current snapshot prerelease, the workflow lists prereleases
  whose tag starts with `Snapshot-`.
- It deletes every matching old snapshot release and its tag.
- The intended release state is exactly one snapshot prerelease: the latest one.

Docker job:

- Builds Linux `amd64` and `arm64` binaries for the Docker build context.
- Builds and pushes a multi-arch image.
- Publishes only this tag:

```text
ghcr.io/<owner>/<repo>:snapshot
```

### Why Docker Uses Only `:snapshot`

The mutable `snapshot` Docker tag is intentional.

Users who run prerelease containers usually want to follow the newest snapshot.
A stable tag reference such as `ghcr.io/...:snapshot` lets Docker image updaters
pull the same tag and detect that the image digest changed.

Adding immutable timestamp tags like `Snapshot-yymmddhhMM` can be useful for
traceability, but users pinned to such a timestamp tag will not automatically
move to the next snapshot. If timestamp image tags are added later, keep
`:snapshot` as the moving tag.

### Snapshot Docker Updates

Container-based updates and binary self-updates are different mechanisms:

- Watchtower-style tools update containers by comparing the image behind the
  configured tag. They should work with the mutable `:snapshot` tag because each
  new snapshot push changes the image digest.
- The agent's own self-update logic updates the binary inside the running
  container filesystem. That does not update the Docker image. If the container
  is recreated, the image contents win again.
- The Dockerfile creates `/.lite-plus-agent-container` and keeps
  `/.lite-agent-container` and `/.komari-agent-container` for agents upgraded
  from Lite-agent or komari-agent. Snapshot-aware auto-update uses that marker
  to skip binary self-update in containers and leave updates to image refresh
  tooling.

For Docker prerelease users, prefer `:snapshot` plus a container image updater.
For non-container prerelease users, snapshot-aware binary self-update follows
the latest `Snapshot-*` GitHub prerelease.

## `release.yml`

Purpose: attach stable release binaries to a published GitHub release.

Trigger:

- Runs when a GitHub release is published.

Prerelease guard:

```yaml
if: ${{ !github.event.release.prerelease }}
```

This guard is important. Snapshot releases are GitHub prereleases, and this
workflow must not attach stable-release assets or perform stable-release behavior
for a snapshot.

Jobs:

- Builds Windows, Linux, macOS, and FreeBSD binaries.
- Embeds the release tag as `update.CurrentVersion`.
- Uploads the matching binary to the GitHub release.

## `release-docker.yml`

Purpose: publish stable Docker images.

Trigger:

- Runs when a GitHub release is published.
- Can be run manually with `workflow_dispatch`.

Prerelease guard:

```yaml
if: ${{ github.event_name == 'workflow_dispatch' || !github.event.release.prerelease }}
```

This means prerelease release events do not publish stable Docker tags. Manual
runs are still allowed.

Jobs:

- Builds Linux `amd64` and `arm64` binaries for the Docker build context.
- Builds and pushes a multi-arch image.
- On release events, publishes:
  - the release tag, such as `v1.2.3`
  - `latest`

Do not let snapshot prereleases publish `latest`.

## `generate-release-notes.yml`

Purpose: generate and apply GitHub release notes.

Trigger:

- Runs when a GitHub release is published.
- Can be run manually for a specific tag.

Prerelease guard:

```yaml
if: ${{ github.event_name == 'workflow_dispatch' || !github.event.release.prerelease }}
```

Snapshot prereleases intentionally keep their simple automated snapshot notes and
do not trigger normal stable-release note generation.

## Auto-Update Interaction

Stable auto-update behavior:

- The agent calls `update.CheckAndUpdate()` when auto-update is enabled.
- `CheckAndUpdate()` uses `github.com/rhysd/go-github-selfupdate/selfupdate`.
- That library's normal latest-release detection skips GitHub prereleases.
- Therefore stable agents with auto-update enabled should not update to
  `Snapshot-*` prereleases.

Snapshot auto-update behavior:

- Snapshot builds are identified by the embedded `update.CurrentVersion` prefix
  `Snapshot-`.
- Snapshot agents list GitHub releases and select the newest non-draft
  prerelease whose tag starts with `Snapshot-` and contains the exact platform
  asset name.
- Snapshot agents update only to another snapshot prerelease.
- Snapshot agents running in Docker skip binary self-update when
  `/.lite-plus-agent-container`, `/.lite-agent-container`, or
  `/.komari-agent-container` exists.

The Docker image tag is not used as the binary version source. The Docker tag is
always `snapshot` by design. Snapshot binary update decisions use the embedded
binary version `update.CurrentVersion == Snapshot-yymmddhhMM` and GitHub release
metadata instead.

Container guidance for future update changes:

- A binary running in Docker can potentially replace `/app/lite-agent`, but
  that only changes the container's writable layer.
- After self-update, the current code exits with status `42`; the container needs
  a restart policy or external supervisor to come back.
- Recreating the container from the image discards any in-container binary
  replacement.
- Prefer image-level updates for Docker deployments.

## `follow-lite-agent.yml`

Purpose: when Lite-agent publishes a new stable four-part tag, merge it and
ship Plus-agent with the last segment increased by one (`0.0.0.1` → `0.0.0.2`).

Trigger:

- Hourly cron on `main`.
- Manual `workflow_dispatch`, optionally with `lite_agent_tag`.

It does not follow Snapshot, prerelease, or draft releases. If
`plus-baseline.json` `lite_agent` already equals that tag, it exits. Version,
repo, readme branding, and changelog rows that Lite also bumps are resolved
automatically (keep Plus names/numbers, keep Lite's new functional files and
changelog). Any other merge conflict still opens `follow/lite-agent-<tag>` and
a PR; no tag is created.

After a successful merge it keeps Xray / sing-box requires, rewrites
`update.CurrentVersion` and `update.Repo`, writes only `lite_plus_agent` +
`lite_agent` into `plus-baseline.json`, runs `go test -tags with_quic,with_utls`
on `./terminal/`, `./update/`, and `./cmd/` (the packages a Lite follow actually
touches), then tags and publishes a Plus-agent GitHub Release. Binary assets are uploaded
by this workflow so the follow still ships if `GITHUB_TOKEN` cannot start
`release.yml`. Set repository secret `PLUS_FOLLOW_TOKEN` (contents + workflow
scope) so the follow job can also dispatch `release-docker.yml`.

## `plus-baseline.json`

This file is for `follow-lite-agent.yml` only. The running agent does not read it.

Keep exactly two keys:

- `lite_plus_agent`: this repo's current Plus-agent version
- `lite_agent`: the Lite-agent tag already merged

Do not add `plus`, `lite`, `lite_web`, or `lite_theme`. Do not copy the
controller/web five-field schema into this repo.

When shipping an Agent-only Plus change, bump `lite_plus_agent` to match
`update.CurrentVersion` and leave `lite_agent` unchanged. When following a
Lite-agent stable tag, set `lite_agent` to that tag and bump
`lite_plus_agent` by one patch.

## Change Checklist

Before changing these workflows, check:

- Snapshot releases are still created with `--prerelease`.
- Stable release workflows still skip prereleases.
- Snapshot cleanup still deletes old `Snapshot-*` prereleases after the new one
  is created.
- Docker snapshot publishing still keeps the mutable `snapshot` tag.
- Stable Docker publishing does not run for snapshot prereleases and does not
  publish `latest` for snapshots.
- Binary asset names still match updater, installer, and Dockerfile expectations.
- `update.CurrentVersion` is still embedded in all release-producing binaries.
- `plus-baseline.json` still has only `lite_plus_agent` and `lite_agent`.
- `follow-lite-agent.yml` still bumps only the fourth Plus-agent segment and
  still refuses extra baseline keys.
- Race protection still prevents stale `main` commits from publishing snapshots.
