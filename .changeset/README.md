# Changesets

This folder holds [changesets](https://github.com/changesets/changesets) — one
markdown file per user-facing change describing the bump it warrants.

## How releases work here

The 11 published packages — the 10 `@vendoai/*` blocks plus the `vendoai` alias
— are a **fixed lockstep group**: any changeset that bumps one bumps all of them
to the same version (see `fixed` in `config.json`). `@vendoai/telemetry` is
deliberately **left out of the fixed group** so it versions independently (it is
a pure leaf and only bumps when a changeset explicitly targets it — it cannot be
added to `ignore` because `@vendoai/vendo` depends on it). `@vendoai/engine` is
also deliberately outside the group: it is not a dependency of any Vendo package
— `vendo init`'s last-resort engine rung fetches it via `npm exec` at a version
pinned in the CLI, so it versions independently and only bumps (with the pin)
when the runner itself changes. All other workspaces (`apps/*`, `fixtures/*`,
`bench`, `corpus/*`, `spikes/*`) are `private` and are never versioned or
published.

## Adding a changeset

```bash
pnpm changeset          # interactive: pick the bump + write a summary
```

Commit the generated `.changeset/*.md` file with your PR. CI runs
`changeset status` as a **non-blocking warning** — a PR with no changeset still
merges (the fleet auto-merges); the warning is just a reminder.

## Cutting a release (orchestrator only)

```bash
pnpm changeset:version  # consume changesets, bump the group, write CHANGELOGs
```

Then commit, tag `vX.Y.Z`, and push the tag — `release.yml` publishes. See the
release runbook in the PR body / repo docs for the exact gated sequence.
