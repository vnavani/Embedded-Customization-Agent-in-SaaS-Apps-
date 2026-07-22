# Multiplayer & enterprise: shared work, org identity, admin approvals

Status: PROPOSAL (2026-07-21) — decision-record draft for a multiplayer/
enterprise lane. Not approved; the Cloud-line question in §8 is an owner
decision and gates increments 2–4. Grounded in the current tree — every claim
carries a file reference.

## Summary

Vendo today is single-player by construction: one `subject` partitions every
durable row, approvals are strictly self-approval, and everything cross-user is
a `cloud-required` stub. This lane turns that into a multiplayer/enterprise
story in five additive increments, ordered by what actually blocks an
enterprise deployment rather than by build appeal:

1. **Approval routing** — a policy rule can send an approval to someone other
   than the requester (admin-approves-member). No org machinery required.
2. **Org identity** — restore the killed org layer (membership, org subjects),
   fed by the SSO claims the auth presets currently drop.
3. **Roles as policy inputs** — `role` joins `tool`/`risk`/`venue`/`presence`
   as a rule-match dimension. No RBAC engine.
4. **Sharing as grants** — one `vendo_shares` table; threads and apps become
   shareable without touching their ownership columns.
5. **Liveness** — SSE fan-out keyed on the existing `revision` counters. No
   CRDTs, no presence.

Plus the hardening enterprise buyers audit for (§7): per-scope secrets, audit
tamper-evidence, a retention runner, deprovision-to-erase.

## 1. Where the tree stands today

Facts, so the increments read against reality:

- `Principal` is `{ kind: "user" | "org", subject, display?, ephemeral? }`;
  the org storage layer that made `kind: "org"` real was cut (kill-list §A5)
  and the wire rejects host-minted org principals
  (`packages/core/src/principal.ts`).
- The tenant axis was deliberately deleted — `subject` is the one partition
  key (decision 17, `docs/archive/contracts/00-overview.md`); the schema-v3
  org tables `vendo_orgs` / `vendo_org_members` were dropped
  (`packages/store/src/schema.ts` header note).
- Approvals are self-approval only: a decision arriving under any principal
  other than the request's own subject reads as `not-found`
  (`packages/guard/src/guard.ts`, ownership checks in `approvals.get`/`decide`).
- Guard rules match `tool` (glob), `risk`, `venue`, `presence` → `run` /
  `ask` / `block` (`packages/guard/src/types.ts`, `policy.ts`); there is no
  role or admin concept anywhere in the package.
- Sharing/publishing throw `cloud-required` from the apps runtime
  (`packages/apps/src/runtime.ts`); `/orgs/*` routes refuse unconditionally,
  key or no key (`packages/vendo/src/wire/shared.ts`, `orgsCloudRequired`).
- Sharing hands over a **copy with a freshly minted id** (decision 14) — a
  deliberate security property (artifacts carry zero authority), and also the
  reason there is no live shared state.
- `RunContext.actor` exists precisely for "human behind a request made under
  a different principal" audit enrichment, and nothing populates it
  (`packages/core/src/run-context.ts`).
- The one genuinely cross-user capability that already ships: audit
  query/export with an optional principal filter
  (`packages/guard/src/guard.ts`, `audit.query`/`export`).
- `vendo_secrets` is host-global and name-keyed; subject/app erase never
  touches it (`packages/store/src/erase.ts`).
- The auth presets (auth0/clerk/supabase/auth-js/jwt,
  `packages/vendo/src/auth-presets/`) resolve a host session to a bare
  `Principal` and drop every other claim — org and role claims included.

## 2. Principles (what the lane must not break)

- **Additive within the version train.** Every schema change is a new table or
  a new nullable column; no rewrite of existing rows, no flag-day.
- **Artifacts still carry zero authority.** Decision 14's property survives:
  a share is a *grant row minted server-side*, never authority embedded in a
  document. Import/fork still mints fresh ids.
- **The guard choke point stays singular.** Roles, routed approvals, and
  share checks all express as inputs to the existing `guard.bind` pipeline —
  no second enforcement path.
- **No RBAC engine, no tenant column.** Roles are strings matched by policy
  rules; scoping stays subject-shaped (`vendo:org:<id>` is a subject).
- **Ephemeral principals stay out.** Anonymous sessions never hold shares,
  org membership, or routed approvals; adoption
  (`adoptEphemeralSubject`) continues to drop grant-shaped state.

## 3. Increment 1 — approval routing (admin approves)

The single biggest enterprise blocker, and the only increment that needs no
org machinery at all.

- **Policy shape** (additive on `GuardRule`): `approvers?: string[]` — a list
  of subjects (later: org subjects / roles, §5) authorized to decide approvals
  minted by this rule. Absent → today's self-approval, unchanged.
- **Guard behavior**: an approval minted by an `ask` rule with `approvers`
  records them on the `ApprovalRequest`. `approvals.get`/`list` answer for
  the requester *and* any listed approver; `decide` accepts a decision from a
  listed approver, records the decider as `actor` on the decision audit event
  (finally consuming `RunContext.actor`'s shape), and keeps minting the
  resulting `PermissionGrant` **for the requester** — the grant's blast
  radius does not change with who approved it.
- **Wire**: `/approvals` already carries the principal; the only addition is
  that a listed approver sees the pending row. UI chrome renders it with the
  existing approval card (the card already shows whose request it is via
  `inputPreview`).
- **Audit**: decision events gain `actor` = the approver principal; the
  requester principal stays the event's `subject` (partition unchanged).
- **Non-goals**: quorums, escalation chains, expiry. One approver from the
  set decides. (Expiry was cut in round 4 — decision 21 — and stays cut.)

## 4. Increment 2 — org identity, restored where it was cut

- Restore `vendo_orgs` / `vendo_org_members` exactly as schema-v3 had them
  (id, display; org_id + subject + role, PK `(org_id, subject)`), as a new
  schema version. The kill-list cut them for having no consumer; increments
  3–4 are the consumers.
- `vendo:org:<orgId>` becomes mintable **server-side only** — the wire still
  rejects host-supplied `kind: "org"` principals; org subjects appear only as
  grantees/scopes resolved from membership, never as a caller identity.
- **Claims through the presets**: `composeHostAuthPreset` gains an optional
  `claims` mapper — `(verifiedClaims) => { orgId?, role? }` — so the org and
  role a host's IdP already asserts stop being dropped at the door. No new
  identity source: the host IdP stays the authority; Vendo stores membership
  as a cache of what the IdP asserted, refreshed on session resolution.
- Membership writes are host-API-only in OSS (the host syncs from its IdP);
  invite flows, SCIM connectors, and org admin console stay Cloud (§8).

## 5. Increment 3 — roles as policy inputs

- `GuardRule` gains `role?: string | string[]` matched against the resolved
  membership role of the current principal in the current org scope.
- `approvers` (increment 1) learns two new member shapes:
  `vendo:org:<id>` (any member) and `vendo:org:<id>#<role>` (members holding
  a role). Resolution happens in the guard via a membership lookup seam so
  the guard package still depends on core only.
- Audit read scoping: `audit.query` with no principal filter — the
  enterprise-wide read — becomes gateable by the same rule shape (a host
  wires "audit export requires role admin" as policy, not code).

## 6. Increment 4 — sharing as grants, not copies

- One new table:

  ```sql
  CREATE TABLE vendo_shares (
    id         TEXT PRIMARY KEY,          -- shr_
    kind       TEXT NOT NULL,             -- 'thread' | 'app'
    resource   TEXT NOT NULL,             -- thr_ / app_ id
    grantee    TEXT NOT NULL,             -- subject or vendo:org:<id>[#role]
    capability TEXT NOT NULL,             -- 'view' | 'use' | 'edit'
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (kind, resource, grantee)
  );
  ```

- Read paths for threads/apps consult owner-or-share; the fast path (owner
  only) is one indexed miss. Writes require `edit`; `use` covers running an
  app without editing it; `view` is read-only.
- Decision 14 is untouched for **export/import/fork/publish** — those still
  copy with fresh ids. A share is the new, distinct verb for *live* access,
  and it is a server-minted row, so artifacts still carry zero authority.
- App data boundary: a shared app's per-subject state stays per-subject
  (`vendo_state` PK is already `(app_id, subject)` — sharing composes with
  it for free); collection data keyed `app:<appId>:…` is shared with the
  app, which is exactly what "shared app" means and gets called out loudly
  in the share consent copy.
- Revocation is row deletion; grant invalidation stays loud (the block-actions
  wave's invalidation semantics apply unchanged).

## 7. Enterprise hardening (parallel track, any order)

- **Per-scope secrets**: `vendo_secrets` gains a nullable `scope` column
  (default null = host-global today); org-scoped secrets join the erase
  cascade for their org. Egress substitution is unchanged — handles stay
  handles.
- **Audit tamper-evidence**: hash-chain the audit stream (each event carries
  `prev` = SHA-256 of the previous event in its partition); `export()` emits
  the chain so an external archiver can verify gaps. Erase-vs-audit tension
  resolved the standard way: `erase.bySubject` pseudonymizes audit rows
  (severs the subject linkage) instead of deleting them; deletion remains
  available explicitly (`{ dropAudit: true }`) for hosts whose counsel wants
  true deletion.
- **Retention runner**: ship the documented "host SQL on the host's cron" as
  an actual `store.retention({ days, tables? })` helper plus a `/tick` step —
  the machinery exists (`/tick` already runs schedules), only the wiring is
  missing. The host-SQL escape hatch stays.
- **Deprovision**: the SSO claims mapper (§4) recognizing a deactivated
  session plus the existing `erase.bySubject` is the whole SCIM story OSS
  needs; a real SCIM endpoint is Cloud console territory.

## 8. The Cloud-line decision (owner call — gates increments 2–4)

The Cloud definition (2026-07-17) draws the line at "coordination that is
inherently multi-party" and lists orgs/members/SSO and sharing as Cloud-only.
This lane's increments sit exactly on that line, so name the tension honestly:

- **Reading A (keep the list as written)**: increments 2–4 are built as the
  Cloud implementations of OSS seams — OSS keeps the shapes, the 402s, and
  gains only increment 1 (approval routing is single-player-adjacent policy
  machinery and is uncontroversially OSS).
- **Reading B (recommended)**: distinguish *cross-deployment* coordination
  (registry, publish, pin review, billing, console — Cloud, unchanged) from
  *single-deployment* collaboration (org rows and share rows in the host's
  own Postgres, resolved from the host's own IdP). The latter needs no
  Vendo-run service to exist, which makes it exactly the thing the hard BYO
  rule protects: every capability a single deployment can run itself keeps a
  no-key path. Enterprise buyers who self-host are the segment that wants
  orgs most; a Cloud-only org story excludes precisely them.

Under reading B, Cloud still sells what only Cloud can do for these features:
hosted membership sync (SCIM/IdP connectors), the org admin console, invite
flows, cross-deployment share/publish. The OSS surface is tables + wire
routes + guard inputs — the parts that are "rows in a database the host
already runs."

Recommendation: **B**, recorded as an amendment to the Cloud definition's
feature-split table, not a silent contradiction of it.

## 9. What this lane deliberately does not build

- **CRDTs / OT / live co-editing** — turn-based agent threads don't need
  them; `revision` CAS + SSE liveness covers "my teammate's turn appeared."
- **Presence, cursors, typing indicators** — no demonstrated need; revisit
  only with evidence.
- **A tenant column** — decision 17 stays; orgs are subjects, scoping stays
  subject-shaped.
- **An RBAC engine** — roles are strings the host's IdP asserts and policy
  rules match; there are no Vendo-defined permissions, role editors, or
  permission matrices.
- **Approval quorums/expiry/escalation** — one approver decides; the cuts of
  round 4 stay cut until a customer proves the need.

## 10. Sequencing and verification

Each increment lands independently green (`build/test/typecheck/lint` plus
the conformance suite), in order 1 → 2 → 3 → 4 → 5; §7 items slot anywhere
after 2. Increment 1 carries no schema change and can ship in the current
train; 2 and 4 bump the store schema version with additive DDL and dual-run
tests on PGlite + Postgres (the `backends()` parameterization already does
this for every store change).
