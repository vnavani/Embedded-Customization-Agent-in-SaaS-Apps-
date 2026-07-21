---
"@vendoai/core": minor
"@vendoai/guard": minor
---

Approval routing (multiplayer-enterprise spec, increment 1): an `ask` policy
rule can name `approvers` — subjects authorized to decide the approvals it
mints instead of the requester. Routed approvals are pending for both the
requester and the approvers; only an approver can decide (the requester reads
`blocked`, anyone else `not-found`); a remembered grant stays scoped to the
requester regardless of who approved; the decision audit event carries the
approver as `detail.actor`. Absent `approvers`, self-approval is unchanged.
