import type { AuditEvent, Principal } from "@vendoai/core";
import { VendoError } from "@vendoai/core";
import { afterEach, describe, expect, it } from "vitest";
import { createGuard } from "../src/index.js";
import { createPGliteStore, type PGliteStore } from "./fixtures/pglite-store.js";
import { alice, bob, call, context, FixtureTools } from "./fixtures/tools.js";

const carol: Principal = { kind: "user", subject: "user_carol", display: "Carol" };

const stores: PGliteStore[] = [];

async function store(): Promise<PGliteStore> {
  const value = await createPGliteStore();
  stores.push(value);
  return value;
}

afterEach(async () => {
  await Promise.all(stores.splice(0).map((value) => value.close()));
});

function routedConfig(sqlStore: PGliteStore, approvers: string[] = [bob.subject]) {
  return {
    store: sqlStore,
    policy: {
      rules: [{ match: { risk: "destructive" as const }, action: "ask" as const, approvers }],
    },
  };
}

async function park(guard: ReturnType<typeof createGuard>, tools: FixtureTools) {
  const parked = await guard.bind(tools).execute(call("host_destructive"), context());
  expect(parked).toMatchObject({ status: "pending-approval" });
  if (parked.status !== "pending-approval") throw new Error("expected parked call");
  return parked.approvalId;
}

describe("approval routing (multiplayer-enterprise spec, increment 1)", () => {
  it("records the rule's approvers on the parked request", async () => {
    const guard = createGuard(routedConfig(await store()));
    await park(guard, new FixtureTools());
    const [pending] = await guard.approvals.pending(alice);
    expect(pending?.approvers).toEqual([bob.subject]);
  });

  it("a routed approval is pending for both the requester and its approver, invisible to others", async () => {
    const guard = createGuard(routedConfig(await store()));
    const id = await park(guard, new FixtureTools());
    expect((await guard.approvals.pending(alice)).map((request) => request.id)).toEqual([id]);
    expect((await guard.approvals.pending(bob)).map((request) => request.id)).toEqual([id]);
    expect(await guard.approvals.pending(carol)).toEqual([]);
  });

  it("the requester cannot decide a routed approval; a foreign subject reads not-found", async () => {
    const guard = createGuard(routedConfig(await store()));
    const id = await park(guard, new FixtureTools());
    await expect(guard.approvals.decide(id, { approve: true }, alice)).rejects.toMatchObject({
      code: "blocked",
    });
    await expect(guard.approvals.decide(id, { approve: true }, carol)).rejects.toMatchObject({
      code: "not-found",
    });
    // Both rejections left it pending for the real approver.
    expect(await guard.approvals.pending(bob)).toHaveLength(1);
  });

  it("an approver's decision resumes the requester's call", async () => {
    const guard = createGuard(routedConfig(await store()));
    const tools = new FixtureTools();
    const id = await park(guard, tools);
    await guard.approvals.decide(id, { approve: true }, bob);
    await expect(guard.bind(tools).execute(call("host_destructive"), context())).resolves.toMatchObject({
      status: "ok",
    });
    expect(tools.executions).toHaveLength(1);
  });

  it("a remembered grant from a routed approval belongs to the requester, not the approver", async () => {
    const sqlStore = await store();
    const guard = createGuard(routedConfig(sqlStore));
    const id = await park(guard, new FixtureTools());
    await guard.approvals.decide(
      id,
      { approve: true, remember: { scope: { kind: "tool" }, duration: "standing" } },
      bob,
    );
    const [aliceGrant] = await guard.grants.list(alice);
    expect(aliceGrant).toMatchObject({ subject: alice.subject, tool: "host_destructive" });
    expect(await guard.grants.list(bob)).toEqual([]);
  });

  it("audits a routed decision under the requester with the approver as actor", async () => {
    const guard = createGuard(routedConfig(await store()));
    const id = await park(guard, new FixtureTools());
    await guard.approvals.decide(id, { approve: true }, bob);
    const { events } = await guard.audit.query({ principal: alice, kind: "approval" });
    const decided = events.find(
      (event: AuditEvent) => (event.detail as { approved?: boolean } | undefined)?.approved === true,
    );
    expect(decided?.principal.subject).toBe(alice.subject);
    expect((decided?.detail as { actor?: Principal }).actor).toMatchObject({ subject: bob.subject });
  });

  it("a decided routed approval leaves the pending queues of both parties", async () => {
    const guard = createGuard(routedConfig(await store()));
    const id = await park(guard, new FixtureTools());
    await guard.approvals.decide(id, { approve: false }, bob);
    expect(await guard.approvals.pending(alice)).toEqual([]);
    expect(await guard.approvals.pending(bob)).toEqual([]);
    await expect(guard.approvals.decide(id, { approve: true }, bob)).rejects.toMatchObject({
      code: "conflict",
    });
  });

  it("the TTL sweep expires routed approvals the requester cannot decide", async () => {
    const guard = createGuard(routedConfig(await store()));
    await park(guard, new FixtureTools());
    const swept = await guard.sweepExpiredApprovals?.(1, Date.now() + 60_000);
    expect(swept).toBe(1);
    expect(await guard.approvals.pending(bob)).toEqual([]);
  });

  it("abandonment denies the requester's own routed approval but never a foreign one", async () => {
    const guard = createGuard(routedConfig(await store()));
    const id = await park(guard, new FixtureTools());
    // A foreign conversation's abandonment must not touch it (isolation).
    await guard.abandonApprovals?.([id], context({ principal: bob }));
    expect(await guard.approvals.pending(bob)).toHaveLength(1);
    // The requester's own conversation moving on denies it, routing or not.
    await guard.abandonApprovals?.([id], context());
    expect(await guard.approvals.pending(bob)).toEqual([]);
  });

  it("self-approval stays byte-for-byte unchanged without approvers", async () => {
    const sqlStore = await store();
    const guard = createGuard({
      store: sqlStore,
      policy: { rules: [{ match: { risk: "destructive" as const }, action: "ask" as const }] },
    });
    const id = await park(guard, new FixtureTools());
    const [pending] = await guard.approvals.pending(alice);
    expect(pending?.approvers).toBeUndefined();
    expect(await guard.approvals.pending(bob)).toEqual([]);
    await expect(guard.approvals.decide(id, { approve: true }, bob)).rejects.toBeInstanceOf(VendoError);
    await guard.approvals.decide(id, { approve: true }, alice);
  });

  it("a requester listed among the approvers may still self-approve", async () => {
    const guard = createGuard(routedConfig(await store(), [alice.subject, bob.subject]));
    const id = await park(guard, new FixtureTools());
    await guard.approvals.decide(id, { approve: true }, alice);
    expect(await guard.approvals.pending(alice)).toEqual([]);
  });
});
