import type { Principal } from "@vendoai/core";
import { describe, expect, it } from "vitest";
import type { HostOAuthAdapter } from "./adapter.js";

// adapter.ts is the host-facing contract; these tests pin the shapes the door
// relies on: the Response-vs-subject union, the prebuilt session flow, and
// principal-as-revocation.
describe("HostOAuthAdapter contract", () => {
  it("session adapter returns the host subject or a login redirect built from returnTo", async () => {
    const adapter: HostOAuthAdapter = {
      async session(req, ctx) {
        if (req.headers.get("cookie") === "host_session=user_1") return { subject: "user_1" };
        const login = new URL("https://product.example/login");
        login.searchParams.set("return_to", ctx.returnTo);
        return Response.redirect(login.toString(), 302);
      },
      async principal(subject) {
        return { kind: "user", subject };
      },
    };
    const returnTo = "https://product.example/api/vendo/mcp/authorize?client_id=mcpc_1&state=s1";

    const anonymous = await adapter.session!(new Request(returnTo), { returnTo });
    expect(anonymous).toBeInstanceOf(Response);
    const location = new URL((anonymous as Response).headers.get("location")!);
    expect(location.origin).toBe("https://product.example");
    expect(location.searchParams.get("return_to")).toBe(returnTo);

    const authenticated = await adapter.session!(
      new Request(returnTo, { headers: { cookie: "host_session=user_1" } }),
      { returnTo },
    );
    expect(authenticated).toEqual({ subject: "user_1" });
  });

  it("legacy authorize adapter resolves to a subject or a full-page Response", async () => {
    const adapter: HostOAuthAdapter = {
      async authorize(req, ctx) {
        if (req.headers.get("authorization") !== "Bearer host-token") {
          return new Response("sign in", { status: 401 });
        }
        return { subject: `user_for:${ctx.clientName}:${ctx.scopes.join("+")}` };
      },
      async principal() {
        return null;
      },
    };
    const ctx = { clientName: "Agent", scopes: ["read", "write"] };

    const challenged = await adapter.authorize!(new Request("https://product.example/authorize"), ctx);
    expect(challenged).toBeInstanceOf(Response);
    expect((challenged as Response).status).toBe(401);

    const authorized = await adapter.authorize!(
      new Request("https://product.example/authorize", { headers: { authorization: "Bearer host-token" } }),
      ctx,
    );
    expect(authorized).toEqual({ subject: "user_for:Agent:read+write" });
  });

  it("authorize with ctx.consent carries the door-owned POST flow into a custom page", async () => {
    const adapter: HostOAuthAdapter = {
      async authorize(_req, ctx) {
        const consent = ctx.consent!;
        // A custom consent page must post transaction + csrf_token + decision
        // back to the door-owned action; the fields are opaque pass-throughs.
        return new Response(
          `<form action="${consent.action}">` +
            `<input name="transaction" value="${consent.transaction}">` +
            `<input name="csrf_token" value="${consent.csrfToken}">` +
            `</form>`,
          { headers: { "content-type": "text/html" } },
        );
      },
      async session() {
        return { subject: "user_1" };
      },
      async principal(subject) {
        return { kind: "user", subject };
      },
    };
    const result = await adapter.authorize!(new Request("https://product.example/authorize"), {
      clientName: "Agent",
      scopes: ["read"],
      consent: { action: "/api/vendo/mcp/consent", transaction: "txn_1", csrfToken: "csrf_1" },
    });
    expect(result).toBeInstanceOf(Response);
    const html = await (result as Response).text();
    expect(html).toContain('action="/api/vendo/mcp/consent"');
    expect(html).toContain('name="transaction" value="txn_1"');
    expect(html).toContain('name="csrf_token" value="csrf_1"');
  });

  it("principal resolves on every request and null means the subject is revoked", async () => {
    const users = new Map<string, Principal>([
      ["user_1", { kind: "user", subject: "user_1", display: "Avery" }],
    ]);
    // A principal-only adapter is the minimum valid implementation shape.
    const adapter: HostOAuthAdapter = {
      async principal(subject) {
        return users.get(subject) ?? null;
      },
    };

    expect(await adapter.principal("user_1")).toEqual({ kind: "user", subject: "user_1", display: "Avery" });
    expect(await adapter.principal("never-existed")).toBeNull();

    users.delete("user_1");
    expect(await adapter.principal("user_1")).toBeNull();
  });
});
