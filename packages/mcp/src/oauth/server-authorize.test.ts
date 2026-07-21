import {
  canonicalJson,
  type AuditEvent,
  type BlobStore,
  type Guard,
  type Principal,
  type RecordQuery,
  type RecordStore,
  type StoreAdapter,
  type VendoRecord,
} from "@vendoai/core";
import { describe, expect, it } from "vitest";
import type { HostOAuthAdapter } from "./adapter.js";
import { OAuthServer } from "./server.js";

// The authorization endpoint and consent flow: request validation, PKCE
// enforcement, exact redirect_uri matching (no open redirect), state
// round-trip, and the prebuilt consent transaction (CSRF, single-use, expiry).

const RESOURCE = "https://product.example/api/vendo/mcp";
const REDIRECT = "https://client.example/callback";
const VERIFIER = "a-very-long-pkce-verifier-that-is-valid-for-the-test-suite-1234567890";

describe("OAuthServer construction", () => {
  it("requires session or authorize on the host adapter", () => {
    const { store, guard } = makeServer({});
    expect(() => new OAuthServer({
      oauth: { async principal() { return null; } },
      store,
      guard,
    })).toThrow(TypeError);
  });
});

describe("authorization request validation", () => {
  it("rejects a request missing client_id or redirect_uri", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    for (const overrides of [{ client_id: undefined }, { redirect_uri: undefined }]) {
      const response = await harness.server.authorize(
        await authorizeRequest(clientId, overrides), RESOURCE,
      );
      expect(response.status).toBe(400);
      expect(response.headers.get("location")).toBeNull();
      expect(await response.json()).toMatchObject({ error: "invalid_request" });
    }
  });

  it("rejects an unknown client_id without redirecting", async () => {
    const harness = makeServer();
    const response = await harness.server.authorize(
      await authorizeRequest("mcpc_does_not_exist"), RESOURCE,
    );
    expect(response.status).toBe(400);
    expect(response.headers.get("location")).toBeNull();
    expect(await response.json()).toMatchObject({ error: "invalid_client" });
  });

  it("never redirects to an unregistered redirect_uri", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    for (const redirectUri of ["https://client.example/other", "https://evil.example/callback"]) {
      const response = await harness.server.authorize(
        await authorizeRequest(clientId, { redirect_uri: redirectUri, state: "s" }), RESOURCE,
      );
      expect(response.status).toBe(400);
      expect(response.headers.get("location")).toBeNull();
      expect(await response.json()).toMatchObject({ error: "invalid_request" });
    }
  });

  it("redirects unsupported response types back with the state round-tripped", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const response = await harness.server.authorize(
      await authorizeRequest(clientId, { response_type: "token", state: "state-1" }), RESOURCE,
    );
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!);
    expect(location.origin + location.pathname).toBe(REDIRECT);
    expect(location.searchParams.get("error")).toBe("unsupported_response_type");
    expect(location.searchParams.get("state")).toBe("state-1");
  });

  it.each([
    ["missing challenge", { code_challenge: undefined }],
    ["malformed challenge", { code_challenge: "too-short" }],
    ["plain method", { code_challenge_method: "plain" }],
    ["missing method", { code_challenge_method: undefined }],
  ])("requires PKCE S256: %s is redirected back as invalid_request", async (_name, overrides) => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const response = await harness.server.authorize(
      await authorizeRequest(clientId, { ...overrides, state: "state-2" }), RESOURCE,
    );
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!);
    expect(location.searchParams.get("error")).toBe("invalid_request");
    expect(location.searchParams.get("error_description")).toContain("PKCE");
    expect(location.searchParams.get("state")).toBe("state-2");
  });

  it("redirects a resource that is not this MCP server as invalid_target", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const response = await harness.server.authorize(
      await authorizeRequest(clientId, { resource: "https://other.example/mcp", state: "s3" }), RESOURCE,
    );
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!);
    expect(location.searchParams.get("error")).toBe("invalid_target");
    expect(location.searchParams.get("state")).toBe("s3");
  });

  it("mints a bound single-use code for a valid request (custom authorize flow)", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const response = await harness.server.authorize(
      await authorizeRequest(clientId, { state: "state-9" }), RESOURCE,
    );
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!);
    const code = location.searchParams.get("code");
    expect(code).toMatch(/^vmcd_[A-Za-z0-9_-]{43}$/);
    expect(location.searchParams.get("state")).toBe("state-9");

    const rows = harness.store.rows("vendo_mcp_grants");
    const grant = rows.find((row) => (row.data as { kind?: string }).kind === "code");
    expect(grant?.data).toMatchObject({
      subject: "user_1",
      clientId,
      redirectUri: REDIRECT,
      scopes: ["read", "write"],
    });
    const family = rows.find((row) => (row.data as { kind?: string }).kind === "family");
    expect(family?.data).toMatchObject({ subject: "user_1", clientId, status: "active" });
    // Codes are stored hashed, never in the clear.
    expect(JSON.stringify(rows)).not.toContain(code);
  });

  it("omits state from success and error redirects when the client sent none", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const success = await harness.server.authorize(await authorizeRequest(clientId), RESOURCE);
    expect(new URL(success.headers.get("location")!).searchParams.has("state")).toBe(false);
    const failure = await harness.server.authorize(
      await authorizeRequest(clientId, { response_type: "token" }), RESOURCE,
    );
    expect(new URL(failure.headers.get("location")!).searchParams.has("state")).toBe(false);
  });

  it("passes a Response from the custom authorize hook through unchanged", async () => {
    const harness = makeServer({
      oauth: {
        async authorize() { return new Response("host login", { status: 418 }); },
        async principal() { return null; },
      },
    });
    const clientId = await registerClient(harness.server);
    const response = await harness.server.authorize(await authorizeRequest(clientId), RESOURCE);
    expect(response.status).toBe(418);
    expect(await response.text()).toBe("host login");
  });
});

describe("prebuilt consent flow", () => {
  it("renders the consent page and persists a hashed single-use interaction", async () => {
    const harness = makeServer({ oauth: sessionOauth({ subject: "user_1" }) });
    const clientId = await registerClient(harness.server);
    const consent = await startConsent(harness, clientId, { state: "state-c" });
    expect(consent.page.status).toBe(200);
    expect(consent.page.headers.get("content-type")).toContain("text/html");
    expect(consent.transaction).toMatch(/^vmci_/);
    expect(consent.csrfToken).toMatch(/^vmcsrf_/);

    const rows = harness.store.rows("vendo_mcp_grants");
    const interaction = rows.find((row) => (row.data as { kind?: string }).kind === "consent");
    expect(interaction?.data).toMatchObject({ subject: "user_1", clientId, state: "state-c" });
    // The transaction and CSRF secrets are stored only as hashes.
    expect(JSON.stringify(rows)).not.toContain(consent.transaction);
    expect(JSON.stringify(rows)).not.toContain(consent.csrfToken);
  });

  it("approve redirects with a code and consumes the interaction (no replay)", async () => {
    const harness = makeServer({ oauth: sessionOauth({ subject: "user_1" }) });
    const clientId = await registerClient(harness.server);
    const consent = await startConsent(harness, clientId, { state: "state-a" });

    const approved = await harness.server.authorize(decision(consent, "approve"), RESOURCE);
    expect(approved.status).toBe(302);
    const location = new URL(approved.headers.get("location")!);
    expect(location.searchParams.get("code")).toMatch(/^vmcd_/);
    expect(location.searchParams.get("state")).toBe("state-a");
    expect(consentRows(harness.store)).toEqual([]);

    const replay = await harness.server.authorize(decision(consent, "approve"), RESOURCE);
    expect(replay.status).toBe(400);
    expect(await replay.json()).toMatchObject({ error: "invalid_request" });
  });

  it("deny redirects with access_denied and no code", async () => {
    const harness = makeServer({ oauth: sessionOauth({ subject: "user_1" }) });
    const clientId = await registerClient(harness.server);
    const consent = await startConsent(harness, clientId, { state: "state-d" });

    const denied = await harness.server.authorize(decision(consent, "deny"), RESOURCE);
    expect(denied.status).toBe(302);
    const location = new URL(denied.headers.get("location")!);
    expect(location.searchParams.get("error")).toBe("access_denied");
    expect(location.searchParams.get("state")).toBe("state-d");
    expect(location.searchParams.has("code")).toBe(false);
    expect(consentRows(harness.store)).toEqual([]);
  });

  it("rejects a wrong CSRF token without consuming the interaction", async () => {
    const harness = makeServer({ oauth: sessionOauth({ subject: "user_1" }) });
    const clientId = await registerClient(harness.server);
    const consent = await startConsent(harness, clientId);

    const forged = await harness.server.authorize(
      decision({ ...consent, csrfToken: "vmcsrf_forged" }, "approve"), RESOURCE,
    );
    expect(forged.status).toBe(400);
    expect(await forged.json()).toMatchObject({ error: "invalid_request" });

    // CSRF is checked before consumption: the legitimate submit still works.
    const approved = await harness.server.authorize(decision(consent, "approve"), RESOURCE);
    expect(approved.status).toBe(302);
    expect(new URL(approved.headers.get("location")!).searchParams.get("code")).toMatch(/^vmcd_/);
  });

  it("rejects a forged transaction", async () => {
    const harness = makeServer({ oauth: sessionOauth({ subject: "user_1" }) });
    const clientId = await registerClient(harness.server);
    const consent = await startConsent(harness, clientId);
    const response = await harness.server.authorize(
      decision({ ...consent, transaction: "vmci_forged" }, "approve"), RESOURCE,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_request" });
  });

  it("rejects and deletes an expired interaction", async () => {
    const harness = makeServer({ oauth: sessionOauth({ subject: "user_1" }) });
    const clientId = await registerClient(harness.server);
    const consent = await startConsent(harness, clientId);

    const record = consentRows(harness.store)[0]!;
    await harness.store.records("vendo_mcp_grants").put({
      id: record.id,
      data: {
        ...(record.data as Record<string, unknown>),
        expiresAt: new Date(Date.now() - 1_000).toISOString(),
      },
      ...(record.refs === undefined ? {} : { refs: record.refs }),
    });

    const response = await harness.server.authorize(decision(consent, "approve"), RESOURCE);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_request" });
    expect(consentRows(harness.store)).toEqual([]);
  });

  it("rejects a decision when the host session changed since the page was rendered", async () => {
    const holder = { subject: "user_1" };
    const harness = makeServer({ oauth: sessionOauth(holder) });
    const clientId = await registerClient(harness.server);
    const consent = await startConsent(harness, clientId);

    holder.subject = "user_2";
    const response = await harness.server.authorize(decision(consent, "approve"), RESOURCE);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_request" });
  });

  it("rejects malformed decision posts", async () => {
    const harness = makeServer({ oauth: sessionOauth({ subject: "user_1" }) });
    const clientId = await registerClient(harness.server);
    const consent = await startConsent(harness, clientId);

    const wrongType = await harness.server.authorize(new Request(`${RESOURCE}/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ decision: "approve" }),
    }), RESOURCE);
    expect(wrongType.status).toBe(400);

    for (const body of [
      { transaction: consent.transaction, csrf_token: consent.csrfToken },
      { transaction: consent.transaction, csrf_token: consent.csrfToken, decision: "maybe" },
      { csrf_token: consent.csrfToken, decision: "approve" },
    ]) {
      const response = await harness.server.authorize(new Request(`${RESOURCE}/authorize`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(body),
      }), RESOURCE);
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: "invalid_request" });
    }
  });

  it("rejects a decision posted to a different MCP resource", async () => {
    const harness = makeServer({ oauth: sessionOauth({ subject: "user_1" }) });
    const clientId = await registerClient(harness.server);
    const consent = await startConsent(harness, clientId);
    const response = await harness.server.authorize(
      decision(consent, "approve"), "https://other.example/mcp",
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_request" });
  });

  it("passes the host login redirect through for a sessionless request", async () => {
    const harness = makeServer({
      oauth: {
        async session(_req, ctx) {
          return Response.redirect(`https://product.example/login?returnTo=${encodeURIComponent(ctx.returnTo)}`, 303);
        },
        async principal() { return null; },
      },
    });
    const clientId = await registerClient(harness.server);
    const response = await harness.server.authorize(await authorizeRequest(clientId), RESOURCE);
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toContain(encodeURIComponent(`${RESOURCE}/authorize`));
  });

  it("rejects a host session that resolves no subject", async () => {
    const harness = makeServer({ oauth: sessionOauth({ subject: "" }) });
    const clientId = await registerClient(harness.server);
    const response = await harness.server.authorize(await authorizeRequest(clientId), RESOURCE);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_request" });
  });

  it("rejects a custom consent UI whose subject differs from the host session", async () => {
    const harness = makeServer({
      oauth: {
        async session() { return { subject: "user_1" }; },
        async authorize() { return { subject: "user_2" }; },
        async principal(subject): Promise<Principal | null> { return { kind: "user", subject }; },
      },
    });
    const clientId = await registerClient(harness.server);
    const response = await harness.server.authorize(await authorizeRequest(clientId), RESOURCE);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_request" });
    expect(consentRows(harness.store)).toEqual([]);
  });

  it("lets a custom consent UI approve directly when subjects match", async () => {
    const consentContexts: Array<{ consent?: unknown }> = [];
    const harness = makeServer({
      oauth: {
        async session() { return { subject: "user_1" }; },
        async authorize(_req, ctx) {
          consentContexts.push(ctx);
          return { subject: "user_1" };
        },
        async principal(subject): Promise<Principal | null> { return { kind: "user", subject }; },
      },
    });
    const clientId = await registerClient(harness.server);
    const response = await harness.server.authorize(
      await authorizeRequest(clientId, { state: "state-x" }), RESOURCE,
    );
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!);
    expect(location.searchParams.get("code")).toMatch(/^vmcd_/);
    expect(location.searchParams.get("state")).toBe("state-x");
    // The custom UI still receives the door-owned consent flow handles.
    expect(consentContexts[0]?.consent).toMatchObject({
      action: expect.stringContaining("/authorize"),
      transaction: expect.stringMatching(/^vmci_/),
      csrfToken: expect.stringMatching(/^vmcsrf_/),
    });
    expect(consentRows(harness.store)).toEqual([]);
  });
});

interface ServerOptions {
  oauth?: HostOAuthAdapter;
}

function makeServer(options: ServerOptions = {}) {
  const store = new MemoryStore();
  const audits: AuditEvent[] = [];
  const guard: Guard = {
    async check() { return { action: "run", decidedBy: "default" }; },
    async report(event) { audits.push(event); },
    async directions() { return []; },
    onApprovalDecision() { return () => undefined; },
  };
  const server = new OAuthServer({
    oauth: options.oauth ?? {
      async authorize() { return { subject: "user_1" }; },
      async principal(subject): Promise<Principal | null> { return { kind: "user", subject }; },
    },
    store,
    guard,
  });
  return { server, store, audits, guard };
}

function sessionOauth(holder: { subject: string }): HostOAuthAdapter {
  return {
    async session() { return { subject: holder.subject }; },
    async principal(subject): Promise<Principal | null> { return { kind: "user", subject }; },
  };
}

async function registerClient(server: OAuthServer): Promise<string> {
  const response = await server.register(new Request(`${RESOURCE}/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "Test client", redirect_uris: [REDIRECT], scope: "read write" }),
  }));
  expect(response.status).toBe(201);
  const body = await response.json() as { client_id: string };
  return body.client_id;
}

async function authorizeRequest(
  clientId: string,
  overrides: Record<string, string | undefined> = {},
): Promise<Request> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER)));
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: Buffer.from(digest).toString("base64url"),
    code_challenge_method: "S256",
    scope: "read write",
    resource: RESOURCE,
  });
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) params.delete(key);
    else params.set(key, value);
  }
  return new Request(`${RESOURCE}/authorize?${params}`);
}

interface ConsentFields {
  transaction: string;
  csrfToken: string;
}

async function startConsent(
  harness: ReturnType<typeof makeServer>,
  clientId: string,
  overrides: Record<string, string | undefined> = {},
) {
  const page = await harness.server.authorize(await authorizeRequest(clientId, overrides), RESOURCE);
  const html = await page.clone().text();
  return {
    page,
    html,
    transaction: inputValue(html, "transaction"),
    csrfToken: inputValue(html, "csrf_token"),
  };
}

function decision(fields: ConsentFields, choice: string): Request {
  return new Request(`${RESOURCE}/authorize`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      transaction: fields.transaction,
      csrf_token: fields.csrfToken,
      decision: choice,
    }),
  });
}

function inputValue(html: string, name: string): string {
  const match = html.match(new RegExp(`<input[^>]+name="${name}"[^>]+value="([^"]+)"`, "i"));
  if (!match?.[1]) throw new Error(`Consent page omitted ${name}`);
  return match[1];
}

function consentRows(store: MemoryStore): VendoRecord[] {
  return store.rows("vendo_mcp_grants").filter((row) => (row.data as { kind?: string }).kind === "consent");
}

class MemoryStore implements StoreAdapter {
  readonly #collections = new Map<string, Map<string, VendoRecord>>();

  rows(collection: string): VendoRecord[] {
    return [...(this.#collections.get(collection)?.values() ?? [])];
  }

  records(collection: string): RecordStore {
    const rows = this.#collections.get(collection) ?? new Map<string, VendoRecord>();
    this.#collections.set(collection, rows);
    return {
      async get(id) { return rows.get(id) ?? null; },
      async put(record) {
        const prior = rows.get(record.id);
        const now = new Date().toISOString();
        const stored: VendoRecord = {
          id: record.id,
          data: structuredClone(record.data),
          ...(record.refs === undefined ? {} : { refs: { ...record.refs } }),
          createdAt: prior?.createdAt ?? now,
          updatedAt: now,
        };
        rows.set(stored.id, stored);
        return stored;
      },
      async claim(expected, replacement) {
        const current = rows.get(expected.id);
        if (
          !current
          || canonicalJson(current.data) !== canonicalJson(expected.data)
          || canonicalJson(current.refs ?? null) !== canonicalJson(expected.refs ?? null)
        ) return false;
        if (replacement === undefined) {
          rows.delete(expected.id);
        } else {
          rows.set(expected.id, {
            id: expected.id,
            data: structuredClone(replacement.data),
            ...(replacement.refs === undefined ? {} : { refs: { ...replacement.refs } }),
            createdAt: current.createdAt,
            updatedAt: new Date().toISOString(),
          });
        }
        return true;
      },
      async delete(id) { rows.delete(id); },
      async list(query?: RecordQuery) {
        const records = [...rows.values()].filter((record) => {
          if (query?.ids && !query.ids.includes(record.id)) return false;
          return Object.entries(query?.refs ?? {}).every(([key, value]) => record.refs?.[key] === value);
        });
        return { records: records.slice(0, query?.limit) };
      },
    };
  }

  blobs(): BlobStore {
    return {
      async put() { return undefined; },
      async get() { return null; },
      async delete() { return undefined; },
      async list() { return []; },
    };
  }

  async ensureSchema(): Promise<void> {
    return undefined;
  }
}
