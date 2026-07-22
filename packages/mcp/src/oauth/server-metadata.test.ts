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
import { afterEach, describe, expect, it, vi } from "vitest";
import type { HostOAuthAdapter } from "./adapter.js";
import { canonicalUri, OAuthServer, sameCanonicalUri } from "./server.js";

// Client identity for the authorization server: dynamic client registration
// (validation + persistence), CIMD client resolution, and the canonical
// resource identity the discovery documents are built from. The well-known
// documents themselves are assembled in door.ts and covered by door.test.ts.

const RESOURCE = "https://product.example/api/vendo/mcp";
const REDIRECT = "https://client.example/callback";
const VERIFIER = "a-very-long-pkce-verifier-that-is-valid-for-the-test-suite-1234567890";

// CIMD hostnames are DNS-resolved to reject private answers; `.example` never
// resolves, so pin the resolver to a public address by default.
const dnsMock = vi.hoisted(() => ({
  addresses: [{ address: "93.184.216.34" }] as Array<{ address: string }>,
  error: undefined as Error | undefined,
}));
vi.mock("node:dns/promises", () => ({
  lookup: async () => {
    if (dnsMock.error) throw dnsMock.error;
    return dnsMock.addresses;
  },
}));

afterEach(() => {
  vi.unstubAllGlobals();
  dnsMock.addresses = [{ address: "93.184.216.34" }];
  dnsMock.error = undefined;
});

describe("dynamic client registration", () => {
  it("registers a public client, persists it, and audits the registration", async () => {
    const harness = makeServer();
    const response = await harness.server.register(registration({
      client_name: "Test client",
      redirect_uris: [REDIRECT],
      scope: "read write",
    }));
    expect(response.status).toBe(201);
    const body = await response.json() as { client_id: string } & Record<string, unknown>;
    expect(body).toEqual({
      client_id: expect.stringMatching(/^mcpc_[0-9a-f]{24}$/),
      client_name: "Test client",
      redirect_uris: [REDIRECT],
      grant_types: ["authorization_code", "refresh_token"],
      token_endpoint_auth_method: "none",
      scope: "read write",
    });

    const rows = harness.store.rows("vendo_mcp_clients");
    expect(rows).toHaveLength(1);
    expect(rows[0]?.id).toBe(body.client_id);
    expect(rows[0]?.data).toEqual({
      client_name: "Test client",
      redirect_uris: [REDIRECT],
      grant_types: ["authorization_code", "refresh_token"],
      token_endpoint_auth_method: "none",
      scope: "read write",
    });
    expect(harness.audits.at(-1)).toMatchObject({
      kind: "door-auth",
      principal: { kind: "user", subject: body.client_id, ephemeral: true },
      detail: { clientId: body.client_id, event: "register" },
    });
  });

  it("defaults client_name and omits scope when not supplied", async () => {
    const harness = makeServer();
    const response = await harness.server.register(registration({ redirect_uris: [REDIRECT] }));
    expect(response.status).toBe(201);
    const body = await response.json() as Record<string, unknown>;
    expect(body.client_name).toBe("MCP client");
    expect("scope" in body).toBe(false);
  });

  it("rejects a registration request that is not application/json", async () => {
    const harness = makeServer();
    const response = await harness.server.register(
      registration({ redirect_uris: [REDIRECT] }, "text/plain"),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_client_metadata" });
    expect(harness.store.rows("vendo_mcp_clients")).toEqual([]);
  });

  it("rejects malformed JSON and missing redirect_uris", async () => {
    const harness = makeServer();
    for (const body of ["not json at all", {}, { redirect_uris: [] }, { redirect_uris: "https://x" }]) {
      const response = await harness.server.register(registration(body));
      expect(response.status).toBe(400);
      expect(await response.json()).toMatchObject({ error: "invalid_redirect_uri" });
    }
    expect(harness.store.rows("vendo_mcp_clients")).toEqual([]);
  });

  it.each([
    [["not-a-url"]],
    [["http://example.com/callback"]], // http only for loopback
    [["https://client.example/cb#fragment"]],
    [["https://user:pass@client.example/cb"]],
    [[REDIRECT, "ftp://client.example/cb"]], // one bad URI poisons the set
  ])("rejects invalid redirect_uris %j", async (redirectUris) => {
    const harness = makeServer();
    const response = await harness.server.register(registration({ redirect_uris: redirectUris }));
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_redirect_uri" });
  });

  it("accepts loopback http redirect URIs", async () => {
    const harness = makeServer();
    const response = await harness.server.register(registration({
      redirect_uris: ["http://localhost:3000/cb", "http://127.0.0.1/cb"],
    }));
    expect(response.status).toBe(201);
  });
});

describe("client id metadata document (CIMD) resolution", () => {
  const CIMD_ID = "https://client.example/oauth/client.json";

  it("authorizes a client resolved from a valid metadata document", async () => {
    const harness = makeServer();
    const fetchSpy = vi.fn(async () => Response.json({
      client_id: CIMD_ID,
      client_name: "CIMD client",
      redirect_uris: [REDIRECT],
    }));
    vi.stubGlobal("fetch", fetchSpy);

    const response = await harness.server.authorize(await authorizeRequest(CIMD_ID), RESOURCE);
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!);
    expect(location.origin + location.pathname).toBe(REDIRECT);
    expect(location.searchParams.get("code")).toMatch(/^vmcd_/);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it("rejects a document whose client_id does not match the fetched URL", async () => {
    const harness = makeServer();
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({
      client_id: "https://client.example/oauth/other.json",
      redirect_uris: [REDIRECT],
    })));
    const response = await harness.server.authorize(await authorizeRequest(CIMD_ID), RESOURCE);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_client" });
  });

  it("rejects a non-JSON document", async () => {
    const harness = makeServer();
    vi.stubGlobal("fetch", vi.fn(async () =>
      new Response("<html></html>", { headers: { "content-type": "text/html" } })));
    const response = await harness.server.authorize(await authorizeRequest(CIMD_ID), RESOURCE);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_client" });
  });

  it("rejects a document larger than 64 KB", async () => {
    const harness = makeServer();
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({
      client_id: CIMD_ID,
      redirect_uris: [REDIRECT],
      pad: "x".repeat(70_000),
    })));
    const response = await harness.server.authorize(await authorizeRequest(CIMD_ID), RESOURCE);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_client" });
  });

  it.each([
    "https://127.0.0.1/client.json",
    "https://[::1]/client.json",
    "https://localhost/client.json",
    "https://intranet/client.json",
    "https://admin.internal/client.json",
    "https://client.example/client.json#fragment",
    "https://user:pass@client.example/client.json",
    "http://client.example/client.json", // non-https falls through to (unknown) stored clients
  ])("refuses %s without fetching it", async (clientId) => {
    const harness = makeServer();
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const response = await harness.server.authorize(await authorizeRequest(clientId), RESOURCE);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_client" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("refuses a public hostname that resolves to a private address (DNS rebind)", async () => {
    const harness = makeServer();
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    dnsMock.addresses = [{ address: "169.254.169.254" }];
    const response = await harness.server.authorize(
      await authorizeRequest("https://169-254-169-254.sslip.io/client.json"),
      RESOURCE,
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_client" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("refuses a hostname that does not resolve", async () => {
    const harness = makeServer();
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    dnsMock.error = new Error("ENOTFOUND");
    const response = await harness.server.authorize(await authorizeRequest(CIMD_ID), RESOURCE);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_client" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("canonical resource identity", () => {
  it.each([
    ["https://Product.Example:443/api/vendo/mcp", "https://product.example/api/vendo/mcp"],
    ["https://product.example/", "https://product.example"],
    ["https://product.example/api/vendo/mcp/", "https://product.example/api/vendo/mcp"],
    ["http://product.example:80/mcp", "http://product.example/mcp"],
  ])("treats %s and %s as the same resource", (left, right) => {
    expect(canonicalUri(left)).toBe(canonicalUri(right));
    expect(sameCanonicalUri(left, right)).toBe(true);
  });

  it.each([
    ["https://product.example:8443/mcp", "https://product.example/mcp"],
    ["https://product.example/mcp?a=1", "https://product.example/mcp"],
    ["https://product.example/mcp", "https://product.example/other"],
  ])("keeps %s distinct from %s", (left, right) => {
    expect(sameCanonicalUri(left, right)).toBe(false);
  });

  it("refuses credentials and malformed URIs", () => {
    expect(() => canonicalUri("https://user:pass@product.example/mcp")).toThrow(TypeError);
    expect(sameCanonicalUri("not-a-uri", RESOURCE)).toBe(false);
  });
});

function makeServer(oauth?: HostOAuthAdapter) {
  const store = new MemoryStore();
  const audits: AuditEvent[] = [];
  const guard: Guard = {
    async check() { return { action: "run", decidedBy: "default" }; },
    async report(event) { audits.push(event); },
    async directions() { return []; },
    onApprovalDecision() { return () => undefined; },
  };
  const server = new OAuthServer({
    oauth: oauth ?? {
      async authorize() { return { subject: "user_1" }; },
      async principal(subject): Promise<Principal | null> { return { kind: "user", subject }; },
    },
    store,
    guard,
  });
  return { server, store, audits };
}

function registration(body: unknown, contentTypeHeader = "application/json"): Request {
  return new Request(`${RESOURCE}/register`, {
    method: "POST",
    headers: { "content-type": contentTypeHeader },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

async function authorizeRequest(clientId: string, overrides: Record<string, string> = {}): Promise<Request> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(VERIFIER)));
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: Buffer.from(digest).toString("base64url"),
    code_challenge_method: "S256",
    scope: "read write",
    resource: RESOURCE,
    ...overrides,
  });
  return new Request(`${RESOURCE}/authorize?${params}`);
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
