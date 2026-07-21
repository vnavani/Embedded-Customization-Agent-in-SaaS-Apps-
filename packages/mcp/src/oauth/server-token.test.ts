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

// The token endpoint and revocation: code exchange with PKCE and binding
// checks, single-use codes, refresh rotation with reuse revocation, bearer
// authentication, and RFC 7009 revocation semantics.

const RESOURCE = "https://product.example/api/vendo/mcp";
const REDIRECT = "https://client.example/callback";
const VERIFIER = "a-very-long-pkce-verifier-that-is-valid-for-the-test-suite-1234567890";

interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
}

describe("token endpoint request validation", () => {
  it("rejects a request that is not form-encoded", async () => {
    const harness = makeServer();
    const response = await harness.server.token(new Request(`${RESOURCE}/token`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ grant_type: "authorization_code" }),
    }));
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_request" });
  });

  it("rejects unsupported grant types and missing grant parameters", async () => {
    const harness = makeServer();
    expect(await (await harness.server.token(form({ grant_type: "client_credentials" }))).json())
      .toMatchObject({ error: "unsupported_grant_type" });
    expect(await (await harness.server.token(form({ grant_type: "authorization_code" }))).json())
      .toMatchObject({ error: "invalid_request" });
    expect(await (await harness.server.token(form({ grant_type: "refresh_token" }))).json())
      .toMatchObject({ error: "invalid_request" });
  });

  it("requires client_id, redirect_uri, and code_verifier on code exchange", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const code = await mintCode(harness.server, clientId);
    const response = await harness.server.token(form({
      grant_type: "authorization_code",
      code,
      client_id: clientId,
      redirect_uri: REDIRECT,
      // code_verifier missing
    }));
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_request" });
  });
});

describe("authorization_code exchange", () => {
  it("exchanges a valid code for tokens that authenticate", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const code = await mintCode(harness.server, clientId);

    const response = await exchange(harness.server, { code, client_id: clientId, code_verifier: VERIFIER });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("pragma")).toBe("no-cache");
    const body = await response.json() as TokenResponse;
    expect(body.access_token).toMatch(/^vmat_[A-Za-z0-9_-]{43}$/);
    expect(body.refresh_token).toMatch(/^vmrt_[A-Za-z0-9_-]{43}$/);
    expect(body).toMatchObject({ token_type: "Bearer", expires_in: 3600, scope: "read write" });
    // Internal bookkeeping (refreshGrantId) never leaks into the response.
    expect(Object.keys(body).sort()).toEqual([
      "access_token", "expires_in", "refresh_token", "scope", "token_type",
    ]);
    expect(harness.audits.at(-1)?.detail).toEqual({ clientId, event: "issue" });

    const authenticated = await harness.server.authenticate(bearer(body.access_token));
    expect(authenticated).toMatchObject({
      tokenWasPresented: true,
      grant: { kind: "access", subject: "user_1", clientId, resource: RESOURCE, scopes: ["read", "write"] },
    });
    // Tokens are stored hashed, never in the clear.
    const rows = JSON.stringify(harness.store.rows("vendo_mcp_grants"));
    expect(rows).not.toContain(body.access_token);
    expect(rows).not.toContain(body.refresh_token);
  });

  it("rejects a malformed PKCE verifier before consuming the code", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const code = await mintCode(harness.server, clientId);

    const malformed = await exchange(harness.server, { code, client_id: clientId, code_verifier: "too-short" });
    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toMatchObject({ error: "invalid_grant" });

    // The syntax check runs before lookup, so the code is still redeemable.
    const retry = await exchange(harness.server, { code, client_id: clientId, code_verifier: VERIFIER });
    expect(retry.status).toBe(200);
  });

  it("rejects a wrong PKCE verifier and burns the presented code", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const code = await mintCode(harness.server, clientId);

    const wrong = await exchange(harness.server, {
      code,
      client_id: clientId,
      code_verifier: `${VERIFIER.slice(0, -1)}X`,
    });
    expect(wrong.status).toBe(400);
    expect(await wrong.json()).toMatchObject({ error: "invalid_grant" });

    // Single-use on presentation: the correct verifier no longer redeems it.
    const retry = await exchange(harness.server, { code, client_id: clientId, code_verifier: VERIFIER });
    expect(retry.status).toBe(400);
    expect(await retry.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("rejects a reused code after a successful exchange", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const code = await mintCode(harness.server, clientId);
    expect((await exchange(harness.server, { code, client_id: clientId, code_verifier: VERIFIER })).status).toBe(200);
    const reuse = await exchange(harness.server, { code, client_id: clientId, code_verifier: VERIFIER });
    expect(reuse.status).toBe(400);
    expect(await reuse.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("rejects unknown and expired codes", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);

    const unknown = await exchange(harness.server, {
      code: "vmcd_unknown",
      client_id: clientId,
      code_verifier: VERIFIER,
    });
    expect(await unknown.json()).toMatchObject({ error: "invalid_grant" });

    const code = await mintCode(harness.server, clientId);
    await expireGrants(harness.store, "code");
    const expired = await exchange(harness.server, { code, client_id: clientId, code_verifier: VERIFIER });
    expect(expired.status).toBe(400);
    expect(await expired.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("rejects a code presented by a different client or redirect_uri", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const otherClient = await registerClient(harness.server);

    const stolen = await exchange(harness.server, {
      code: await mintCode(harness.server, clientId),
      client_id: otherClient,
      code_verifier: VERIFIER,
    });
    expect(stolen.status).toBe(400);
    expect(await stolen.json()).toMatchObject({ error: "invalid_grant" });

    const rebound = await exchange(harness.server, {
      code: await mintCode(harness.server, clientId),
      client_id: clientId,
      code_verifier: VERIFIER,
      redirect_uri: "https://client.example/other",
    });
    expect(rebound.status).toBe(400);
    expect(await rebound.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("binds the code to its resource canonically", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);

    const mismatch = await exchange(harness.server, {
      code: await mintCode(harness.server, clientId),
      client_id: clientId,
      code_verifier: VERIFIER,
      resource: "https://other.example/mcp",
    });
    expect(mismatch.status).toBe(400);
    expect(await mismatch.json()).toMatchObject({ error: "invalid_target" });

    // A trailing slash is the same canonical resource.
    const canonical = await exchange(harness.server, {
      code: await mintCode(harness.server, clientId),
      client_id: clientId,
      code_verifier: VERIFIER,
      resource: `${RESOURCE}/`,
    });
    expect(canonical.status).toBe(200);
  });

  it("refuses to exchange when the store cannot claim atomically", async () => {
    const harness = makeServer({ store: new NoClaimStore() });
    const clientId = await registerClient(harness.server);
    const code = await mintCode(harness.server, clientId);
    const response = await exchange(harness.server, { code, client_id: clientId, code_verifier: VERIFIER });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "server_error" });
  });
});

describe("refresh_token rotation", () => {
  it("rotates the refresh token without disturbing outstanding access tokens", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const first = await issueTokens(harness.server, clientId);

    const response = await refresh(harness.server, first.refresh_token, clientId);
    expect(response.status).toBe(200);
    const rotated = await response.json() as TokenResponse;
    expect(rotated.refresh_token).not.toBe(first.refresh_token);
    expect(rotated.access_token).not.toBe(first.access_token);
    expect(harness.audits.at(-1)?.detail).toEqual({ clientId, event: "refresh" });

    // Rotation is not revocation: the earlier access token lives to its expiry.
    expect(await harness.server.authenticate(bearer(first.access_token))).not.toBeNull();
    expect(await harness.server.authenticate(bearer(rotated.access_token))).not.toBeNull();
  });

  it("detects reuse of a rotated refresh token and revokes the whole family", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const first = await issueTokens(harness.server, clientId);
    const rotated = await (await refresh(harness.server, first.refresh_token, clientId)).json() as TokenResponse;

    const reuse = await refresh(harness.server, first.refresh_token, clientId);
    expect(reuse.status).toBe(400);
    expect(await reuse.json()).toMatchObject({ error: "invalid_grant" });
    expect(harness.audits.at(-1)?.detail).toEqual({ clientId, event: "revoke" });

    // The successor tokens die with the family.
    expect(await harness.server.authenticate(bearer(rotated.access_token))).toBeNull();
    expect((await refresh(harness.server, rotated.refresh_token, clientId)).status).toBe(400);
  });

  it("rejects a refresh presented by a different client without consuming it", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const otherClient = await registerClient(harness.server);
    const tokens = await issueTokens(harness.server, clientId);

    const stolen = await refresh(harness.server, tokens.refresh_token, otherClient);
    expect(stolen.status).toBe(400);
    expect(await stolen.json()).toMatchObject({ error: "invalid_grant" });

    expect((await refresh(harness.server, tokens.refresh_token, clientId)).status).toBe(200);
  });

  it("rejects an expired refresh token", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const tokens = await issueTokens(harness.server, clientId);
    await expireGrants(harness.store, "refresh");
    const response = await refresh(harness.server, tokens.refresh_token, clientId);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_grant" });
  });

  it("kills the grant when the host no longer resolves the subject (principal kill switch)", async () => {
    let alive = true;
    const harness = makeServer({
      principal: async (subject) => (alive ? { kind: "user", subject } : null),
    });
    const clientId = await registerClient(harness.server);
    const tokens = await issueTokens(harness.server, clientId);

    alive = false;
    const response = await refresh(harness.server, tokens.refresh_token, clientId);
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({
      error: "invalid_grant",
      error_description: expect.stringContaining("no longer authorized"),
    });
    expect(await harness.server.authenticate(bearer(tokens.access_token))).toBeNull();
  });

  it("binds the refresh token to its resource", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const tokens = await issueTokens(harness.server, clientId);
    const response = await refresh(harness.server, tokens.refresh_token, clientId, {
      resource: "https://other.example/mcp",
    });
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ error: "invalid_target" });
  });
});

describe("bearer authentication", () => {
  it("returns null for missing, non-bearer, and unknown credentials", async () => {
    const harness = makeServer();
    expect(await harness.server.authenticate(new Request(RESOURCE))).toBeNull();
    expect(await harness.server.authenticate(new Request(RESOURCE, {
      headers: { authorization: "Basic dXNlcjpwdw==" },
    }))).toBeNull();
    expect(await harness.server.authenticate(bearer("vmat_unknown"))).toBeNull();
  });

  it("returns null for an expired access token", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const tokens = await issueTokens(harness.server, clientId);
    expect(await harness.server.authenticate(bearer(tokens.access_token))).not.toBeNull();
    await expireGrants(harness.store, "access");
    expect(await harness.server.authenticate(bearer(tokens.access_token))).toBeNull();
  });
});

describe("revocation", () => {
  it("validates the revocation request and the client", async () => {
    const harness = makeServer();
    const wrongType = await harness.server.revoke(new Request(`${RESOURCE}/revoke`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    }));
    expect(wrongType.response.status).toBe(400);
    expect(await wrongType.response.json()).toMatchObject({ error: "invalid_request" });

    const missing = await harness.server.revoke(form({ token: "vmat_x" }, "revoke"));
    expect(await missing.response.json()).toMatchObject({ error: "invalid_request" });

    const unknownClient = await harness.server.revoke(form({ token: "vmat_x", client_id: "mcpc_ghost" }, "revoke"));
    expect(unknownClient.response.status).toBe(400);
    expect(await unknownClient.response.json()).toMatchObject({ error: "invalid_client" });
  });

  it("returns an empty 200 for an unknown token (RFC 7009)", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const result = await harness.server.revoke(form({ token: "vmrt_unknown", client_id: clientId }, "revoke"));
    expect(result.response.status).toBe(200);
    expect(await result.response.text()).toBe("");
    expect(result.grant).toBeUndefined();
    expect(harness.audits.filter((event) => (event.detail as { event?: string })?.event === "revoke")).toEqual([]);
  });

  it("revokes an access token without killing its refresh grant", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const tokens = await issueTokens(harness.server, clientId);

    const result = await harness.server.revoke(form({ token: tokens.access_token, client_id: clientId }, "revoke"));
    expect(result.response.status).toBe(200);
    expect(result.grant).toMatchObject({ subject: "user_1", clientId, tokenType: "access_token" });

    expect(await harness.server.authenticate(bearer(tokens.access_token))).toBeNull();
    expect((await refresh(harness.server, tokens.refresh_token, clientId)).status).toBe(200);
    expect(harness.audits.map((event) => event.detail)).toContainEqual({ clientId, event: "revoke" });
  });

  it("revoking a refresh token kills its whole family but not another family", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const doomed = await issueTokens(harness.server, clientId);
    const independent = await issueTokens(harness.server, clientId);

    const result = await harness.server.revoke(form({
      token: doomed.refresh_token,
      client_id: clientId,
      token_type_hint: "refresh_token",
    }, "revoke"));
    expect(result.response.status).toBe(200);
    expect(result.grant).toMatchObject({ subject: "user_1", clientId, tokenType: "refresh_token" });

    expect(await harness.server.authenticate(bearer(doomed.access_token))).toBeNull();
    expect((await refresh(harness.server, doomed.refresh_token, clientId)).status).toBe(400);
    expect(await harness.server.authenticate(bearer(independent.access_token))).not.toBeNull();
    expect((await refresh(harness.server, independent.refresh_token, clientId)).status).toBe(200);
  });

  it("refuses a valid client revoking another client's token", async () => {
    const harness = makeServer();
    const owner = await registerClient(harness.server);
    const other = await registerClient(harness.server);
    const tokens = await issueTokens(harness.server, owner);

    const result = await harness.server.revoke(form({
      token: tokens.refresh_token,
      client_id: other,
      token_type_hint: "refresh_token",
    }, "revoke"));
    expect(result.response.status).toBe(400);
    expect(await result.response.json()).toMatchObject({ error: "invalid_client" });
    expect(result.grant).toBeUndefined();
    expect(await harness.server.authenticate(bearer(tokens.access_token))).not.toBeNull();
  });

  it("revokeClient kills every grant for one subject/client pair", async () => {
    const harness = makeServer();
    const clientId = await registerClient(harness.server);
    const tokens = await issueTokens(harness.server, clientId);

    expect(await harness.server.revokeClient("user_1", clientId)).toBe(true);
    expect(await harness.server.authenticate(bearer(tokens.access_token))).toBeNull();
    expect((await refresh(harness.server, tokens.refresh_token, clientId)).status).toBe(400);
    // Everything is already revoked, so a second sweep changes nothing.
    expect(await harness.server.revokeClient("user_1", clientId)).toBe(false);
  });
});

interface ServerOptions {
  store?: MemoryStore;
  principal?: (subject: string) => Promise<Principal | null>;
}

function makeServer(options: ServerOptions = {}) {
  const store = options.store ?? new MemoryStore();
  const audits: AuditEvent[] = [];
  const guard: Guard = {
    async check() { return { action: "run", decidedBy: "default" }; },
    async report(event) { audits.push(event); },
    async directions() { return []; },
    onApprovalDecision() { return () => undefined; },
  };
  const oauth: HostOAuthAdapter = {
    async authorize() { return { subject: "user_1" }; },
    principal: options.principal ?? (async (subject) => ({ kind: "user", subject })),
  };
  const server = new OAuthServer({ oauth, store, guard });
  return { server, store, audits };
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

async function mintCode(server: OAuthServer, clientId: string): Promise<string> {
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
  const response = await server.authorize(new Request(`${RESOURCE}/authorize?${params}`), RESOURCE);
  expect(response.status).toBe(302);
  return new URL(response.headers.get("location")!).searchParams.get("code")!;
}

function form(values: Record<string, string>, path = "token"): Request {
  return new Request(`${RESOURCE}/${path}`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(values),
  });
}

async function exchange(server: OAuthServer, values: Record<string, string>): Promise<Response> {
  return server.token(form({ grant_type: "authorization_code", redirect_uri: REDIRECT, ...values }));
}

async function issueTokens(server: OAuthServer, clientId: string): Promise<TokenResponse> {
  const code = await mintCode(server, clientId);
  const response = await exchange(server, { code, client_id: clientId, code_verifier: VERIFIER });
  expect(response.status).toBe(200);
  return await response.json() as TokenResponse;
}

async function refresh(
  server: OAuthServer,
  refreshToken: string,
  clientId: string,
  extra: Record<string, string> = {},
): Promise<Response> {
  return server.token(form({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: clientId,
    ...extra,
  }));
}

function bearer(token: string): Request {
  return new Request(RESOURCE, { headers: { authorization: `Bearer ${token}` } });
}

/** Backdate every stored grant of one kind past its expiry. */
async function expireGrants(store: MemoryStore, kind: string): Promise<void> {
  for (const record of store.rows("vendo_mcp_grants")) {
    const data = record.data as { kind?: string };
    if (data.kind !== kind) continue;
    await store.records("vendo_mcp_grants").put({
      id: record.id,
      data: { ...data, expiresAt: new Date(Date.now() - 1_000).toISOString() },
      ...(record.refs === undefined ? {} : { refs: record.refs }),
    });
  }
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

/** A store whose record collections cannot claim atomically. */
class NoClaimStore extends MemoryStore {
  override records(collection: string): RecordStore {
    const { claim: _claim, ...rest } = super.records(collection);
    return rest;
  }
}
