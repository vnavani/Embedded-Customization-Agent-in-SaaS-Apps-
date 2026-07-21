import { jwtVerify, SignJWT, type JWTPayload } from "jose";
import { describe, expect, it } from "vitest";
import type { HostOAuthAdapter } from "./adapter.js";
import { handleFederation } from "./federation.js";

const RESOURCE = "https://product.example/api/vendo/mcp";
const SECRET = "federation-shared-secret-for-tests";
const AS_ISSUER = "https://accounts.example";
const CALLBACK = "https://accounts.example/federate/callback";

function key(secret = SECRET): Uint8Array {
  return new TextEncoder().encode(secret);
}

async function federateJwt(
  overrides: Record<string, unknown> = {},
  options: { secret?: string; alg?: string } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1_000);
  const payload: Record<string, unknown> = {
    iss: AS_ISSUER,
    aud: RESOURCE,
    exp: now + 120,
    jti: "fedreq-1",
    redirect_uri: CALLBACK,
    scopes: ["read"],
    client_name: "Fed client",
    ...overrides,
  };
  return new SignJWT(payload as JWTPayload)
    .setProtectedHeader({ alg: options.alg ?? "HS256" })
    .sign(key(options.secret));
}

function federateRequest(compact?: string): Request {
  const url = new URL(`${RESOURCE}/federate`);
  if (compact !== undefined) url.searchParams.set("request", compact);
  return new Request(url.toString());
}

function subjectAdapter(subject = "user_1"): HostOAuthAdapter {
  return {
    async authorize() {
      return { subject };
    },
    async principal(resolved) {
      return { kind: "user", subject: resolved };
    },
  };
}

async function expectInvalidRequest(response: Response): Promise<void> {
  expect(response.status).toBe(400);
  expect(response.headers.get("content-type")).toBe("application/json");
  expect(await response.json()).toEqual({ error: "invalid_request" });
}

describe("handleFederation", () => {
  it("rejects when the adapter exposes neither authorize nor session", async () => {
    const adapter: HostOAuthAdapter = { async principal() { return null; } };
    await expectInvalidRequest(
      await handleFederation(federateRequest(await federateJwt()), RESOURCE, SECRET, adapter),
    );
  });

  it("rejects a missing request parameter", async () => {
    await expectInvalidRequest(
      await handleFederation(federateRequest(), RESOURCE, SECRET, subjectAdapter()),
    );
  });

  it("rejects bad signatures, disallowed algorithms, and garbage tokens", async () => {
    const adapter = subjectAdapter();
    for (const compact of [
      await federateJwt({}, { secret: "the-wrong-secret" }),
      await federateJwt({}, { alg: "HS384" }),
      "not-a-jwt",
    ]) {
      await expectInvalidRequest(await handleFederation(federateRequest(compact), RESOURCE, SECRET, adapter));
    }
  });

  it("rejects a request minted for a different resource audience", async () => {
    const compact = await federateJwt({ aud: "https://other.example/api/vendo/mcp" });
    await expectInvalidRequest(await handleFederation(federateRequest(compact), RESOURCE, SECRET, subjectAdapter()));
  });

  it("rejects missing or malformed claims", async () => {
    const adapter = subjectAdapter();
    for (const overrides of [
      { client_name: undefined },
      { client_name: "" },
      { redirect_uri: undefined },
      { redirect_uri: "not-a-url" },
      { scopes: "read" },
      { iss: "not-a-url" },
      { jti: "" },
    ]) {
      const compact = await federateJwt(overrides);
      await expectInvalidRequest(await handleFederation(federateRequest(compact), RESOURCE, SECRET, adapter));
    }
  });

  it("rejects an expiry outside the five-minute handshake window", async () => {
    const now = Math.floor(Date.now() / 1_000);
    const adapter = subjectAdapter();
    for (const exp of [now - 30, now + 600]) {
      const compact = await federateJwt({ exp });
      await expectInvalidRequest(await handleFederation(federateRequest(compact), RESOURCE, SECRET, adapter));
    }
  });

  it("rejects a redirect_uri whose origin differs from the issuer (assertion-leak defense)", async () => {
    const adapter = subjectAdapter();
    for (const redirect_uri of [
      "https://evil.example/federate/callback",
      "http://accounts.example/federate/callback",
      "https://accounts.example.evil.example/cb",
    ]) {
      const compact = await federateJwt({ redirect_uri });
      await expectInvalidRequest(await handleFederation(federateRequest(compact), RESOURCE, SECRET, adapter));
    }
  });

  it("authenticates through authorize and redirects back with a signed assertion", async () => {
    const seen: Array<{ clientName: string; scopes: string[] }> = [];
    const adapter: HostOAuthAdapter = {
      async authorize(_req, ctx) {
        seen.push({ clientName: ctx.clientName, scopes: ctx.scopes });
        return { subject: "user_1" };
      },
      async principal() {
        return null;
      },
    };
    const compact = await federateJwt({ scopes: ["read", "write"], jti: "fedreq-42" });
    const response = await handleFederation(federateRequest(compact), RESOURCE, SECRET, adapter);

    expect(seen).toEqual([{ clientName: "Fed client", scopes: ["read", "write"] }]);
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!);
    expect(`${location.origin}${location.pathname}`).toBe(CALLBACK);

    const { payload, protectedHeader } = await jwtVerify(location.searchParams.get("assertion")!, key(), {
      algorithms: ["HS256"],
      issuer: RESOURCE,
      audience: AS_ISSUER,
    });
    expect(protectedHeader.alg).toBe("HS256");
    expect(payload.sub).toBe("user_1");
    expect(payload.jti).toBe("fedreq-42");
    expect(payload.exp! - payload.iat!).toBe(60);
  });

  it("passes an authorize Response through instead of redirecting", async () => {
    const login = new Response("sign in first", { status: 401 });
    const adapter: HostOAuthAdapter = {
      async authorize() {
        return login;
      },
      async principal() {
        return null;
      },
    };
    const response = await handleFederation(federateRequest(await federateJwt()), RESOURCE, SECRET, adapter);
    expect(response).toBe(login);
  });

  it("falls back to session with the federate request itself as returnTo", async () => {
    const returnTos: string[] = [];
    const adapter: HostOAuthAdapter = {
      async session(_req, ctx) {
        returnTos.push(ctx.returnTo);
        return { subject: "user_2" };
      },
      async principal() {
        return null;
      },
    };
    const req = federateRequest(await federateJwt());
    const response = await handleFederation(req, RESOURCE, SECRET, adapter);
    expect(returnTos).toEqual([req.url]);
    expect(response.status).toBe(302);
    const { payload } = await jwtVerify(
      new URL(response.headers.get("location")!).searchParams.get("assertion")!,
      key(),
      { algorithms: ["HS256"], issuer: RESOURCE, audience: AS_ISSUER },
    );
    expect(payload.sub).toBe("user_2");
  });

  it("passes a session login Response through so the bounce can retry the handshake", async () => {
    const login = Response.redirect("https://product.example/login", 302);
    const adapter: HostOAuthAdapter = {
      async session() {
        return login;
      },
      async principal() {
        return null;
      },
    };
    const response = await handleFederation(federateRequest(await federateJwt()), RESOURCE, SECRET, adapter);
    expect(response).toBe(login);
  });

  it("prefers a full authorize adapter over the prebuilt session flow", async () => {
    let sessionCalls = 0;
    const adapter: HostOAuthAdapter = {
      async authorize() {
        return { subject: "from-authorize" };
      },
      async session() {
        sessionCalls += 1;
        return { subject: "from-session" };
      },
      async principal() {
        return null;
      },
    };
    const response = await handleFederation(federateRequest(await federateJwt()), RESOURCE, SECRET, adapter);
    expect(sessionCalls).toBe(0);
    const { payload } = await jwtVerify(
      new URL(response.headers.get("location")!).searchParams.get("assertion")!,
      key(),
      { algorithms: ["HS256"], issuer: RESOURCE, audience: AS_ISSUER },
    );
    expect(payload.sub).toBe("from-authorize");
  });
});
