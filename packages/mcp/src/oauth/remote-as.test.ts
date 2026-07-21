import { exportJWK, generateKeyPair, SignJWT, type JWK, type JWTPayload, type KeyLike } from "jose";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { RemoteAsVerifier, type RemoteAsConfig } from "./remote-as.js";

const ISSUER = "https://as.example";
const AUDIENCE = "https://product.example/api/vendo/mcp";
const JWKS_URI = "https://as.example/jwks.json";
const METADATA_URI = "https://as.example/.well-known/oauth-authorization-server";

interface TestKey {
  privateKey: KeyLike;
  jwk: JWK;
}

let es1: TestKey;
let es2: TestKey;
let rsa: TestKey;

beforeAll(async () => {
  [es1, es2, rsa] = await Promise.all([
    makeKey("ES256", "key-1"),
    makeKey("ES256", "key-2"),
    makeKey("RS256", "rsa-1"),
  ]);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function makeKey(alg: string, kid: string): Promise<TestKey> {
  const { privateKey, publicKey } = await generateKeyPair(alg);
  const jwk = await exportJWK(publicKey);
  jwk.kid = kid;
  jwk.alg = alg;
  jwk.use = "sig";
  return { privateKey: privateKey as KeyLike, jwk };
}

async function signToken(
  claims: Record<string, unknown> = {},
  options: { key?: TestKey; alg?: string; kid?: string } = {},
): Promise<string> {
  const key = options.key ?? es1;
  const now = Math.floor(Date.now() / 1_000);
  const payload: Record<string, unknown> = {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: "user-1",
    iat: now - 30,
    exp: now + 300,
    ...claims,
  };
  return new SignJWT(payload as JWTPayload)
    .setProtectedHeader({ alg: options.alg ?? "ES256", kid: options.kid ?? key.jwk.kid })
    .sign(key.privateKey);
}

function bearer(token: string): Request {
  return new Request(AUDIENCE, { headers: { authorization: `Bearer ${token}` } });
}

function makeVerifier(config: Partial<RemoteAsConfig> = {}): RemoteAsVerifier {
  return new RemoteAsVerifier({ issuer: ISSUER, jwksUri: JWKS_URI, audience: AUDIENCE, ...config });
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** Serve JWKS/metadata from a handler; returns the fetched URLs. */
function stubFetch(handler: (url: string) => Response): string[] {
  const calls: string[] = [];
  vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
    const url = input instanceof Request ? input.url : String(input);
    calls.push(url);
    return handler(url);
  });
  return calls;
}

function serveJwks(keys: JWK[]): string[] {
  return stubFetch((url) => (url === JWKS_URI ? jsonResponse({ keys }) : jsonResponse({}, 404)));
}

describe("RemoteAsVerifier", () => {
  it("returns null for missing or malformed authorization headers without touching the network", async () => {
    const calls = serveJwks([es1.jwk]);
    const verifier = makeVerifier();
    expect(await verifier.authenticate(new Request(AUDIENCE))).toBeNull();
    for (const authorization of ["Basic dXNlcjpwdw==", "Bearer", "Bearer  ", "Bearer a b", "bearer-ish token"]) {
      expect(await verifier.authenticate(new Request(AUDIENCE, { headers: { authorization } }))).toBeNull();
    }
    expect(calls).toEqual([]);
  });

  it("accepts a valid token and maps it to an access grant", async () => {
    serveJwks([es1.jwk]);
    const now = Math.floor(Date.now() / 1_000);
    const token = await signToken({ exp: now + 300, scope: "read write read", client_id: "client-1" });
    const result = await makeVerifier().authenticate(bearer(token));
    expect(result).toEqual({
      grant: {
        kind: "access",
        subject: "user-1",
        clientId: "client-1",
        resource: AUDIENCE,
        scopes: ["read", "write"],
        expiresAt: new Date((now + 300) * 1_000).toISOString(),
      },
      tokenWasPresented: true,
    });
  });

  it("rejects a token from a different issuer", async () => {
    serveJwks([es1.jwk]);
    const token = await signToken({ iss: "https://other-as.example" });
    expect(await makeVerifier().authenticate(bearer(token))).toBeNull();
  });

  it("rejects a token minted for a different resource audience", async () => {
    serveJwks([es1.jwk]);
    const token = await signToken({ aud: "https://other-product.example/mcp" });
    expect(await makeVerifier().authenticate(bearer(token))).toBeNull();
  });

  it("rejects a token signed by a key outside the JWKS", async () => {
    serveJwks([es1.jwk]);
    // Attacker signs with their own key but claims the trusted kid.
    const token = await signToken({}, { key: es2, kid: "key-1" });
    expect(await makeVerifier().authenticate(bearer(token))).toBeNull();
  });

  it("rejects a correctly-signed token using a disallowed algorithm", async () => {
    serveJwks([es1.jwk, rsa.jwk]);
    const token = await signToken({}, { key: rsa, alg: "RS256" });
    expect(await makeVerifier().authenticate(bearer(token))).toBeNull();
  });

  it("rejects expired tokens and tokens issued in the future", async () => {
    serveJwks([es1.jwk]);
    const now = Math.floor(Date.now() / 1_000);
    const verifier = makeVerifier();
    expect(await verifier.authenticate(bearer(await signToken({ exp: now - 30 })))).toBeNull();
    expect(await verifier.authenticate(bearer(await signToken({ iat: now + 120 })))).toBeNull();
    expect(await verifier.authenticate(bearer(await signToken({ iat: "yesterday", exp: now + 300 })))).toBeNull();
  });

  it("rejects an empty or non-string subject", async () => {
    serveJwks([es1.jwk]);
    const verifier = makeVerifier();
    expect(await verifier.authenticate(bearer(await signToken({ sub: "" })))).toBeNull();
    expect(await verifier.authenticate(bearer(await signToken({ sub: 42 })))).toBeNull();
  });

  it("falls back from client_id to azp to the issuer for the grant clientId", async () => {
    serveJwks([es1.jwk]);
    const verifier = makeVerifier();
    const viaAzp = await verifier.authenticate(bearer(await signToken({ azp: "azp-client" })));
    expect(viaAzp?.grant.clientId).toBe("azp-client");
    const viaIssuer = await verifier.authenticate(bearer(await signToken({ client_id: "", azp: "" })));
    expect(viaIssuer?.grant.clientId).toBe(ISSUER);
  });

  it("normalizes scope string, scope array, and scp array shapes", async () => {
    serveJwks([es1.jwk]);
    const verifier = makeVerifier();
    const fromArray = await verifier.authenticate(bearer(await signToken({ scope: ["read", 5, "", "read"] })));
    expect(fromArray?.grant.scopes).toEqual(["read"]);
    const fromScp = await verifier.authenticate(bearer(await signToken({ scp: ["write", "read"] })));
    expect(fromScp?.grant.scopes).toEqual(["write", "read"]);
    const preferScope = await verifier.authenticate(bearer(await signToken({ scope: "read", scp: ["write"] })));
    expect(preferScope?.grant.scopes).toEqual(["read"]);
    const missing = await verifier.authenticate(bearer(await signToken()));
    expect(missing?.grant.scopes).toEqual([]);
  });

  it("picks up a rotated key by refetching the JWKS on an unfamiliar kid", async () => {
    let served = [es1.jwk];
    const calls = stubFetch((url) => (url === JWKS_URI ? jsonResponse({ keys: served }) : jsonResponse({}, 404)));
    const verifier = makeVerifier();
    expect(await verifier.authenticate(bearer(await signToken()))).not.toBeNull();

    served = [es2.jwk];
    expect(await verifier.authenticate(bearer(await signToken({}, { key: es2 })))).not.toBeNull();
    expect(calls.filter((url) => url === JWKS_URI).length).toBe(2);
  });

  it("discovers the JWKS from authorization-server metadata when jwksUri is unset", async () => {
    const calls = stubFetch((url) => {
      if (url === METADATA_URI) return jsonResponse({ issuer: ISSUER, jwks_uri: JWKS_URI });
      if (url === JWKS_URI) return jsonResponse({ keys: [es1.jwk] });
      return jsonResponse({}, 404);
    });
    const verifier = makeVerifier({ jwksUri: undefined });
    const result = await verifier.authenticate(bearer(await signToken()));
    expect(result?.grant.subject).toBe("user-1");
    expect(calls[0]).toBe(METADATA_URI);

    // Discovery is cached; a second token does not re-fetch the metadata.
    expect(await verifier.authenticate(bearer(await signToken()))).not.toBeNull();
    expect(calls.filter((url) => url === METADATA_URI).length).toBe(1);
  });

  it("strips trailing slashes for the metadata URL but demands an exact issuer echo", async () => {
    stubFetch((url) => {
      if (url === METADATA_URI) return jsonResponse({ issuer: `${ISSUER}/`, jwks_uri: JWKS_URI });
      if (url === JWKS_URI) return jsonResponse({ keys: [es1.jwk] });
      return jsonResponse({}, 404);
    });
    const verifier = makeVerifier({ issuer: `${ISSUER}/`, jwksUri: undefined });
    const result = await verifier.authenticate(bearer(await signToken({ iss: `${ISSUER}/` })));
    expect(result?.grant.subject).toBe("user-1");
  });

  it("rejects metadata whose issuer does not match or whose jwks_uri is not a string", async () => {
    for (const metadata of [
      { issuer: "https://evil.example", jwks_uri: JWKS_URI },
      { issuer: ISSUER, jwks_uri: 7 },
      { issuer: ISSUER },
    ]) {
      stubFetch((url) => (url === METADATA_URI ? jsonResponse(metadata) : jsonResponse({ keys: [es1.jwk] })));
      const verifier = makeVerifier({ jwksUri: undefined });
      expect(await verifier.authenticate(bearer(await signToken()))).toBeNull();
      vi.unstubAllGlobals();
    }
  });

  it("does not cache a failed discovery: the next token retries the metadata fetch", async () => {
    let healthy = false;
    const calls = stubFetch((url) => {
      if (url === METADATA_URI) {
        return healthy ? jsonResponse({ issuer: ISSUER, jwks_uri: JWKS_URI }) : jsonResponse({}, 503);
      }
      if (url === JWKS_URI) return jsonResponse({ keys: [es1.jwk] });
      return jsonResponse({}, 404);
    });
    const verifier = makeVerifier({ jwksUri: undefined });
    expect(await verifier.authenticate(bearer(await signToken()))).toBeNull();

    healthy = true;
    expect(await verifier.authenticate(bearer(await signToken()))).not.toBeNull();
    expect(calls.filter((url) => url === METADATA_URI).length).toBe(2);
  });
});
