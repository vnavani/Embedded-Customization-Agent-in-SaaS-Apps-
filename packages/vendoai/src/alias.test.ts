import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createVendo as canonicalCreateVendo } from "@vendoai/vendo/server";
import { VendoRoot as canonicalVendoRoot } from "@vendoai/vendo/react";
import { applyDraft as canonicalApplyDraft } from "@vendoai/vendo/extract";
import { vendoTools as canonicalVendoTools } from "@vendoai/vendo/ai-sdk";
import { vendoMastraTools as canonicalVendoMastraTools } from "@vendoai/vendo/mastra";
import { auth0 as canonicalAuth0 } from "@vendoai/vendo/auth/auth0";
import { authJs as canonicalAuthJs } from "@vendoai/vendo/auth/auth-js";
import { clerk as canonicalClerk } from "@vendoai/vendo/auth/clerk";
import { jwt as canonicalJwt } from "@vendoai/vendo/auth/jwt";
import { supabase as canonicalSupabase } from "@vendoai/vendo/auth/supabase";
import { createVendo } from "./server.js";
import { VendoRoot } from "./react.js";
import { applyDraft } from "./extract.js";
import { vendoTools } from "./ai-sdk.js";
import { vendoMastraTools } from "./mastra.js";
import { auth0 } from "./auth-presets/auth0.js";
import { authJs } from "./auth-presets/auth-js.js";
import { clerk } from "./auth-presets/clerk.js";
import { jwt } from "./auth-presets/jwt.js";
import { supabase } from "./auth-presets/supabase.js";

const readExports = (url: URL) =>
  (JSON.parse(readFileSync(fileURLToPath(url), "utf8")) as { exports: Record<string, unknown> })
    .exports;

const aliasExports = readExports(new URL("../package.json", import.meta.url));
const canonicalExports = readExports(new URL("../../vendo/package.json", import.meta.url));

describe("vendoai alias", () => {
  it("delegates server and React entry points to @vendoai/vendo", () => {
    expect(createVendo).toBe(canonicalCreateVendo);
    expect(VendoRoot).toBe(canonicalVendoRoot);
  });

  it("delegates the extract, ai-sdk, and mastra subpaths to @vendoai/vendo", () => {
    expect(applyDraft).toBe(canonicalApplyDraft);
    expect(vendoTools).toBe(canonicalVendoTools);
    expect(vendoMastraTools).toBe(canonicalVendoMastraTools);
  });

  it("delegates every auth preset to @vendoai/vendo/auth/*", () => {
    expect(auth0).toBe(canonicalAuth0);
    expect(authJs).toBe(canonicalAuthJs);
    expect(clerk).toBe(canonicalClerk);
    expect(jwt).toBe(canonicalJwt);
    expect(supabase).toBe(canonicalSupabase);
  });

  // The alias promises "the same" surface as @vendoai/vendo: a subpath added
  // there without a mirror here must fail this test, not drift silently.
  it("mirrors the full @vendoai/vendo exports map", () => {
    expect(Object.keys(aliasExports).sort()).toEqual(Object.keys(canonicalExports).sort());
  });
});
