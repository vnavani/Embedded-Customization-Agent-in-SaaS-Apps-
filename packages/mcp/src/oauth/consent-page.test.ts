import type { VendoTheme } from "@vendoai/core";
import { describe, expect, it } from "vitest";
import { consentPage } from "./consent-page.js";

const FLOW = { action: "/api/vendo/mcp/consent", transaction: "txn_1", csrfToken: "csrf_1" };

const THEME: VendoTheme = {
  colors: {
    background: "#101820",
    surface: "#18242f",
    text: "#f4f7fa",
    muted: "#aebbc7",
    accent: "#ffb81c",
    accentText: "#101820",
    danger: "#f35b66",
    border: "#405261",
  },
  typography: { fontFamily: "Inter, sans-serif", headingFamily: "Newsreader, serif", baseSize: "16px" },
  radius: { small: "4px", medium: "8px", large: "14px" },
  density: "compact",
  motion: "reduced",
};

describe("consentPage", () => {
  it("renders the client, scopes, and door-owned form with hardened response headers", async () => {
    const response = consentPage("Cadence Agent", ["read", "write"], FLOW);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-security-policy")).toBe(
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    );
    expect(response.headers.get("referrer-policy")).toBe("no-referrer");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");

    const html = await response.text();
    expect(html).toContain("Allow Cadence Agent to access this product?");
    expect(html).toContain("read · write");
    expect(html).toContain('<form method="post" action="/api/vendo/mcp/consent">');
    expect(html).toContain('<input type="hidden" name="transaction" value="txn_1">');
    expect(html).toContain('<input type="hidden" name="csrf_token" value="csrf_1">');
    expect(html).toContain('name="decision" value="deny"');
    expect(html).toContain('name="decision" value="approve"');
  });

  it("escapes an attacker-supplied client name (registration is unauthenticated)", async () => {
    const html = await consentPage('<img src=x onerror=alert(1)> "Nice" <b>App</b>', [], FLOW).text();
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<b>");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt; &quot;Nice&quot; &lt;b&gt;App&lt;/b&gt;");
  });

  it("escapes scope values and omits the scope block entirely when no scopes were requested", async () => {
    const attacked = await consentPage("Agent", ["read", "</strong><script>alert(1)</script>"], FLOW).text();
    expect(attacked).not.toContain("<script");
    expect(attacked).toContain("read · &lt;/strong&gt;&lt;script&gt;alert(1)&lt;/script&gt;");

    const empty = await consentPage("Agent", [], FLOW).text();
    expect(empty).not.toContain('class="scope"');
    expect(empty).not.toContain("Requested access");
  });

  it("escapes flow fields so an attribute breakout cannot inject markup", async () => {
    const html = await consentPage("Agent", ["read"], {
      action: '/consent"><script>alert(1)</script>',
      transaction: 'txn"><input name="x',
      csrfToken: "csrf'><script>alert(2)</script>",
    }).text();
    expect(html).not.toContain("<script");
    expect(html).toContain('action="/consent&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"');
    expect(html).toContain('value="txn&quot;&gt;&lt;input name=&quot;x"');
    expect(html).toContain('value="csrf&#39;&gt;&lt;script&gt;alert(2)&lt;/script&gt;"');
  });

  it("maps a theme to kebab-cased CSS variables on the html element", async () => {
    const html = await consentPage("Agent", [], FLOW, THEME).text();
    expect(html).toContain('<html lang="en" style="');
    expect(html).toContain("--vendo-color-accent-text:#101820");
    expect(html).toContain("--vendo-color-background:#101820");
    expect(html).toContain("--vendo-font-family:Inter, sans-serif");
    expect(html).toContain("--vendo-heading-family:Newsreader, serif");
    expect(html).toContain("--vendo-font-size:16px");
    expect(html).toContain("--vendo-radius-medium:8px");
    expect(html).toContain("--vendo-density:compact");
    expect(html).toContain("--vendo-motion:reduced");
  });

  it("omits the style attribute without a theme and the heading variable without a heading family", async () => {
    const untheme = await consentPage("Agent", [], FLOW).text();
    expect(untheme).toContain('<html lang="en">');
    expect(untheme).not.toContain("style=");

    // The static stylesheet references var(--vendo-heading-family, …), so
    // check the declaration is absent from the style attribute specifically.
    const { headingFamily: _omitted, ...typography } = THEME.typography;
    const html = await consentPage("Agent", [], FLOW, { ...THEME, typography }).text();
    const style = html.match(/<html lang="en" style="([^"]*)"/)?.[1] ?? "";
    expect(style).not.toBe("");
    expect(style).not.toContain("--vendo-heading-family");
    expect(style).toContain("--vendo-font-family:Inter, sans-serif");
  });

  it("escapes theme values so host-configured strings cannot break out of the style attribute", async () => {
    const html = await consentPage("Agent", [], FLOW, {
      ...THEME,
      typography: { ...THEME.typography, fontFamily: 'Evil" onmouseover="alert(1)' },
    }).text();
    expect(html).not.toContain('" onmouseover="alert(1)');
    expect(html).toContain("--vendo-font-family:Evil&quot; onmouseover=&quot;alert(1)");
  });
});
