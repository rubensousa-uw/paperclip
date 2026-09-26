import { describe, expect, it } from "vitest";
import type { SsoProviderConfig } from "@paperclipai/shared";
import { DEFAULT_OIDC_SCOPES, mapSsoProviderToOAuthConfig } from "../auth/better-auth.js";

const GENERIC_OIDC: SsoProviderConfig = {
  providerId: "google",
  type: "oidc",
  clientId: "client",
  clientSecret: "secret",
  discoveryUrl: "https://idp.example.com/.well-known/openid-configuration",
};

describe("mapSsoProviderToOAuthConfig: generic oidc scopes", () => {
  it("defaults to openid/email/profile when the provider declares no scopes", () => {
    const config = mapSsoProviderToOAuthConfig(GENERIC_OIDC);
    expect(config.scopes).toEqual([...DEFAULT_OIDC_SCOPES]);
  });

  it("defaults when the provider declares an empty scope list", () => {
    const config = mapSsoProviderToOAuthConfig({ ...GENERIC_OIDC, scopes: [] });
    expect(config.scopes).toEqual([...DEFAULT_OIDC_SCOPES]);
  });

  it("keeps an explicit scope list", () => {
    const config = mapSsoProviderToOAuthConfig({ ...GENERIC_OIDC, scopes: ["openid", "email", "groups"] });
    expect(config.scopes).toEqual(["openid", "email", "groups"]);
  });
});
