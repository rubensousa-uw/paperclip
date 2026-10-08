import { memoryAdapter } from "better-auth/adapters/memory";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SsoProviderConfig } from "@paperclipai/shared";
import { createBetterAuthManager } from "../auth/better-auth.js";
import type { Config } from "../config.js";
import { logger } from "../middleware/logger.js";

vi.mock("better-auth/adapters/drizzle", () => ({ drizzleAdapter: vi.fn(() => memoryAdapter({ user: [], session: [], account: [], verification: [] })) }));
vi.mock("../middleware/logger.js", () => ({ logger: { warn: vi.fn(), info: vi.fn(), error: vi.fn() } }));

const ORIGIN = "http://paperclip.localhost:41999";
const DISCOVERY_URL = "https://idp.example.com/.well-known/openid-configuration";
const PROVIDER: SsoProviderConfig = {
  type: "oidc",
  providerId: "rehearsal-idp",
  clientId: "test-client-id",
  clientSecret: "secret-must-not-be-logged",
  discoveryUrl: DISCOVERY_URL,
};

function config(ssoProviders: SsoProviderConfig[]): Config {
  return {
    deploymentMode: "authenticated",
    deploymentExposure: "private",
    authBaseUrlMode: "explicit",
    authPublicBaseUrl: ORIGIN,
    authDisableSignUp: false,
    ssoProviders,
  } as Config;
}

function discoveryResponse() {
  return Response.json({
    issuer: "https://idp.example.com",
    authorization_endpoint: "https://idp.example.com/authorize",
    token_endpoint: "https://idp.example.com/token",
    userinfo_endpoint: "https://idp.example.com/userinfo",
    jwks_uri: "https://idp.example.com/jwks",
    id_token_signing_alg_values_supported: ["RS256"],
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.clearAllMocks();
});

describe("OIDC discovery failures during Better Auth startup", () => {
  it("disables only a provider whose real genericOAuth init fails, keeps password auth, and restores it on rebuild", async () => {
    vi.stubEnv("BETTER_AUTH_SECRET", "better-auth-test-secret-that-is-long-enough");
    vi.stubEnv("PAPERCLIP_PUBLIC_URL", ORIGIN);
    vi.stubEnv("PAPERCLIP_AUTH_RATE_LIMIT_ENABLED", "false");
    const fetchMock = vi.fn(async () => {
      throw new Error("network unavailable");
    });
    vi.stubGlobal("fetch", fetchMock);

    // This is the production manager path used by server startup. Awaiting the
    // manager awaits Better Auth's real genericOAuth plugin init and discovery.
    const manager = await createBetterAuthManager({} as never, config([PROVIDER]), [ORIGIN]);
    const missingProvider = await manager.fetch(new Request(`${ORIGIN}/api/auth/sign-in/social`, {
      method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" },
      body: JSON.stringify({ provider: PROVIDER.providerId, callbackURL: `${ORIGIN}/` }),
    }));
    expect(missingProvider.status).not.toBe(200);

    const passwordAuth = await manager.fetch(new Request(`${ORIGIN}/api/auth/sign-in/email`, {
      method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" },
      body: JSON.stringify({ email: "nobody@example.com", password: "not-a-password" }),
    }));
    expect(passwordAuth.status).toBe(401);

    expect(logger.warn).toHaveBeenCalledTimes(1);
    expect(logger.warn).toHaveBeenCalledWith(
      { providerId: PROVIDER.providerId },
      "SSO provider disabled because OIDC discovery failed",
    );
    expect(JSON.stringify(vi.mocked(logger.warn).mock.calls)).not.toContain(PROVIDER.clientSecret);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    fetchMock.mockImplementation(async () => discoveryResponse());
    await manager.rebuild([PROVIDER]);
    const restoredProvider = await manager.fetch(new Request(`${ORIGIN}/api/auth/sign-in/social`, {
      method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" },
      body: JSON.stringify({ provider: PROVIDER.providerId, callbackURL: `${ORIGIN}/` }),
    }));
    expect(restoredProvider.status).toBe(200);
  });

  it("registers a provider when discovery succeeds", async () => {
    vi.stubEnv("BETTER_AUTH_SECRET", "better-auth-test-secret-that-is-long-enough");
    vi.stubEnv("PAPERCLIP_PUBLIC_URL", ORIGIN);
    vi.stubEnv("PAPERCLIP_AUTH_RATE_LIMIT_ENABLED", "false");
    vi.stubGlobal("fetch", vi.fn(async () => discoveryResponse()));

    const manager = await createBetterAuthManager({} as never, config([PROVIDER]), [ORIGIN]);
    const response = await manager.fetch(new Request(`${ORIGIN}/api/auth/sign-in/social`, {
      method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" },
      body: JSON.stringify({ provider: PROVIDER.providerId, callbackURL: `${ORIGIN}/` }),
    }));

    expect(response.status).toBe(200);
    expect(await response.text()).toContain("idp.example.com/authorize");
    expect(logger.warn).not.toHaveBeenCalled();
  });
});
