import { memoryAdapter } from "better-auth/adapters/memory";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SsoProviderConfig } from "@paperclipai/shared";
import { createBetterAuthManager, SSO_DISCOVERY_BOOT_TIMEOUT_MS } from "../auth/better-auth.js";
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

function signIn(manager: Awaited<ReturnType<typeof createBetterAuthManager>>, providerId = PROVIDER.providerId) {
  return manager.fetch(new Request(`${ORIGIN}/api/auth/sign-in/social`, {
    method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" },
    body: JSON.stringify({ provider: providerId, callbackURL: `${ORIGIN}/` }),
  }));
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

    // The attempted social sign-in made one rate-limited recovery attempt,
    // which also failed, so startup and recovery each log their provider.
    expect(logger.warn).toHaveBeenCalledTimes(2);
    expect(logger.warn).toHaveBeenCalledWith(
      { providerId: PROVIDER.providerId },
      "SSO provider disabled because OIDC discovery failed",
    );
    expect(JSON.stringify(vi.mocked(logger.warn).mock.calls)).not.toContain(PROVIDER.clientSecret);
    expect(fetchMock).toHaveBeenCalledTimes(2);

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

  it("drops a provider when discovery returns a document without an issuer", async () => {
    vi.stubEnv("BETTER_AUTH_SECRET", "better-auth-test-secret-that-is-long-enough");
    vi.stubEnv("PAPERCLIP_PUBLIC_URL", ORIGIN);
    vi.stubEnv("PAPERCLIP_AUTH_RATE_LIMIT_ENABLED", "false");
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({ authorization_endpoint: "https://idp.example.com/authorize", token_endpoint: "https://idp.example.com/token" })));

    const manager = await createBetterAuthManager({} as never, config([PROVIDER]), [ORIGIN]);
    expect((await signIn(manager)).status).not.toBe(200);
    expect(logger.warn).toHaveBeenCalledTimes(2);
    expect(logger.warn).toHaveBeenCalledWith({ providerId: PROVIDER.providerId }, "SSO provider disabled because OIDC discovery failed");
  });

  it("keeps a healthy provider when another provider fails discovery", async () => {
    vi.stubEnv("BETTER_AUTH_SECRET", "better-auth-test-secret-that-is-long-enough");
    vi.stubEnv("PAPERCLIP_PUBLIC_URL", ORIGIN);
    vi.stubEnv("PAPERCLIP_AUTH_RATE_LIMIT_ENABLED", "false");
    const healthy = { ...PROVIDER, providerId: "healthy-idp", discoveryUrl: "https://healthy.example.com/.well-known/openid-configuration" };
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = input instanceof Request ? input.url : String(input);
      return url.includes("healthy.example.com") ? Response.json({ ...await discoveryResponse().json(), issuer: "https://healthy.example.com" }) : Promise.reject(new Error("network unavailable"));
    });
    vi.stubGlobal("fetch", fetchMock);

    const manager = await createBetterAuthManager({} as never, config([PROVIDER, healthy]), [ORIGIN]);
    expect((await signIn(manager, healthy.providerId)).status).toBe(200);
    expect((await signIn(manager, PROVIDER.providerId)).status).not.toBe(200);
    expect(logger.warn).toHaveBeenCalledTimes(2);
  });

  it("keeps password sign-up invite-only after an SSO provider fallback", async () => {
    vi.stubEnv("BETTER_AUTH_SECRET", "better-auth-test-secret-that-is-long-enough");
    vi.stubEnv("PAPERCLIP_PUBLIC_URL", ORIGIN);
    vi.stubEnv("PAPERCLIP_AUTH_RATE_LIMIT_ENABLED", "false");
    vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("network unavailable"); }));
    const manager = await createBetterAuthManager({} as never, config([PROVIDER]), [ORIGIN]);

    const response = await manager.fetch(new Request(`${ORIGIN}/api/auth/sign-up/email`, {
      method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" },
      body: JSON.stringify({ name: "No Invite", email: "nobody@example.com", password: "not-a-password" }),
    }));
    expect(response.status).toBe(403);
    expect(await response.text()).toContain("INVITE_REQUIRED");
  });

  it("times out a hanging discovery at boot, drops the provider, and logs once", async () => {
    vi.stubEnv("BETTER_AUTH_SECRET", "better-auth-test-secret-that-is-long-enough");
    vi.stubEnv("PAPERCLIP_PUBLIC_URL", ORIGIN);
    vi.stubEnv("PAPERCLIP_AUTH_RATE_LIMIT_ENABLED", "false");
    const healthy = { ...PROVIDER, providerId: "healthy-idp", discoveryUrl: "https://healthy.example.com/.well-known/openid-configuration" };
    const hanging = { ...PROVIDER, providerId: "hanging-idp", discoveryUrl: "https://hanging.example.com/.well-known/openid-configuration" };
    vi.stubGlobal("fetch", vi.fn((input: string | URL | Request) => {
      const url = input instanceof Request ? input.url : String(input);
      return url.includes("hanging.example.com") ? new Promise<Response>(() => undefined) : Promise.resolve(discoveryResponse());
    }));
    const manager = await createBetterAuthManager({} as never, config([healthy, hanging]), [ORIGIN], { discoveryTimeoutMs: 15 });

    expect(SSO_DISCOVERY_BOOT_TIMEOUT_MS).toBe(10_000);
    const passwordAuth = await manager.fetch(new Request(`${ORIGIN}/api/auth/sign-in/email`, {
      method: "POST", headers: { origin: ORIGIN, "content-type": "application/json" },
      body: JSON.stringify({ email: "nobody@example.com", password: "not-a-password" }),
    }));
    expect(passwordAuth.status).toBe(401);
    expect((await signIn(manager, healthy.providerId)).status).toBe(200);
    expect(logger.warn).toHaveBeenCalledTimes(1);
    expect(logger.warn).toHaveBeenCalledWith({ providerId: hanging.providerId }, "SSO provider disabled because OIDC discovery failed");
  });

  it("discards an older enable rebuild that resolves after a newer disable rebuild", async () => {
    vi.stubEnv("BETTER_AUTH_SECRET", "better-auth-test-secret-that-is-long-enough");
    vi.stubEnv("PAPERCLIP_PUBLIC_URL", ORIGIN);
    vi.stubEnv("PAPERCLIP_AUTH_RATE_LIMIT_ENABLED", "false");
    let resolveDiscovery!: (response: Response) => void;
    const fetchMock = vi.fn(() => new Promise<Response>((resolve) => { resolveDiscovery = resolve; }));
    vi.stubGlobal("fetch", fetchMock);
    const manager = await createBetterAuthManager({} as never, config([]), [ORIGIN]);

    const enabling = manager.rebuild([PROVIDER]);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    await manager.rebuild([]);
    resolveDiscovery(discoveryResponse());
    await enabling;
    expect((await signIn(manager)).status).not.toBe(200);
  });

  it("recovers a dropped provider on sign-in and shares one concurrent recovery rebuild", async () => {
    vi.stubEnv("BETTER_AUTH_SECRET", "better-auth-test-secret-that-is-long-enough");
    vi.stubEnv("PAPERCLIP_PUBLIC_URL", ORIGIN);
    vi.stubEnv("PAPERCLIP_AUTH_RATE_LIMIT_ENABLED", "false");
    let calls = 0;
    let resolveRecovery!: (response: Response) => void;
    const fetchMock = vi.fn(() => {
      calls += 1;
      if (calls === 1) return Promise.reject(new Error("network unavailable"));
      return new Promise<Response>((resolve) => { resolveRecovery = resolve; });
    });
    vi.stubGlobal("fetch", fetchMock);
    const manager = await createBetterAuthManager({} as never, config([PROVIDER]), [ORIGIN]);
    const first = signIn(manager);
    const second = signIn(manager);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    resolveRecovery(discoveryResponse());
    expect((await first).status).toBe(200);
    expect((await second).status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("rate-limits repeated failed sign-in recovery attempts for 60 seconds", async () => {
    vi.stubEnv("BETTER_AUTH_SECRET", "better-auth-test-secret-that-is-long-enough");
    vi.stubEnv("PAPERCLIP_PUBLIC_URL", ORIGIN);
    vi.stubEnv("PAPERCLIP_AUTH_RATE_LIMIT_ENABLED", "false");
    const fetchMock = vi.fn(async () => { throw new Error("network unavailable"); });
    vi.stubGlobal("fetch", fetchMock);
    let now = 1_000;
    const manager = await createBetterAuthManager({} as never, config([PROVIDER]), [ORIGIN], { now: () => now });

    expect((await signIn(manager)).status).not.toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect((await signIn(manager)).status).not.toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    now += 60_000;
    expect((await signIn(manager)).status).not.toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });
});
