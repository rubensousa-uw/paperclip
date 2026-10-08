import { createServer, type RequestListener } from "node:http";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { genericOAuth } from "better-auth/plugins";
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

async function localIdp(listener: RequestListener) {
  const server = createServer(listener);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Expected a local TCP listener");
  return {
    origin: `http://127.0.0.1:${address.port}`,
    close: () => new Promise<void>((resolve, reject) => {
      server.closeAllConnections();
      server.close((error) => error ? reject(error) : resolve());
    }),
  };
}

function shortDiscoveryTimeout() {
  // Keep the production 10 s option, but shorten its real abort signal so the
  // tests finish quickly. The readiness guard remains a separate, later limit.
  const timeout = AbortSignal.timeout;
  return vi.spyOn(AbortSignal, "timeout").mockImplementation((ms) => timeout(Math.min(ms, 100)));
}

function authTestEnvironment() {
  vi.stubEnv("BETTER_AUTH_SECRET", "better-auth-test-secret-that-is-long-enough");
  vi.stubEnv("PAPERCLIP_PUBLIC_URL", ORIGIN);
  vi.stubEnv("PAPERCLIP_AUTH_RATE_LIMIT_ENABLED", "false");
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.clearAllMocks();
  vi.restoreAllMocks();
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

  it("drops all SSO providers when the last-resort readiness guard times out and keeps password auth", async () => {
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
    expect(logger.warn).toHaveBeenCalledTimes(2);
    expect(logger.warn).toHaveBeenCalledWith({ providerId: healthy.providerId }, "SSO provider disabled because OIDC discovery failed");
    expect(logger.warn).toHaveBeenCalledWith({ providerId: hanging.providerId }, "SSO provider disabled because OIDC discovery failed");
  });

  it("handles two providers sharing one discovery URL independently when the second request hangs", async () => {
    authTestEnvironment();
    const timeout = shortDiscoveryTimeout();
    let requests = 0;
    let aborted = false;
    const fetchMock = vi.fn((_input: string | URL | Request, init?: RequestInit) => {
      requests += 1;
      if (requests === 2) {
        const signal = init!.signal!;
        return new Promise<Response>((_resolve, reject) => {
          signal.addEventListener("abort", () => {
            aborted = true;
            reject(signal.reason);
          }, { once: true });
        });
      }
      return Promise.resolve(discoveryResponse());
    });
    vi.stubGlobal("fetch", fetchMock);
    const healthy = { ...PROVIDER, providerId: "shared-healthy" };
    const hanging = { ...PROVIDER, providerId: "shared-hanging" };
    const manager = await createBetterAuthManager({} as never, config([healthy, hanging]), [ORIGIN], { discoveryTimeoutMs: 1_500 });

    expect(aborted).toBe(true);
    // Healthy discovery is repeated after the failed provider is removed.
    expect(requests).toBe(3);
    expect(timeout).toHaveBeenCalledWith(SSO_DISCOVERY_BOOT_TIMEOUT_MS);
    const [url, request] = fetchMock.mock.calls[1]!;
    expect(String(url)).toBe(DISCOVERY_URL);
    expect((request as RequestInit & { timeout: number }).timeout).toBe(SSO_DISCOVERY_BOOT_TIMEOUT_MS);
    expect(request!.signal!.aborted).toBe(true);
    expect(logger.warn).toHaveBeenCalledExactlyOnceWith(
      { providerId: hanging.providerId }, "SSO provider disabled because OIDC discovery failed",
    );
    expect((await signIn(manager, healthy.providerId)).status).toBe(200);
  });

  it("aborts a hanging discovery body and drops only that provider", async () => {
    authTestEnvironment();
    shortDiscoveryTimeout();
    let aborted = false;
    let sentHeaders = false;
    const idp = await localIdp((req, res) => {
      res.setHeader("content-type", "application/json");
      if (req.url === "/hanging-body") {
        res.on("close", () => { aborted = !res.writableEnded; });
        res.flushHeaders();
        res.write('{"issuer":');
        sentHeaders = true;
        return;
      }
      res.end(JSON.stringify({
        issuer: idp.origin,
        authorization_endpoint: `${idp.origin}/authorize`,
        token_endpoint: `${idp.origin}/token`,
      }));
    });
    try {
      const hanging = { ...PROVIDER, discoveryUrl: `${idp.origin}/hanging-body` };
      const healthy = { ...PROVIDER, providerId: "healthy-idp", discoveryUrl: `${idp.origin}/discovery` };
      const manager = await createBetterAuthManager({} as never, config([hanging, healthy]), [ORIGIN], { discoveryTimeoutMs: 1_500 });

      expect(sentHeaders).toBe(true);
      // Readiness fallback alone leaves this socket open. This assertion proves
      // cancellation of the body read through the real patched package path.
      await vi.waitFor(() => expect(aborted).toBe(true));
      expect(logger.warn).toHaveBeenCalledExactlyOnceWith(
        { providerId: hanging.providerId }, "SSO provider disabled because OIDC discovery failed",
      );
      expect((await signIn(manager, healthy.providerId)).status).toBe(200);
    } finally {
      await idp.close();
    }
  });

  it("bounds a hanging JWKS fetch with the configured jose timeoutDuration", async () => {
    authTestEnvironment();
    let jwksRequested = false;
    let aborted = false;
    vi.stubGlobal("fetch", vi.fn((input: string | URL | Request, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.endsWith("/jwks")) {
        jwksRequested = true;
        const signal = init!.signal!;
        return new Promise<Response>((_resolve, reject) => {
          signal.addEventListener("abort", () => {
            aborted = true;
            reject(signal.reason);
          }, { once: true });
        });
      }
      return Promise.resolve(discoveryResponse());
    }));
    const auth = betterAuth({
      baseURL: ORIGIN,
      secret: process.env.BETTER_AUTH_SECRET,
      database: memoryAdapter({ user: [], session: [], account: [], verification: [] }),
      plugins: [genericOAuth({ config: [{
        providerId: PROVIDER.providerId,
        clientId: PROVIDER.clientId,
        clientSecret: PROVIDER.clientSecret,
        discoveryUrl: DISCOVERY_URL,
        discoveryFetchOptions: { timeout: 100 },
      }] })],
    });
    const ctx = await auth.$context;
    const provider = ctx.socialProviders.find((p) => p.id === PROVIDER.providerId)!;
    // JWKS fetching is lazy. Exercise the resolver that the real plugin
    // installed for ID-token verification. Only the HTTP transport is mocked.
    expect(jwksRequested).toBe(false);
    expect(provider.idToken).toMatchObject({
      issuer: "https://idp.example.com", audience: PROVIDER.clientId, algorithms: ["RS256"],
    });
    expect(provider.requiresIdTokenNonce).toBe(true);
    const started = performance.now();
    await expect(provider.idToken!.jwks({ alg: "RS256", kid: "test-key" }, {
      payload: "", protected: "", signature: "",
    })).rejects.toMatchObject({ name: "JWKSTimeout", code: "ERR_JWKS_TIMEOUT" });
    expect(performance.now() - started).toBeLessThan(1_500);
    expect(jwksRequested).toBe(true);
    expect(aborted).toBe(true);
  }, 2_000);

  it("aborts a hanging discovery body through a signal-aware stream transport", async () => {
    authTestEnvironment();
    shortDiscoveryTimeout();
    let aborted = false;
    vi.stubGlobal("fetch", vi.fn((input: string | URL | Request, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url.includes("healthy.example.com")) return Promise.resolve(discoveryResponse());
      const signal = init!.signal!;
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"issuer":'));
          signal.addEventListener("abort", () => {
            aborted = true;
            controller.error(signal.reason);
          }, { once: true });
        },
      });
      return Promise.resolve(new Response(body, { headers: { "content-type": "application/json" } }));
    }));
    const healthy = { ...PROVIDER, providerId: "healthy-idp", discoveryUrl: "https://healthy.example.com/discovery" };
    const manager = await createBetterAuthManager({} as never, config([PROVIDER, healthy]), [ORIGIN], { discoveryTimeoutMs: 1_500 });

    // Supplemental body-consumption proof for environments that prohibit
    // loopback listeners. The local node:http regression above remains required.
    expect(aborted).toBe(true);
    expect(logger.warn).toHaveBeenCalledExactlyOnceWith(
      { providerId: PROVIDER.providerId }, "SSO provider disabled because OIDC discovery failed",
    );
    expect((await signIn(manager, healthy.providerId)).status).toBe(200);
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
