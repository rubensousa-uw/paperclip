import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import type { Auth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { memoryAdapter } from "better-auth/adapters/memory";
import { drizzle } from "drizzle-orm/pg-proxy";
import type { Db } from "@paperclipai/db";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createBetterAuthInstance } from "../auth/better-auth.js";
import type { Config } from "../config.js";
import { logger } from "../middleware/logger.js";

vi.mock("better-auth/adapters/drizzle", () => ({ drizzleAdapter: vi.fn() }));
vi.mock("../middleware/logger.js", () => ({ logger: { warn: vi.fn() } }));

const ORIGIN = "http://paperclip.localhost:41999";
const IDP = "https://idp.example.com";
const EMAIL = "founder@example.com";
const TOKEN = "pcp_bootstrap_test-invite-token";
const INVITE_URL = `${ORIGIN}/invite/${TOKEN}`;
const CALLBACK_URL = `${ORIGIN}/auth?next=${encodeURIComponent(`/invite/${TOKEN}`)}`;
const NOW = new Date("2026-09-08T12:00:00.000Z");
const PASSWORD = "correct-horse-battery-staple";

describe("invite-only Better Auth user creation", () => {
  let sqlite: DatabaseSync;
  let auth: Auth;
  let store: Record<string, Record<string, unknown>[]>;
  let userCreate: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
    vi.stubEnv("BETTER_AUTH_SECRET", "better-auth-secret-for-invite-only-tests");
    vi.stubEnv("PAPERCLIP_AUTH_RATE_LIMIT_ENABLED", "false");
    vi.stubEnv("PAPERCLIP_PUBLIC_URL", ORIGIN);
    vi.stubEnv("PAPERCLIP_WORKSPACE_HANDOFF_KEY", "");
    vi.clearAllMocks();
    // Execute the production Drizzle SELECT (including every WHERE predicate)
    // in SQLite. Only auth persistence and provider responses are test doubles;
    // no listener, external database, or live IdP is needed.
    sqlite = new DatabaseSync(":memory:");
    sqlite.exec(`CREATE TABLE invites (
      id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, invite_type TEXT NOT NULL,
      allowed_join_types TEXT NOT NULL, expires_at TEXT NOT NULL,
      accepted_at TEXT, revoked_at TEXT
    )`);
    const db = drizzle(async (sql, params) => {
      const statement = sqlite.prepare(sql);
      statement.setReturnArrays(true);
      const bindings = Object.fromEntries(params.map((value, i) => [`$${i + 1}`, value]));
      return { rows: statement.all(bindings) as unknown as unknown[][] };
    }) as unknown as Db;
    store = { user: [], session: [], account: [], verification: [] };
    vi.mocked(drizzleAdapter).mockReturnValue(memoryAdapter(store));
    vi.stubGlobal("fetch", vi.fn(async (input: string | URL | Request) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === `${IDP}/discovery`) return Response.json({
        issuer: IDP,
        authorization_endpoint: `${IDP}/authorize`,
        token_endpoint: `${IDP}/token`,
        userinfo_endpoint: `${IDP}/userinfo`,
      });
      if (url === `${IDP}/token`) return Response.json({ access_token: "test-token", token_type: "Bearer" });
      if (url === `${IDP}/userinfo`) return Response.json({
        id: "provider-user", sub: "provider-user", email: EMAIL, name: "Founder", email_verified: true,
      });
      throw new Error(`Unexpected provider request: ${url}`);
    }));
    auth = createBetterAuthInstance(db, {
      deploymentMode: "authenticated",
      deploymentExposure: "private",
      authBaseUrlMode: "explicit",
      authPublicBaseUrl: ORIGIN,
      authDisableSignUp: false,
      ssoProviders: [{
        type: "oidc", providerId: "oidc", clientId: "test-client", clientSecret: "test-secret",
        discoveryUrl: `${IDP}/discovery`,
      }],
    } as Config, [ORIGIN]) as Auth;
    userCreate = vi.spyOn(auth.options.databaseHooks!.user!.create!, "before");
  });

  afterEach(() => {
    sqlite.close();
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  function seedInvite(overrides: { type?: string; joins?: string; expires?: Date; accepted?: Date; revoked?: Date } = {}) {
    sqlite.prepare("INSERT INTO invites VALUES (?, ?, ?, ?, ?, ?, ?)").run(
      "invite-1", createHash("sha256").update(TOKEN).digest("hex"),
      overrides.type ?? "company_join", overrides.joins ?? "human",
      (overrides.expires ?? new Date(NOW.getTime() + 60_000)).toISOString(),
      overrides.accepted?.toISOString() ?? null, overrides.revoked?.toISOString() ?? null,
    );
  }

  function post(path: string, body: Record<string, unknown>, headers: Record<string, string> = {}) {
    return auth.handler(new Request(`${ORIGIN}/api/auth${path}`, {
      method: "POST", headers: { origin: ORIGIN, "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
    }));
  }

  function signUp(referer?: string) {
    return post("/sign-up/email", { email: EMAIL, password: PASSWORD, name: "Founder" },
      referer ? { referer } : {});
  }

  async function startOAuth(callbackURL: string, requestSignUp = true) {
    const response = await post("/sign-in/social", { provider: "oidc", callbackURL, requestSignUp });
    expect(response.status).toBe(200);
    const { url } = await response.json();
    return {
      state: new URL(url).searchParams.get("state")!,
      cookie: response.headers.getSetCookie().map((value) => value.split(";")[0]).join("; "),
    };
  }

  function finishOAuth(flow: { state: string; cookie: string }) {
    return auth.handler(new Request(
      `${ORIGIN}/api/auth/callback/oidc?code=test-code&state=${encodeURIComponent(flow.state)}`,
      { headers: { cookie: flow.cookie } },
    ));
  }

  function expectNoAccount() {
    expect(store.user).toHaveLength(0);
    expect(store.account).toHaveLength(0);
    expect(store.session).toHaveLength(0);
    expect(logger.warn).toHaveBeenCalledWith(
      { email: EMAIL }, "Account creation rejected: a pending invite is required",
    );
  }

  it("rejects password creation without an invite with a readable 403 and audit log", async () => {
    const response = await signUp();
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: "INVITE_REQUIRED", message: expect.stringContaining("invite") });
    expectNoAccount();
  });

  it.each(["human", "both"])("allows password creation with a pending %s invite", async (joins) => {
    seedInvite({ joins });
    const response = await signUp(INVITE_URL);
    expect(response.status).toBe(200);
    expect(store.user).toHaveLength(1);
    expect(store.account).toHaveLength(1);
    expect(userCreate).toHaveBeenCalledOnce();
  });

  it("allows bootstrap creation and leaves consumption for the admin-claim route", async () => {
    seedInvite({ type: "bootstrap_ceo" });
    expect((await signUp(INVITE_URL)).status).toBe(200);
    expect(sqlite.prepare("SELECT accepted_at FROM invites").get()?.accepted_at).toBeNull();
  });

  it.each([
    { expires: new Date(NOW.getTime() - 1) }, { expires: NOW },
    { accepted: NOW }, { revoked: NOW }, { joins: "agent" }, { type: "unknown" },
  ])("rejects an unusable invite: %j", async (overrides) => {
    seedInvite(overrides);
    expect((await signUp(INVITE_URL)).status).toBe(403);
    expectNoAccount();
  });

  it.each([undefined, `${ORIGIN}/invite/unknown`, `${IDP}/invite/${TOKEN}`, `${ORIGIN}/invite/%ZZ`])(
    "does not authorize from an unrelated pending invite: %s", async (referer) => {
      seedInvite();
      expect((await signUp(referer)).status).toBe(403);
      expectNoAccount();
    },
  );

  it("blocks client-controlled requestSignUp at the real OAuth callback without an invite", async () => {
    const response = await finishOAuth(await startOAuth(`${ORIGIN}/auth`, true));
    expect(response.status).toBe(302);
    const location = new URL(response.headers.get("location")!);
    expect(location.searchParams.get("error")).toBe("INVITE_REQUIRED");
    expect(location.searchParams.get("error_description")).toContain("invite");
    expect(userCreate).toHaveBeenCalledOnce();
    expectNoAccount();
  });

  it.each(["company_join", "bootstrap_ceo"])("allows OAuth creation with a pending %s invite in saved state", async (type) => {
    seedInvite({ type });
    const response = await finishOAuth(await startOAuth(CALLBACK_URL));
    expect(response.status).toBe(302);
    expect(response.headers.get("location")).toBe(CALLBACK_URL);
    expect(store.user).toHaveLength(1);
    expect(store.account).toHaveLength(1);
    expect(store.session).toHaveLength(1);
    expect(userCreate).toHaveBeenCalledOnce();
  });

  it("rechecks invite revocation after OAuth starts", async () => {
    seedInvite();
    const flow = await startOAuth(CALLBACK_URL);
    sqlite.exec(`UPDATE invites SET revoked_at = '${NOW.toISOString()}'`);
    const response = await finishOAuth(flow);
    expect(new URL(response.headers.get("location")!).searchParams.get("error")).toBe("INVITE_REQUIRED");
    expectNoAccount();
  });

  it("does not accept a forged callback query in place of the saved invite URL", async () => {
    seedInvite();
    const flow = await startOAuth(`${ORIGIN}/auth`);
    const response = await auth.handler(new Request(
      `${ORIGIN}/api/auth/callback/oidc?code=test-code&state=${encodeURIComponent(flow.state)}&callbackURL=${encodeURIComponent(CALLBACK_URL)}`,
      { headers: { cookie: flow.cookie, referer: INVITE_URL } },
    ));
    expect(new URL(response.headers.get("location")!).searchParams.get("error")).toBe("INVITE_REQUIRED");
    expectNoAccount();
  });

  it("fails closed for internal user creation without request context", async () => {
    seedInvite();
    const context = await auth.$context;
    await expect(context.internalAdapter.createUser({ email: EMAIL, name: "Founder", emailVerified: false }))
      .rejects.toMatchObject({ status: "FORBIDDEN", body: { code: "INVITE_REQUIRED" } });
    expectNoAccount();
  });

  it("keeps disableImplicitSignUp enforced even with a valid invite", async () => {
    seedInvite();
    await finishOAuth(await startOAuth(CALLBACK_URL, false));
    expect(store.user).toHaveLength(0);
    expect(userCreate).not.toHaveBeenCalled();
  });

  it("links and signs in an existing password user through OAuth without running user.create", async () => {
    seedInvite();
    expect((await signUp(INVITE_URL)).status).toBe(200);
    const existingId = store.user[0]!.id;
    expect(store.user[0]!.emailVerified).toBe(false);
    sqlite.exec("DELETE FROM invites");
    userCreate.mockClear();
    const passwordSignIn = await post("/sign-in/email", { email: EMAIL, password: PASSWORD });
    expect(passwordSignIn.status).toBe(200);
    for (let i = 0; i < 2; i++) {
      const response = await finishOAuth(await startOAuth(`${ORIGIN}/auth`, false));
      expect(response.headers.get("location")).toBe(`${ORIGIN}/auth`);
    }
    expect(store.user).toHaveLength(1);
    expect(store.user[0]!.id).toBe(existingId);
    expect(store.account.map((account) => account.providerId).sort()).toEqual(["credential", "oidc"]);
    expect(userCreate).not.toHaveBeenCalled();
  });
});
