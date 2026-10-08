import type { Request, RequestHandler } from "express";
import type { IncomingHttpHeaders } from "node:http";
import { createHash } from "node:crypto";
import { betterAuth, type Auth, type BetterAuthOptions } from "better-auth";
import { APIError, getOAuthState } from "better-auth/api";
import { and, eq, gt, inArray, isNull } from "drizzle-orm";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { toNodeHandler } from "better-auth/node";
import {
  genericOAuth,
  keycloak,
  auth0,
  okta,
  microsoftEntraId,
} from "better-auth/plugins";
import type { GenericOAuthConfig } from "better-auth/plugins";
import type { Db } from "@paperclipai/db";
import {
  authAccounts,
  authSessions,
  authUsers,
  authVerifications,
  invites,
} from "@paperclipai/db";
import type { SsoProviderConfig, SsoRoleRequirement } from "@paperclipai/shared";
import type { Config } from "../config.js";
import { logger } from "../middleware/logger.js";
import { resolvePaperclipInstanceId } from "../home-paths.js";
import {
  workspaceLoginHandoffPlugin,
  type WorkspaceHandoffExpectedIdentity,
} from "./workspace-login-handoff-plugin.js";
import {
  normalizeWorkspaceHandoffOrigin,
  resolveWorkspaceHandoffLocalCompanyId,
  resolveWorkspaceHandoffLocalKey,
  resolveWorkspaceHandoffLocalWorkspaceId,
} from "./workspace-login-handoff.js";

export type BetterAuthSessionUser = {
  id: string;
  email?: string | null;
  name?: string | null;
};

export type BetterAuthSessionResult = {
  session: { id: string; userId: string } | null;
  user: BetterAuthSessionUser | null;
};

type BetterAuthGetSessionApi = {
  getSession?: (input: { headers: Headers }) => Promise<unknown>;
};

type BetterAuthHandlerTarget = Extract<Parameters<typeof toNodeHandler>[0], { handler: Auth["handler"] }>;

type BetterAuthSessionResolver = {
  api?: BetterAuthGetSessionApi;
};

type BetterAuthInstance = BetterAuthHandlerTarget & BetterAuthSessionResolver & {
  $context?: Promise<unknown>;
  $paperclipSsoProviderIds?: string[];
};

const AUTH_COOKIE_PREFIX_FALLBACK = "default";
const AUTH_COOKIE_PREFIX_INVALID_SEGMENTS_RE = /[^a-zA-Z0-9_-]+/g;

export function deriveAuthCookiePrefix(instanceId = resolvePaperclipInstanceId()): string {
  const scopedInstanceId = instanceId
    .trim()
    .replace(AUTH_COOKIE_PREFIX_INVALID_SEGMENTS_RE, "-")
    .replace(/^-+|-+$/g, "") || AUTH_COOKIE_PREFIX_FALLBACK;
  return `paperclip-${scopedInstanceId}`;
}

export function buildBetterAuthAdvancedOptions(input: { disableSecureCookies: boolean }) {
  return {
    cookiePrefix: deriveAuthCookiePrefix(),
    ...(input.disableSecureCookies ? { useSecureCookies: false } : {}),
  };
}

export function shouldEnableAuthRateLimit(input: {
  deploymentMode: Config["deploymentMode"];
  deploymentExposure?: Config["deploymentExposure"];
  override?: string | undefined;
}): boolean {
  const override = input.override?.trim().toLowerCase();
  if (override === "true") return true;
  if (override === "false") return false;

  return input.deploymentMode === "authenticated";
}

export function buildBetterAuthRateLimitOptions(input: {
  deploymentMode: Config["deploymentMode"];
  deploymentExposure?: Config["deploymentExposure"];
  override?: string | undefined;
}) {
  return {
    enabled: shouldEnableAuthRateLimit(input),
  };
}

export function shouldDisableSecureAuthCookies(input: {
  deploymentMode: Config["deploymentMode"];
  deploymentExposure?: Config["deploymentExposure"];
  authBaseUrlMode: Config["authBaseUrlMode"];
  authPublicBaseUrl: string | undefined;
  publicUrl?: string | undefined;
  managedRuntimePublicUrl?: string | undefined;
  requestUrl?: string | undefined;
}): boolean {
  const publicUrl = (
    input.publicUrl?.trim() ||
    (input.authBaseUrlMode === "explicit" ? input.authPublicBaseUrl?.trim() : "")
  );
  if (
    input.deploymentMode === "authenticated" &&
    isHttpsUrl(publicUrl) &&
    isHttpsUrl(input.managedRuntimePublicUrl) &&
    isHttpLoopbackUrl(input.requestUrl)
  ) {
    return true;
  }
  if (publicUrl) return publicUrl.startsWith("http://");

  return (
    input.deploymentMode === "authenticated" &&
    (
      (input.deploymentExposure === "private" && input.authBaseUrlMode === "auto") ||
      input.deploymentExposure === undefined
    )
  );
}

function isHttpsUrl(value: string | undefined): boolean {
  if (!value) return false;
  try {
    return new URL(value).protocol === "https:";
  } catch {
    return false;
  }
}

function isLoopbackHostname(hostname: string): boolean {
  const normalized = hostname.trim().toLowerCase();
  return (
    normalized === "localhost" ||
    normalized === "127.0.0.1" ||
    normalized === "[::1]" ||
    normalized === "::1"
  );
}

function isHttpLoopbackUrl(value: string | undefined): boolean {
  if (!value) return false;
  try {
    const url = new URL(value);
    return url.protocol === "http:" && isLoopbackHostname(url.hostname);
  } catch {
    return false;
  }
}

function requestUrlFromHeaders(headers: Headers): string | undefined {
  const host = headers.get("host")?.trim();
  if (!host) return undefined;

  const forwardedProtocol = headers.get("x-forwarded-proto")?.split(",", 1)[0]?.trim().toLowerCase();
  const protocol = forwardedProtocol === "http" || forwardedProtocol === "https"
    ? forwardedProtocol
    : (() => {
      try {
        return isLoopbackHostname(new URL(`http://${host}`).hostname) ? "http" : "https";
      } catch {
        return "https";
      }
    })();
  return `${protocol}://${host}`;
}

function headersFromNodeHeaders(rawHeaders: IncomingHttpHeaders): Headers {
  const headers = new Headers();
  for (const [key, raw] of Object.entries(rawHeaders)) {
    if (!raw) continue;
    if (Array.isArray(raw)) {
      for (const value of raw) headers.append(key, value);
      continue;
    }
    headers.set(key, raw);
  }
  return headers;
}

function headersFromExpressRequest(req: Request): Headers {
  return headersFromNodeHeaders(req.headers);
}

export function deriveAuthTrustedOrigins(config: Config, opts?: { listenPort?: number }): string[] {
  const baseUrl = config.authBaseUrlMode === "explicit" ? config.authPublicBaseUrl : undefined;
  const trustedOrigins = new Set<string>();

  if (baseUrl) {
    try {
      trustedOrigins.add(new URL(baseUrl).origin);
    } catch {
      // Better Auth will surface invalid base URL separately.
    }
  }
  if (config.deploymentMode === "authenticated") {
    const port = opts?.listenPort ?? config.port;
    const needsPortVariants = port !== 80 && port !== 443;
    for (const hostname of config.allowedHostnames) {
      const trimmed = hostname.trim().toLowerCase();
      if (!trimmed) continue;
      trustedOrigins.add(`https://${trimmed}`);
      trustedOrigins.add(`http://${trimmed}`);
      if (needsPortVariants) {
        trustedOrigins.add(`https://${trimmed}:${port}`);
        trustedOrigins.add(`http://${trimmed}:${port}`);
      }
    }
  }

  return Array.from(trustedOrigins);
}

/**
 * Identity a managed workspace instance compares an inbound handoff ticket
 * against. Every field comes from persisted configuration or injected runtime
 * identity — never from request headers — so a spoofed `X-Forwarded-Host` or
 * Tailscale identity header cannot retarget a ticket. Returns null when this
 * process was not started as a managed workspace, which leaves the exchange
 * endpoint unregistered.
 */
export function resolveWorkspaceHandoffIdentity(
  config: Config,
  env: NodeJS.ProcessEnv = process.env,
): WorkspaceHandoffExpectedIdentity | null {
  const key = resolveWorkspaceHandoffLocalKey(env);
  if (!key) return null;
  const configuredOrigin =
    normalizeWorkspaceHandoffOrigin(env.PAPERCLIP_PUBLIC_URL)
    ?? (config.authBaseUrlMode === "explicit"
      ? normalizeWorkspaceHandoffOrigin(config.authPublicBaseUrl)
      : null);
  return {
    key,
    instanceId: resolvePaperclipInstanceId(),
    executionWorkspaceId: resolveWorkspaceHandoffLocalWorkspaceId(env),
    companyId: resolveWorkspaceHandoffLocalCompanyId(env),
    origin: configuredOrigin,
  };
}

function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  try {
    const parts = jwt.split(".");
    if (parts.length !== 3) return null;
    const payload = Buffer.from(parts[1]!, "base64url").toString("utf-8");
    return JSON.parse(payload) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function resolveClaimAtPath(claims: Record<string, unknown>, path: string): unknown {
  let current: unknown = claims;
  for (const segment of path.split(".")) {
    if (!current || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function userHasRequiredRole(
  claims: Record<string, unknown>,
  requirement: SsoRoleRequirement,
): boolean {
  const value = resolveClaimAtPath(claims, requirement.claimPath);
  if (Array.isArray(value)) {
    return requirement.roles.some((role: string) => value.includes(role));
  }
  if (typeof value === "string") {
    return requirement.roles.includes(value);
  }
  return false;
}

function mapSsoProviderToOAuthConfig(provider: SsoProviderConfig): GenericOAuthConfig {
  const base = {
    clientId: provider.clientId,
    clientSecret: provider.clientSecret,
    ...(provider.scopes ? { scopes: provider.scopes } : {}),
  };

  let baseConfig: GenericOAuthConfig;
  switch (provider.type) {
    case "keycloak":
      baseConfig = keycloak({ ...base, issuer: provider.issuer! });
      break;
    case "auth0":
      baseConfig = auth0({
        ...base,
        clientId: provider.clientId,
        clientSecret: provider.clientSecret,
        domain: provider.domain ?? new URL(provider.issuer!).hostname,
      });
      break;
    case "okta":
      baseConfig = okta({ ...base, issuer: provider.issuer! });
      break;
    case "microsoft_entra_id":
      baseConfig = microsoftEntraId({ ...base, tenantId: provider.tenantId! });
      break;
    case "oidc":
      baseConfig = {
        providerId: provider.providerId,
        discoveryUrl: provider.discoveryUrl!,
        ...base,
        scopes: provider.scopes?.length ? provider.scopes : ["openid", "email", "profile"],
      };
      break;
  }

  baseConfig.disableImplicitSignUp = true;
  baseConfig.discoveryFetchOptions = { timeout: SSO_DISCOVERY_BOOT_TIMEOUT_MS };
  return withRoleRestrictedUserInfo(baseConfig, provider);
}

export function withRoleRestrictedUserInfo(
  baseConfig: GenericOAuthConfig,
  provider: SsoProviderConfig,
): GenericOAuthConfig {
  if (!provider.requiredRoles) {
    return baseConfig;
  }

  const requirement = provider.requiredRoles;
  const upstreamGetUserInfo = baseConfig.getUserInfo;

  baseConfig.getUserInfo = async (tokens) => {
    const rawTokens = tokens.raw as Record<string, unknown> | undefined;
    const idToken = (tokens as Record<string, unknown>).idToken as string | undefined
      ?? rawTokens?.id_token as string | undefined;
    const accessToken = (tokens as Record<string, unknown>).accessToken as string | undefined
      ?? rawTokens?.access_token as string | undefined;

    let hasRole = false;

    if (idToken) {
      const claims = decodeJwtPayload(idToken);
      if (claims && userHasRequiredRole(claims, requirement)) {
        hasRole = true;
      }
    }

    if (!hasRole && accessToken) {
      const claims = decodeJwtPayload(accessToken);
      if (claims && userHasRequiredRole(claims, requirement)) {
        hasRole = true;
      }
    }

    if (idToken || accessToken) {
      if (!hasRole) {
        logger.warn(
          {
            providerId: provider.providerId,
            claimPath: requirement.claimPath,
            requiredRoles: requirement.roles,
          },
          "SSO login rejected: user does not have required role",
        );
        return null;
      }
    } else {
      logger.warn(
        { providerId: provider.providerId },
        "SSO role check skipped: no id_token or access_token in response — access denied",
      );
      return null;
    }

    if (upstreamGetUserInfo) {
      return upstreamGetUserInfo(tokens);
    }
    // Better Auth only falls back to its own user-info resolution when the
    // provider config has NO getUserInfo at all — and this wrapper is one.
    // Replicate its id_token fallback here (same shape as the plugin's
    // getUserInfo), otherwise every role-restricted provider whose helper
    // does not define getUserInfo fails with "user_info_is_missing".
    if (idToken) {
      const claims = decodeJwtPayload(idToken);
      if (claims && typeof claims.sub === "string" && typeof claims.email === "string") {
        return {
          id: claims.sub,
          emailVerified: Boolean(claims.email_verified),
          image: typeof claims.picture === "string" ? claims.picture : undefined,
          ...claims,
        } as Awaited<ReturnType<NonNullable<GenericOAuthConfig["getUserInfo"]>>>;
      }
    }
    logger.warn(
      { providerId: provider.providerId },
      "SSO login rejected: id_token lacks sub/email claims and provider has no getUserInfo",
    );
    return null;
  };

  return baseConfig;
}

function inviteTokenFromAuthUrl(raw: unknown, baseURL: string): string | null {
  if (typeof raw !== "string" || !raw) return null;
  try {
    const origin = new URL(baseURL).origin;
    let url = new URL(raw, origin);
    if (url.origin !== origin) return null;
    // InviteLanding sends OAuth back through /auth?next=/invite/<token>.
    if (url.pathname === "/auth") {
      const next = url.searchParams.get("next");
      if (!next) return null;
      url = new URL(next, origin);
    }
    if (url.origin !== origin) return null;
    const match = /^\/invite\/([^/]+)\/?$/.exec(url.pathname);
    return match ? decodeURIComponent(match[1]!) : null;
  } catch {
    return null;
  }
}

export function createBetterAuthInstance(db: Db, config: Config, trustedOrigins: string[]): BetterAuthInstance {
  const baseUrl = config.authBaseUrlMode === "explicit" ? config.authPublicBaseUrl : undefined;
  const publicUrl = process.env.PAPERCLIP_PUBLIC_URL?.trim() || baseUrl;
  const managedRuntimePublicUrl = process.env.PAPERCLIP_MANAGED_RUNTIME_PUBLIC_URL?.trim() || undefined;
  const secret = process.env.BETTER_AUTH_SECRET ?? process.env.PAPERCLIP_AGENT_JWT_SECRET;
  if (!secret) {
    throw new Error(
      "BETTER_AUTH_SECRET (or PAPERCLIP_AGENT_JWT_SECRET) must be set. " +
      "For local development, set BETTER_AUTH_SECRET=paperclip-dev-secret in your .env file.",
    );
  }
  const disableSecureCookies = shouldDisableSecureAuthCookies({
    deploymentMode: config.deploymentMode,
    deploymentExposure: config.deploymentExposure,
    authBaseUrlMode: config.authBaseUrlMode,
    authPublicBaseUrl: config.authPublicBaseUrl,
    publicUrl,
  });

  const oauthConfigs = config.ssoProviders.map(mapSsoProviderToOAuthConfig);
  const plugins = oauthConfigs.length > 0 ? [genericOAuth({ config: oauthConfigs })] : [];

  const authConfig: Record<string, unknown> = {
    baseURL: baseUrl,
    secret,
    trustedOrigins,
    database: drizzleAdapter(db, {
      provider: "pg",
      schema: {
        user: authUsers,
        session: authSessions,
        account: authAccounts,
        verification: authVerifications,
      },
    }),
    databaseHooks: {
      user: {
        create: {
          before: async (user, ctx) => {
            // Invites are bearer links, with no target-email column. Require
            // possession of a specific pending human invite, not just any row.
            // OAuth state has already been validated by Better Auth here.
            const oauthState = ctx ? await getOAuthState() : null;
            const inviteUrl = oauthState?.callbackURL
              ?? (ctx?.path === "/sign-up/email"
                ? ctx.body?.callbackURL ?? ctx.headers?.get("referer")
                : null);
            const token = ctx ? inviteTokenFromAuthUrl(inviteUrl, ctx.context.baseURL) : null;
            if (token) {
              const [invite] = await db
                .select({ id: invites.id })
                .from(invites)
                .where(and(
                  eq(invites.tokenHash, createHash("sha256").update(token).digest("hex")),
                  inArray(invites.inviteType, ["company_join", "bootstrap_ceo"]),
                  inArray(invites.allowedJoinTypes, ["human", "both"]),
                  isNull(invites.acceptedAt),
                  isNull(invites.revokedAt),
                  gt(invites.expiresAt, new Date()),
                ))
                .limit(1);
              // Acceptance still consumes the invite and grants membership (or
              // the bootstrap admin role) after authentication has completed.
              if (invite) return;
            }
            logger.warn({ email: user.email }, "Account creation rejected: a pending invite is required");
            throw new APIError("FORBIDDEN", {
              code: "INVITE_REQUIRED",
              message: "A valid, pending invite is required to create an account. Open your invite link and try again.",
            });
          },
        },
      },
    } satisfies NonNullable<BetterAuthOptions["databaseHooks"]>,
    emailAndPassword: {
      enabled: true,
      requireEmailVerification: false,
      disableSignUp: config.authDisableSignUp,
    },
    ...(plugins.length > 0 ? { plugins } : {}),
    ...(oauthConfigs.length > 0
      ? {
          account: {
            accountLinking: {
              enabled: true,
              requireLocalEmailVerified: false,
              trustedProviders: config.ssoProviders.map((p) => p.providerId),
            },
          },
        }
      : {}),
    rateLimit: buildBetterAuthRateLimitOptions({
      deploymentMode: config.deploymentMode,
      deploymentExposure: config.deploymentExposure,
      override: process.env.PAPERCLIP_AUTH_RATE_LIMIT_ENABLED,
    }),
    advanced: buildBetterAuthAdvancedOptions({ disableSecureCookies }),
    // Registered only for a managed workspace instance: the plugin is what makes
    // `Open workspace` password-independent, and a control-plane instance that
    // was never handed a workspace key must not expose the exchange at all.
    ...(resolveWorkspaceHandoffIdentity(config)
      ? {
          plugins: [
            ...plugins,
            workspaceLoginHandoffPlugin({
              db,
              // Re-resolved per exchange so a hot restart cannot keep validating
              // against an origin the control plane has since republished.
              resolveExpectedIdentity: () =>
                resolveWorkspaceHandoffIdentity(config) ?? {
                  key: null,
                  instanceId: null,
                  executionWorkspaceId: null,
                  companyId: null,
                  origin: null,
                },
            }),
          ],
        }
      : {}),
  };

  if (!baseUrl) {
    delete authConfig.baseURL;
  }

  const defaultAuth = betterAuth(authConfig as Parameters<typeof betterAuth>[0]);
  const supportsManagedLoopbackAuth = Boolean(
    !disableSecureCookies &&
    isHttpsUrl(publicUrl) &&
    isHttpsUrl(managedRuntimePublicUrl),
  );
  if (!supportsManagedLoopbackAuth) return defaultAuth;

  // Better Auth fixes both the Secure attribute and the __Secure- name prefix
  // when an instance is created. Keep the public instance unchanged and route
  // only managed HTTP-loopback requests through a cookie-compatible instance.
  const loopbackAuth = betterAuth({
    ...authConfig,
    advanced: buildBetterAuthAdvancedOptions({ disableSecureCookies: true }),
  } as Parameters<typeof betterAuth>[0]);
  const cookieSecurityInput = {
    deploymentMode: config.deploymentMode,
    deploymentExposure: config.deploymentExposure,
    authBaseUrlMode: config.authBaseUrlMode,
    authPublicBaseUrl: config.authPublicBaseUrl,
    publicUrl,
    managedRuntimePublicUrl,
  };

  return {
    $context: Promise.all([defaultAuth.$context, loopbackAuth.$context]).then(() => undefined),
    handler: (request) => {
      const auth = shouldDisableSecureAuthCookies({
        ...cookieSecurityInput,
        requestUrl: request.url,
      }) ? loopbackAuth : defaultAuth;
      return auth.handler(request);
    },
    api: {
      getSession: (input) => {
        const auth = shouldDisableSecureAuthCookies({
          ...cookieSecurityInput,
          requestUrl: requestUrlFromHeaders(input.headers),
        }) ? loopbackAuth : defaultAuth;
        return auth.api.getSession(input);
      },
    },
  };
}

export function createBetterAuthHandler(auth: BetterAuthHandlerTarget): RequestHandler {
  const handler = toNodeHandler(auth);
  return (req, res, next) => {
    void Promise.resolve(handler(req, res)).catch(next);
  };
}

export interface BetterAuthManager {
  handler: RequestHandler;
  fetch: (request: globalThis.Request) => Promise<Response>;
  resolveSession: (req: Request) => Promise<BetterAuthSessionResult | null>;
  resolveSessionFromHeaders: (headers: Headers) => Promise<BetterAuthSessionResult | null>;
  rebuild: (ssoProviders: SsoProviderConfig[]) => Promise<void>;
}

export const SSO_DISCOVERY_BOOT_TIMEOUT_MS = 10_000;
export const SSO_DISCOVERY_READINESS_GUARD_MS = SSO_DISCOVERY_BOOT_TIMEOUT_MS + 5_000;
const SSO_RECOVERY_COOLDOWN_MS = 60_000;

export interface BetterAuthManagerOptions {
  discoveryTimeoutMs?: number;
  now?: () => number;
}

class SsoDiscoveryReadinessTimeout extends Error {}

function isDiscoveryTimeout(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const { name, code } = error as { name?: unknown; code?: unknown };
  // better-fetch propagates the fetch signal's DOMException; jose wraps its
  // remote JWKS timeout in JWKSTimeout. Match identities, not error messages.
  return name === "TimeoutError" || name === "AbortError" ||
    name === "JWKSTimeout" || code === "ERR_JWKS_TIMEOUT";
}

function isDiscoveryFailure(error: unknown): string | null {
  const message = error instanceof Error ? error.message : String(error);
  return /Provider "([^"]+)": discovery (?:returned no valid data|did not return an issuer)/.exec(message)?.[1] ?? null;
}

async function createReadyBetterAuthInstance(
  db: Db,
  config: Config,
  trustedOrigins: string[],
  timeoutMs = SSO_DISCOVERY_READINESS_GUARD_MS,
): Promise<BetterAuthInstance> {
  let providers = [...config.ssoProviders];
  const originalProviderIds = new Set(providers.map((provider) => provider.providerId));
  while (true) {
    const auth = createBetterAuthInstance(db, { ...config, ssoProviders: providers }, trustedOrigins);
    try {
      // genericOAuth performs discovery from its async plugin init. Await it
      // before the server considers auth ready so a rejected init cannot escape
      // as an unhandled promise rejection after the listener starts.
      let timeout: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          auth.$context,
          new Promise<never>((_, reject) => {
            timeout = setTimeout(() => {
              reject(new SsoDiscoveryReadinessTimeout("SSO discovery readiness timed out"));
            }, timeoutMs);
          }),
        ]);
      } finally {
        if (timeout) clearTimeout(timeout);
      }
      auth.$paperclipSsoProviderIds = [...providers]
        .filter((provider) => originalProviderIds.has(provider.providerId))
        .map((provider) => provider.providerId);
      return auth;
    } catch (error) {
      const failedProviderId = isDiscoveryFailure(error);
      const failedProviderIds = failedProviderId
        ? [failedProviderId]
        // Normally genericOAuth attributes discovery failures to a provider.
        // This guard (or an unattributed fetch/JWKS timeout) cannot identify one
        // provider, so rebuild with password auth and no SSO providers.
        : error instanceof SsoDiscoveryReadinessTimeout || isDiscoveryTimeout(error)
          ? providers.map((provider) => provider.providerId)
          : [];
      const droppedProviderIds = failedProviderIds.filter((providerId) =>
        providers.some((provider) => provider.providerId === providerId),
      );
      if (droppedProviderIds.length === 0) {
        throw error;
      }
      for (const providerId of droppedProviderIds) {
        logger.warn(
          { providerId },
          "SSO provider disabled because OIDC discovery failed",
        );
      }
      providers = providers.filter((provider) => !droppedProviderIds.includes(provider.providerId));
      // A timed out context may still reject after it is abandoned. Keep a
      // rejection handler attached even though readiness has moved on.
      void auth.$context?.catch(() => undefined);
    }
  }
}

export async function createBetterAuthManager(
  db: Db,
  config: Config,
  trustedOrigins: string[],
  options: BetterAuthManagerOptions = {},
): Promise<BetterAuthManager> {
  const timeoutMs = options.discoveryTimeoutMs ?? SSO_DISCOVERY_READINESS_GUARD_MS;
  const now = options.now ?? Date.now;
  let configuredProviders = [...config.ssoProviders];
  let installedProviders = [...config.ssoProviders];
  let generation = 0;
  let currentAuth = await createReadyBetterAuthInstance(db, config, trustedOrigins, timeoutMs);
  installedProviders = config.ssoProviders.filter((provider) =>
    currentAuth.$paperclipSsoProviderIds?.includes(provider.providerId),
  );
  let currentHandler = toNodeHandler(currentAuth);
  let recoveryPromise: Promise<void> | null = null;
  let lastRecoveryAt = Number.NEGATIVE_INFINITY;

  const rebuild = async (ssoProviders: SsoProviderConfig[]): Promise<void> => {
    const rebuildGeneration = ++generation;
    configuredProviders = [...ssoProviders];
    const updatedConfig = { ...config, ssoProviders };
    const readyAuth = await createReadyBetterAuthInstance(db, updatedConfig, trustedOrigins, timeoutMs);
    if (rebuildGeneration !== generation) return;
    currentAuth = readyAuth;
    installedProviders = ssoProviders.filter((provider) =>
      readyAuth.$paperclipSsoProviderIds?.includes(provider.providerId),
    );
    currentHandler = toNodeHandler(currentAuth);
    logger.info(
      { providers: ssoProviders.map((p) => p.providerId) },
      "Better Auth instance rebuilt with updated SSO providers",
    );
  };

  const recoverDroppedProvider = (): Promise<void> => {
    if (recoveryPromise) return recoveryPromise;
    if (now() - lastRecoveryAt < SSO_RECOVERY_COOLDOWN_MS) return Promise.resolve();
    lastRecoveryAt = now();
    const attempt = rebuild(configuredProviders);
    recoveryPromise = attempt.finally(() => {
      if (recoveryPromise === wrapped) recoveryPromise = null;
    });
    const wrapped = recoveryPromise;
    return wrapped;
  };

  const providerFromBody = (body: unknown, path: string): string | null => {
    if (!body || typeof body !== "object") return null;
    const value = body as Record<string, unknown>;
    const provider = path.endsWith("/sign-in/oauth2") ? value.providerId : value.provider;
    return typeof provider === "string" ? provider : null;
  };

  const shouldRecover = async (providerId: string | null): Promise<boolean> => {
    if (!providerId || !configuredProviders.some((provider) => provider.providerId === providerId) ||
        installedProviders.some((provider) => provider.providerId === providerId)) return false;
    await recoverDroppedProvider().catch(() => undefined);
    return installedProviders.some((provider) => provider.providerId === providerId);
  };

  const handleFetch = async (request: globalThis.Request): Promise<Response> => {
    const url = new URL(request.url);
    if (request.method === "POST" && /\/sign-in\/(?:oauth2|social)$/.test(url.pathname)) {
      let body: unknown;
      try { body = await request.clone().json(); } catch { /* Better Auth handles malformed input. */ }
      await shouldRecover(providerFromBody(body, url.pathname));
    }
    return currentAuth.handler(request);
  };

  const manager: BetterAuthManager = {
    handler: (req, res, next) => {
      const path = req.url.split("?")[0] ?? "";
      const providerId = req.method === "POST" && /\/sign-in\/(?:oauth2|social)$/.test(path)
        ? providerFromBody(req.body, path)
        : null;
      void (async () => {
        await shouldRecover(providerId);
        await currentHandler(req, res);
      })().catch(next);
    },
    fetch: handleFetch,
    resolveSession: (req) => resolveBetterAuthSession(currentAuth, req),
    resolveSessionFromHeaders: (headers) =>
      resolveBetterAuthSessionFromHeaders(currentAuth, headers),
    rebuild,
  };

  return manager;
}

export async function resolveBetterAuthSessionFromHeaders(
  auth: BetterAuthSessionResolver,
  headers: Headers,
): Promise<BetterAuthSessionResult | null> {
  const api = auth.api;
  if (!api?.getSession) return null;

  const sessionValue = await api.getSession({
    headers,
  });
  if (!sessionValue || typeof sessionValue !== "object") return null;

  const value = sessionValue as {
    session?: { id?: string; userId?: string } | null;
    user?: { id?: string; email?: string | null; name?: string | null } | null;
  };
  const session = value.session?.id && value.session.userId
    ? { id: value.session.id, userId: value.session.userId }
    : null;
  const user = value.user?.id
    ? {
        id: value.user.id,
        email: value.user.email ?? null,
        name: value.user.name ?? null,
      }
    : null;

  if (!session || !user) return null;
  return { session, user };
}

export async function resolveBetterAuthSession(
  auth: BetterAuthSessionResolver,
  req: Request,
): Promise<BetterAuthSessionResult | null> {
  return resolveBetterAuthSessionFromHeaders(auth, headersFromExpressRequest(req));
}
