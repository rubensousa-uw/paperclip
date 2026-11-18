const SECRET_NAME = /key|secret|token/i;
const ENVIRONMENT_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;
const PROVIDER_ONLY_KEYS: ReadonlySet<string> = new Set([
  "OPENAI_API_KEY", "CODEX_API_KEY", "PAPERCLIP_AI_PROVIDER_KEY",
  // backport: upstream spreads AGENT_OBSERVABILITY_ENV_KEYS from agent-observability.ts,
  // which this fork does not carry; the names are inlined from upstream df6b43c4d^.
  "CLAUDE_CODE_ENABLE_TELEMETRY", "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA", "ENABLE_ENHANCED_TELEMETRY_BETA",
  "OTEL_LOGS_EXPORTER", "OTEL_TRACES_EXPORTER", "OTEL_METRICS_EXPORTER", "OTEL_RESOURCE_ATTRIBUTES",
  "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_PROTOCOL", "OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TIMEOUT",
  "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
  "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
  "OTEL_EXPORTER_OTLP_LOGS_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
  "OTEL_EXPORTER_OTLP_LOGS_TIMEOUT", "OTEL_EXPORTER_OTLP_TRACES_TIMEOUT",
  "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_HEADERS", "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
  "PAPERCLIP_OBSERVABILITY_CODEX_CONFIG",
  "OTEL_LOG_USER_PROMPTS", "OTEL_LOG_ASSISTANT_RESPONSES", "OTEL_LOG_TOOL_DETAILS", "OTEL_LOG_TOOL_CONTENT", "OTEL_LOG_RAW_API_BODIES",
]);
const IDENTITY_KEYS = ["PAPERCLIP_AGENT_KEY_ID", "PAPERCLIP_AGENT_PUBLIC_KEY", "PAPERCLIP_AGENT_PRIVATE_KEY"];

/** Only resolved adapter configuration can opt a service secret into shell access.
 * The launch environment here is Paperclip-built, never ambient process.env.
 * Return names only: values must stay out of provider config and argv.
 */
export function codexShellEnvironmentKeys(
  environment: Record<string, string>,
  configuredEnvironment: Record<string, unknown>,
  hasAgentIdentity: boolean,
): string[] {
  const configuredSecrets = new Set(Object.entries(configuredEnvironment)
    .filter(([key, value]) => ENVIRONMENT_NAME.test(key) && typeof value === "string" && typeof environment[key] === "string"
      && !/^PAPERCLIP_(?:GITHUB_|RUNNER_|NATIVE_|ACPX_)/i.test(key)
      && SECRET_NAME.test(key) && !PROVIDER_ONLY_KEYS.has(key.toUpperCase()))
    .map(([key]) => key));
  return [...new Set([
    "PATH", "HOME", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "TEMP", "TMP", "CODEX_HOME",
    ...Object.keys(environment).filter(key => ENVIRONMENT_NAME.test(key) && !PROVIDER_ONLY_KEYS.has(key.toUpperCase())
      && (key === "PAPERCLIP_API_KEY" || configuredSecrets.has(key) || !SECRET_NAME.test(key))),
    ...(hasAgentIdentity ? IDENTITY_KEYS : []),
  ])].sort();
}
