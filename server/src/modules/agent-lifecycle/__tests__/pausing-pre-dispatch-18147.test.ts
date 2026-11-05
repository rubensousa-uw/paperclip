// Backport de paperclipai/paperclip#18072 (issue #18147): os casos da PR (lifecycle.test.ts@32d712f316) e a run presa do smoke (b807f9e8).
import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { agents, heartbeatRuns, heartbeatRunEvents, companies, createDb, type Db } from "@paperclipai/db";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { getEmbeddedPostgresTestSupport, startEmbeddedPostgresTestDatabase } from "../../../__tests__/helpers/embedded-postgres.js";
import { agentExecutionsHaveStopped } from "../../../services/agent-execution-stop.js";
import { createLifecycleDriver } from "../../../services/agent-lifecycle-driver.js";
import { createAgentLifecycle, configureAgentLifecycle } from "../../../services/agent-lifecycle.js";
import { LEGACY_ADAPTER_ENTERED, LEGACY_ADAPTER_ENTRY_ABANDONED } from "../../../services/run-dispatch-evidence.js";
import type { LifecycleAgent } from "../application/ports.js";

const LEGACY_EXECUTION_SETTLEMENT_KEY = "legacyExecutionSettlement";
const LEGACY_EXECUTION_SETTLEMENT_SCHEMA = "paperclip.legacy-execution-settlement.v1";

const support = await getEmbeddedPostgresTestSupport();
(support.supported ? describe : describe.skip)("backport #18072", () => {
  let database: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>>;
  let db: Db;
  let companyId: string;
  const workers: ReturnType<typeof configureAgentLifecycle>[] = [];
  beforeAll(async () => { database = await startEmbeddedPostgresTestDatabase("paperclip-bp18072-"); db = createDb(database.connectionString); }, 90_000);
  afterAll(async () => { for (const worker of workers) await worker.stop(); await database?.cleanup(); });
  beforeEach(async () => {
    for (const work of workers) await work.stop();
    companyId = randomUUID();
    await db.insert(companies).values({ id: companyId, name: "Lifecycle test", issuePrefix: `L${companyId.slice(0, 7)}` });
  });
  function worker(runHost: (agent: LifecycleAgent) => Promise<"complete" | "pending"> = async () => "complete") {
    const value = configureAgentLifecycle(db, { requiredPluginIds: async () => [], runPlugin: async () => "complete", runHost });
    workers.push(value); return value;
  }
  async function current(id: string) { return (await db.select().from(agents).where(eq(agents.id, id)))[0]!; }

  const unrecordedCancellation = (agentId: string, executionStage: string, resultJson?: Record<string, unknown>) => ({
    companyId, agentId, status: "cancelled", invocationSource: "on_demand" as const,
    runtimeMode: "legacy", executionStage, startedAt: new Date(), finishedAt: new Date(),
    resultJson: (resultJson ?? null) as never,
    runnerProfileJson: { adapterDispatch: { adapterType: "claude_local" } } as never,
  });
  const settlementReceipt = {
    [LEGACY_EXECUTION_SETTLEMENT_KEY]: {
      schema: LEGACY_EXECUTION_SETTLEMENT_SCHEMA, settledAt: new Date().toISOString(),
      controllerBootId: null, stage: "dispatching",
    },
  };
  async function readyAgent(name = "Ready") {
    return (await db.insert(agents).values({ companyId, name, status: "idle", lifecycleState: "ready" }).returning())[0]!;
  }

  it.each([
    { executionStage: "preparing", resultJson: undefined },
    { executionStage: "settled", resultJson: undefined },
    { executionStage: "dispatching", resultJson: settlementReceipt as Record<string, unknown> },
  ])("pauses after a conversation-adapter run was cancelled at stage $executionStage before its PID was recorded", async ({ executionStage, resultJson }) => {
    const agent = await readyAgent();
    const [run] = await db.insert(heartbeatRuns).values(unrecordedCancellation(agent.id, executionStage, resultJson)).returning();
    const work = worker(createLifecycleDriver(db, {} as never).runHost);
    await createAgentLifecycle(db).pauseAgent(agent.id);
    await work.process(agent.id);
    expect((await current(agent.id)).lifecycleState).toBe("paused");
    await db.insert(heartbeatRunEvents).values({ companyId, runId: run.id, agentId: agent.id, seq: 1, eventType: "adapter.invoke" });
    expect(await agentExecutionsHaveStopped(db, [agent.id])).toBe(false);
  });

  it.each(["http", "hermes_local", "claude_local"])(
    "holds the stop when a cancelled %s run recorded entering its adapter", async (adapterType) => {
      const agent = await readyAgent();
      const [run] = await db.insert(heartbeatRuns).values({
        ...unrecordedCancellation(agent.id, "preparing"),
        runnerProfileJson: { adapterDispatch: { adapterType } } as never,
      }).returning();
      await db.insert(heartbeatRunEvents).values({
        companyId, runId: run.id, agentId: agent.id, seq: 1, eventType: LEGACY_ADAPTER_ENTERED,
      });
      expect(await agentExecutionsHaveStopped(db, [agent.id])).toBe(false);
      const work = worker(createLifecycleDriver(db, {} as never).runHost);
      await createAgentLifecycle(db).pauseAgent(agent.id);
      await work.process(agent.id);
      expect((await current(agent.id)).lifecycleState).toBe("pausing");
    });

  it.each(["http", "hermes_local", "claude_local"])(
    "pauses a cancelled %s run whose adapter entry was abandoned before the adapter ran", async (adapterType) => {
      const agent = await readyAgent();
      const [run] = await db.insert(heartbeatRuns).values({
        ...unrecordedCancellation(agent.id, "preparing"),
        runnerProfileJson: { adapterDispatch: { adapterType } } as never,
      }).returning();
      await db.insert(heartbeatRunEvents).values([
        { companyId, runId: run.id, agentId: agent.id, seq: 1, eventType: LEGACY_ADAPTER_ENTERED },
        { companyId, runId: run.id, agentId: agent.id, seq: 2, eventType: LEGACY_ADAPTER_ENTRY_ABANDONED },
      ]);
      expect(await agentExecutionsHaveStopped(db, [agent.id])).toBe(true);
      const work = worker(createLifecycleDriver(db, {} as never).runHost);
      await createAgentLifecycle(db).pauseAgent(agent.id);
      await work.process(agent.id);
      expect((await current(agent.id)).lifecycleState).toBe("paused");
      await db.insert(heartbeatRunEvents).values({ companyId, runId: run.id, agentId: agent.id, seq: 3, eventType: LEGACY_ADAPTER_ENTERED });
      expect(await agentExecutionsHaveStopped(db, [agent.id])).toBe(false);
    });

  // Our shape (b807f9e8): legacy, codex_local, settled, no pid/pgid, startedAt set, executionCancellation null,
  // error_code continuation_task_ownership_changed, written BEFORE any marker existed (no events at all).
  it("admits a pre-marker codex_local run cancelled with continuation_task_ownership_changed", async () => {
    const agent = await readyAgent();
    const [run] = await db.insert(heartbeatRuns).values({
      ...unrecordedCancellation(agent.id, "settled"),
      runnerProfileJson: { adapterDispatch: { adapterType: "codex_local" } } as never,
      errorCode: "continuation_task_ownership_changed", error: "continuation_task_ownership_changed",
    }).returning();
    expect(await agentExecutionsHaveStopped(db, [agent.id])).toBe(true);
    const work = worker(createLifecycleDriver(db, {} as never).runHost);
    await createAgentLifecycle(db).pauseAgent(agent.id);
    await work.process(agent.id);
    expect((await current(agent.id)).lifecycleState).toBe("paused");
    await db.update(heartbeatRuns).set({ sessionIdAfter: "thread-x" }).where(eq(heartbeatRuns.id, run.id));
    expect(await agentExecutionsHaveStopped(db, [agent.id])).toBe(false);
  });
});
