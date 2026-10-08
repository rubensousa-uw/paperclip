import { randomUUID } from "node:crypto";
import { desc, eq } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  activityLog,
  agentRuntimeState,
  agents,
  agentTaskSessions,
  agentWakeupRequests,
  companies,
  companySkillVersions,
  companySkills,
  createDb,
  environmentLeases,
  environments,
  heartbeatRunEvents,
  heartbeatRuns,
  issues,
} from "@paperclipai/db";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";

const mockTelemetryClient = vi.hoisted(() => ({ track: vi.fn() }));
vi.mock("../telemetry.js", () => ({ getTelemetryClient: () => mockTelemetryClient }));

// The gate cases below are about what the control plane does with a run it has
// already terminalized, so no case may depend on a real provider starting. The
// stub is the same shape the neighbouring stale-queue suite uses, and the
// `execute` call count is what proves a case never got past its gate.
const mockAdapterExecute = vi.hoisted(() =>
  vi.fn(async (_context: { runId?: string }) => ({
    exitCode: 0,
    signal: null,
    timedOut: false,
    errorMessage: null,
    summary: "Orphan-lease-release test run.",
    provider: "test",
    model: "test-model",
  })),
);

vi.mock("../adapters/index.ts", async () => {
  const actual = await vi.importActual<typeof import("../adapters/index.ts")>(
    "../adapters/index.ts",
  );
  return {
    ...actual,
    getServerAdapter: vi.fn(() => ({
      supportsLocalAgentJwt: false,
      execute: mockAdapterExecute,
    })),
  };
});

import { heartbeatService } from "../services/heartbeat.ts";
import { drainHeartbeatRunsToQuiescence } from "./helpers/drain-heartbeat-runs.js";
import { getExecutionBlocker } from "../services/execution-blocker.ts";

const embeddedPostgresSupport = await getEmbeddedPostgresTestSupport();
const describeEmbeddedPostgres = embeddedPostgresSupport.supported ? describe : describe.skip;

if (!embeddedPostgresSupport.supported) {
  console.warn(
    `Skipping embedded Postgres orphan-lease-release tests on this host: ${
      embeddedPostgresSupport.reason ?? "unsupported environment"
    }`,
  );
}

// Every fixture id and time here is generated, so nothing depends on a
// neighbouring suite's rows. The pid is above the system maximum: that is the
// repo's own convention for "this run's process is provably gone", which is
// what lets the backstop's process-death authority terminalize the run.
const DEAD_PID = 2_000_000_000;

describeEmbeddedPostgres("recovery backstop releases the environment lease", () => {
  let db!: ReturnType<typeof createDb>;
  let tempDb: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | null = null;
  // Every fixture id is generated, so each test registers what it created and
  // the suite deletes exactly that. A wake provisions company skills and writes
  // activity rows for the company it targets, so cleanup by company id is the
  // only shape that does not have to guess every table a wake can touch.
  const seeded: { companyIds: string[]; environmentIds: string[] } = {
    companyIds: [],
    environmentIds: [],
  };
  // The one place a case can interleave with the production code at the
  // checkout gate: the service calls this immediately before checking the issue
  // out, which is the only way to make that checkout lose a race
  // deterministically. It is the seam the neighbouring stale-queue suite uses
  // for the same gate, and the same seam keeps this case from depending on
  // timing.
  let beforeContinuationCheckout:
    | ((input: { runId: string; issueId: string }) => Promise<void>)
    | null = null;

  function heartbeat() {
    return heartbeatService(db, {
      runtimeEnv: { ...process.env, PAPERCLIP_IN_WORKTREE: "false" },
      beforeResolvedInteractionContinuationDispatchCheck: async (input) => {
        await beforeContinuationCheckout?.(input);
      },
    });
  }

  const executeCallsFor = (runId: string) =>
    mockAdapterExecute.mock.calls.filter(
      ([context]) => (context as { runId?: string } | undefined)?.runId === runId,
    ).length;

  beforeAll(async () => {
    tempDb = await startEmbeddedPostgresTestDatabase("paperclip-orphan-lease-release-");
    db = createDb(tempDb.connectionString);
  }, 60_000);

  afterEach(async () => {
    mockTelemetryClient.track.mockClear();
    mockAdapterExecute.mockClear();
    beforeContinuationCheckout = null;
    await drainHeartbeatRunsToQuiescence(db, heartbeat()).catch(() => undefined);
    // A wake provisions company skills and writes activity for the company it
    // targets, so this suite cleans up by company id rather than by guessing
    // every table a wake can touch. Fixture ids are generated, so each test
    // owns exactly the rows it created.
    for (const environmentId of seeded.environmentIds.splice(0)) {
      await db.delete(environmentLeases).where(eq(environmentLeases.environmentId, environmentId));
      await db.delete(environments).where(eq(environments.id, environmentId));
    }
    for (const companyId of seeded.companyIds.splice(0)) {
      await db
        .delete(environmentLeases)
        .where(eq(environmentLeases.companyId, companyId));
      // A dispatched run opens a task session that points back at the run, so
      // the session rows have to go before the runs do.
      await db
        .delete(agentTaskSessions)
        .where(eq(agentTaskSessions.companyId, companyId));
      await db.delete(heartbeatRunEvents).where(
        eq(heartbeatRunEvents.companyId, companyId),
      );
      await db.delete(activityLog).where(eq(activityLog.companyId, companyId));
      await db.delete(issues).where(eq(issues.companyId, companyId));
      await db.delete(heartbeatRuns).where(eq(heartbeatRuns.companyId, companyId));
      await db.delete(agentWakeupRequests).where(
        eq(agentWakeupRequests.companyId, companyId),
      );
      await db.delete(agentRuntimeState).where(
        eq(agentRuntimeState.companyId, companyId),
      );
      await db.delete(activityLog).where(eq(activityLog.companyId, companyId));
      await db
        .delete(companySkillVersions)
        .where(eq(companySkillVersions.companyId, companyId));
      await db.delete(companySkills).where(eq(companySkills.companyId, companyId));
      await db.delete(agents).where(eq(agents.companyId, companyId));
      await db.delete(companies).where(eq(companies.id, companyId));
    }
  });

  afterAll(async () => {
    await tempDb?.cleanup();
  });

  /**
   * @param lockRun "orphan" locks the issue on a dead run (the measured shape:
   *   the service died with the run in flight). "live" locks it on a run whose
   *   process really is alive, which is the control-negative shape.
   * @param orphanIsLastRun seeds no second live run, so the orphaned run is the
   *   agent's only run. That is the `maxConcurrentRuns: 1` shape of #14752, and
   *   the only shape in which the agent must actually leave `running`.
   */
  async function seed(input?: {
    lockRun?: "orphan" | "live";
    orphanIsLastRun?: boolean;
    agentStatus?: string;
  }) {
    const companyId = randomUUID();
    const agentId = randomUUID();
    const issueId = randomUUID();
    const orphanRunId = randomUUID();
    const liveRunId = randomUUID();

    await db.insert(companies).values({
      id: companyId,
      name: "Paperclip",
      issuePrefix: `T${companyId.replace(/-/g, "").slice(0, 6).toUpperCase()}`,
      requireBoardApprovalForNewAgents: false,
      // A dispatched run needs a responsible user; the cases that admit a wake
      // after a terminal path are exactly the cases that dispatch one.
      defaultResponsibleUserId: "responsible-user",
    });
    seeded.companyIds.push(companyId);
    await db.insert(agents).values({
      id: agentId,
      companyId,
      name: "Coder",
      role: "engineer",
      // The measured #14752 shape: the backstop ends the run but leaves the
      // agent in `running`, so a maxConcurrentRuns:1 agent never frees a slot.
      status: input?.agentStatus ?? "running",
      adapterType: "codex_local",
      adapterConfig: {},
      runtimeConfig: {},
      permissions: {},
    });
    await db.insert(heartbeatRuns).values([
      {
        id: orphanRunId,
        companyId,
        agentId,
        status: "running",
        runtimeMode: "legacy",
        invocationSource: "automation",
        processPid: DEAD_PID,
        processStartedAt: new Date("2026-10-01T08:00:00.000Z"),
        contextSnapshot: { issueId, wakeReason: "issue_commented" },
        startedAt: new Date("2026-10-01T08:00:00.000Z"),
        // The claim-time record that makes this run a conversation run, which is
        // what `getConversationOwnershipBlocker` considers for the lease hold.
        runnerProfileJson: { adapterDispatch: { adapterType: "codex_local" } },
      },
      // A second run of the same agent whose process really is alive: this
      // control-plane host's own pid, started now so the identity check agrees.
      // Omitted when the orphaned run has to be the agent's last one.
      ...(input?.orphanIsLastRun
        ? []
        : [
            {
              id: liveRunId,
              companyId,
              agentId,
              status: "running" as const,
              runtimeMode: "legacy" as const,
              invocationSource: "automation",
              processPid: process.pid,
              processStartedAt: new Date(),
              contextSnapshot: { issueId },
              startedAt: new Date(),
              runnerProfileJson: { adapterDispatch: { adapterType: "codex_local" } },
            },
          ]),
    ]);

    const lockRunId =
      input?.lockRun === "live" && !input?.orphanIsLastRun ? liveRunId : orphanRunId;
    await db.insert(issues).values({
      id: issueId,
      companyId,
      title: "Issue whose execution run outlived its service",
      status: "in_progress",
      priority: "high",
      assigneeAgentId: agentId,
      executionRunId: lockRunId,
    });

    const [environment] = await db
      .insert(environments)
      .values({ name: `Env ${orphanRunId}`, driver: "sandbox" })
      .returning();
    seeded.environmentIds.push(environment.id);
    const [orphanLease] = await db
      .insert(environmentLeases)
      .values({
        companyId,
        issueId,
        environmentId: environment.id,
        heartbeatRunId: orphanRunId,
        status: "active",
        leasePolicy: "ephemeral",
      })
      .returning();
    const [liveLease] = await db
      .insert(environments)
      .values({ name: `Env ${liveRunId}`, driver: "sandbox" })
      .returning();
    seeded.environmentIds.push(liveLease.id);
    const [liveLeaseRow] = input?.orphanIsLastRun
      ? [null]
      : await db
          .insert(environmentLeases)
          .values({
            companyId,
            issueId,
            environmentId: liveLease.id,
            heartbeatRunId: liveRunId,
            status: "active",
            leasePolicy: "ephemeral",
          })
          .returning();

    return {
      companyId,
      agentId,
      issueId,
      orphanRunId,
      liveRunId,
      orphanLeaseId: orphanLease.id,
      liveLeaseId: liveLeaseRow?.id ?? null,
    };
  }

  async function leaseRow(leaseId: string) {
    const [row] = await db
      .select()
      .from(environmentLeases)
      .where(eq(environmentLeases.id, leaseId));
    return row;
  }

  async function agentStatusOf(agentId: string) {
    const [row] = await db
      .select({ status: agents.status })
      .from(agents)
      .where(eq(agents.id, agentId));
    return row?.status ?? null;
  }

  async function runStatusOf(runId: string) {
    const [row] = await db
      .select({ status: heartbeatRuns.status, errorCode: heartbeatRuns.errorCode })
      .from(heartbeatRuns)
      .where(eq(heartbeatRuns.id, runId));
    return row ?? null;
  }

  async function issueLockOf(issueId: string) {
    const [row] = await db
      .select({ executionRunId: issues.executionRunId })
      .from(issues)
      .where(eq(issues.id, issueId));
    return row?.executionRunId ?? null;
  }

  // The production backstop: `heartbeatService` builds the recovery service
  // with its real dependencies, so this exercises the wiring and not a stub.
  async function runBackstop() {
    return heartbeat().sweepStaleIssueLocks();
  }

  /**
   * Admits a wake for `agentId` on `issueId` through the production
   * `wakeup` entry point and reports what the control plane did with it.
   *
   * A refused wake is the whole symptom: `enqueueWakeup` returns `null` and the
   * receipt is `skipped` (the `execution_owner_active` branch), and nothing
   * retries it. So this returns the three things a caller needs to tell
   * "admitted" from "refused forever" — the run it created, the receipt
   * status, and whether the issue still has a blocker naming the old run.
   */
  async function admitWake(input: {
    companyId: string;
    agentId: string;
    issueId: string;
    reason: string;
    requestedByActorType?: "user" | "agent";
    requestedByActorId?: string;
    requestedByAgentId?: string;
  }) {
    const run = await heartbeat().wakeup(input.agentId, {
      source: "automation",
      triggerDetail: "system",
      reason: input.reason,
      payload: { issueId: input.issueId },
      contextSnapshot: {
        issueId: input.issueId,
        taskId: input.issueId,
        wakeReason: input.reason,
      },
      requestedByActorType: input.requestedByActorType ?? "user",
      requestedByActorId: input.requestedByActorId ?? "local-board",
      ...(input.requestedByAgentId
        ? { requestedByAgentId: input.requestedByAgentId }
        : {}),
    });
    const [receipt] = await db
      .select({ status: agentWakeupRequests.status, error: agentWakeupRequests.error })
      .from(agentWakeupRequests)
      .where(eq(agentWakeupRequests.companyId, input.companyId))
      .orderBy(desc(agentWakeupRequests.requestedAt))
      .limit(1);
    return {
      run,
      admitted: run !== null,
      receiptStatus: receipt?.status ?? null,
      receiptError: receipt?.error ?? null,
      blocker: await getExecutionBlocker(db, input.companyId, input.issueId),
    };
  }

  // Case 1 (the #14672 regression): the backstop terminalizes a run whose
  // process is gone. Without the fix the lease row stays `active`, so once the
  // run is terminal `getConversationOwnershipBlocker` names it as the issue's
  // owner with `recoveryActionId: null` and every later wake is deferred. The
  // admission assertion is the point of the case: releasing the lease row is
  // not the outcome, a wake being admitted again is.
  it("releases the lease and admits a wake after the backstop terminalizes a dead run", async () => {
    const f = await seed();

    await runBackstop();

    expect(await runStatusOf(f.orphanRunId)).toMatchObject({
      status: "interrupted",
      errorCode: "orphaned_running_run",
    });

    const lease = await leaseRow(f.orphanLeaseId);
    expect(lease?.status).not.toBe("active");
    expect(lease?.releasedAt).not.toBeNull();
    expect(await issueLockOf(f.issueId)).toBeNull();
    expect(await getExecutionBlocker(db, f.companyId, f.issueId)).toBeNull();

    // A real new run is admitted, and no blocker names the dead run any more.
    const admitted = await admitWake({
      companyId: f.companyId,
      agentId: f.agentId,
      issueId: f.issueId,
      reason: "issue_commented",
    });
    expect(admitted.admitted, `wake refused: ${admitted.receiptError ?? "no receipt"}`).toBe(true);
    expect(admitted.receiptStatus).not.toBe("skipped");
    expect(admitted.blocker).toBeNull();
  });

  // Case 2 (#14752, positive, its own hunk): the orphaned run is the agent's
  // only run — the `maxConcurrentRuns: 1` shape the upstream issue is about.
  // The backstop has to take the agent off `running`, or its single slot stays
  // taken by a run that no longer exists. This is the case that proves the
  // finalization hunk does something, as opposed to being present.
  it("takes the agent off running when the orphaned run was its last one", async () => {
    const f = await seed({ orphanIsLastRun: true });

    await runBackstop();

    expect(await runStatusOf(f.orphanRunId)).toMatchObject({
      status: "interrupted",
      errorCode: "orphaned_running_run",
    });
    expect((await leaseRow(f.orphanLeaseId))?.status).not.toBe("active");
    // No other run of this agent exists, so the shutdown's own status is what
    // the agent must now carry.
    expect(await agentStatusOf(f.agentId)).not.toBe("running");
  });

  // Case 3 (#14752, control): same backstop call, but the agent still has
  // another live run. Its state must not move, and the other run's lease must
  // not be touched.
  it("leaves the agent in running while another of its runs is still alive", async () => {
    const f = await seed();

    await runBackstop();

    expect((await leaseRow(f.orphanLeaseId))?.status).not.toBe("active");
    expect(await agentStatusOf(f.agentId)).toBe("running");
    expect(await runStatusOf(f.liveRunId)).toMatchObject({ status: "running" });
    expect((await leaseRow(f.liveLeaseId!))?.status).toBe("active");
  });

  // Case 4, control negative: an issue whose lock points at a run whose process
  // is alive keeps its lease, its lock and its run. This one stays green with the
  // patch reverted, so a red here means the gate measures the wrong thing.
  it("keeps lease, lock and run intact while the run is still alive", async () => {
    const f = await seed({ lockRun: "live" });

    await runBackstop();

    expect(await runStatusOf(f.liveRunId)).toMatchObject({ status: "running" });
    expect((await leaseRow(f.liveLeaseId!))?.status).toBe("active");
    expect(await issueLockOf(f.issueId)).toBe(f.liveRunId);
    // A live run is not a blocker: nothing about it defers a wake.
    expect(await getExecutionBlocker(db, f.companyId, f.issueId)).toBeNull();
  });

  // Case 5: the `lock_released_on_reassignment` cancellation. The measured
  // baseline (2026-10-01, 12:20 Lisboa) had an issue in_review whose
  // `executionRunId` pointed at a `cancelled` run with this code, and whose
  // wake was refused with `execution_reconciliation_required`. The case ends
  // with a wake that has to be admitted, not with the lease row's status.
  it("releases the lease of a run cancelled by lock_released_on_reassignment", async () => {
    const companyId = randomUUID();
    const coderAgentId = randomUUID();
    const reviewerAgentId = randomUUID();
    const issueId = randomUUID();
    const holderRunId = randomUUID();

    await db.insert(companies).values({
      id: companyId,
      name: "Paperclip",
      issuePrefix: `T${companyId.replace(/-/g, "").slice(0, 6).toUpperCase()}`,
      requireBoardApprovalForNewAgents: false,
      defaultResponsibleUserId: "responsible-user",
    });
    seeded.companyIds.push(companyId);
    await db.insert(agents).values([
      {
        id: coderAgentId,
        companyId,
        name: "Coder",
        role: "engineer",
        status: "idle",
        adapterType: "process",
        adapterConfig: {},
        runtimeConfig: {},
        permissions: {},
      },
      {
        id: reviewerAgentId,
        companyId,
        name: "Reviewer",
        role: "engineer",
        status: "idle",
        adapterType: "process",
        adapterConfig: {},
        runtimeConfig: {},
        permissions: {},
      },
    ]);
    await db.insert(heartbeatRuns).values({
      id: holderRunId,
      companyId,
      agentId: coderAgentId,
      invocationSource: "assignment",
      triggerDetail: "system",
      status: "queued",
      contextSnapshot: { issueId, taskId: issueId, wakeReason: "issue_assigned" },
    });
    await db.insert(issues).values({
      id: issueId,
      companyId,
      title: "Reassigned while a queued run held the lock",
      status: "in_review",
      priority: "medium",
      assigneeAgentId: reviewerAgentId,
      executionRunId: holderRunId,
      executionAgentNameKey: "coder",
      executionLockedAt: new Date(),
      issueNumber: 1,
      identifier: `T${companyId.replace(/-/g, "").slice(0, 4)}-1`,
    });
    const [environment] = await db
      .insert(environments)
      .values({ name: `Env ${holderRunId}`, driver: "sandbox" })
      .returning();
    seeded.environmentIds.push(environment.id);
    const [lease] = await db
      .insert(environmentLeases)
      .values({
        companyId,
        issueId,
        environmentId: environment.id,
        heartbeatRunId: holderRunId,
        status: "active",
        leasePolicy: "ephemeral",
      })
      .returning();

    // The new assignee wakes: the sweep finds a queued holder that no longer
    // matches the issue's assignee and cancels it.
    await heartbeat().wakeup(reviewerAgentId, {
      source: "automation",
      triggerDetail: "system",
      reason: "issue_assigned",
      payload: { issueId },
      contextSnapshot: { issueId, taskId: issueId, wakeReason: "issue_assigned" },
      requestedByActorType: "user",
      requestedByActorId: "local-board",
    });

    expect(await runStatusOf(holderRunId)).toMatchObject({
      status: "cancelled",
      errorCode: "lock_released_on_reassignment",
    });
    expect((await leaseRow(lease.id))?.status).not.toBe("active");

    // The promotion inside that wake is not the end of the story: a later wake
    // has to be admitted too, which is the difference between a released lease
    // and an issue that accepts work again.
    const after = await admitWake({
      companyId,
      agentId: reviewerAgentId,
      issueId,
      reason: "issue_commented",
    });
    expect(after.admitted, `wake refused: ${after.receiptError ?? "no receipt"}`).toBe(true);
    expect(after.blocker).toBeNull();
  });

  // Case 6: the `issue_continuation_waiting_on_review` cancellation, the second
  // measured baseline shape. A continuation run that already holds a
  // reusable environment lease is queued again; the gate finds the issue parked
  // for review and cancels the run before it starts. That cancellation used to
  // leave the lease `active` on a terminal run, which is exactly what kept the
  // issue's later wakes refused with `execution_reconciliation_required`.
  it("releases the lease of a run cancelled by issue_continuation_waiting_on_review", async () => {
    const companyId = randomUUID();
    const agentId = randomUUID();
    const issueId = randomUUID();
    const queuedRunId = randomUUID();

    await db.insert(companies).values({
      id: companyId,
      name: "Paperclip",
      issuePrefix: `T${companyId.replace(/-/g, "").slice(0, 6).toUpperCase()}`,
      requireBoardApprovalForNewAgents: false,
      defaultResponsibleUserId: "responsible-user",
    });
    seeded.companyIds.push(companyId);
    await db.insert(agents).values({
      id: agentId,
      companyId,
      name: "Coder",
      role: "engineer",
      status: "idle",
      adapterType: "codex_local",
      adapterConfig: {},
      runtimeConfig: {},
      permissions: {},
    });
    // The queued continuation run. Its context names the parked continuation
    // summary, which is what makes the gate classify it as a deliberate wait.
    await db.insert(heartbeatRuns).values({
      id: queuedRunId,
      companyId,
      agentId,
      invocationSource: "automation",
      triggerDetail: "system",
      status: "queued",
      contextSnapshot: {
        issueId,
        wakeReason: "issue_continuation_needed",
        paperclipContinuationSummary: {
          body: "## Next action\n\nWaiting for reviewer feedback before continuing.",
        },
      },
      runnerProfileJson: { adapterDispatch: { adapterType: "codex_local" } },
    });
    await db.insert(issues).values({
      id: issueId,
      companyId,
      title: "Continuation parked for review",
      status: "in_progress",
      priority: "high",
      assigneeAgentId: agentId,
      executionRunId: queuedRunId,
      issueNumber: 1,
      identifier: `T${companyId.replace(/-/g, "").slice(0, 4)}-1`,
    });
    const [environment] = await db
      .insert(environments)
      .values({ name: `Env ${queuedRunId}`, driver: "sandbox" })
      .returning();
    seeded.environmentIds.push(environment.id);
    // A queued run can already hold a lease: the reusable-lease path keeps a
    // warm sandbox attached to the run across the queue boundary.
    const [lease] = await db
      .insert(environmentLeases)
      .values({
        companyId,
        issueId,
        environmentId: environment.id,
        heartbeatRunId: queuedRunId,
        status: "active",
        leasePolicy: "ephemeral",
      })
      .returning();

    // The agent claims the queue. The gate cancels this run as a deliberate wait.
    // The production path: a wake enqueues nothing new here, so it reaches the
    // queue claim, where the gate reads the parked continuation summary and
    // cancels the run before a provider starts.
    await heartbeat().wakeup(agentId, {
      source: "automation",
      triggerDetail: "system",
      reason: "issue_continuation_needed",
      payload: { issueId },
      contextSnapshot: { issueId, wakeReason: "issue_continuation_needed" },
      requestedByActorType: "agent",
      requestedByAgentId: agentId,
    });
    await drainHeartbeatRunsToQuiescence(db, heartbeat());

    expect(await runStatusOf(queuedRunId)).toMatchObject({
      status: "cancelled",
      errorCode: "issue_continuation_waiting_on_review",
    });
    expect((await leaseRow(lease.id))?.status).not.toBe("active");

    const after = await admitWake({
      companyId,
      agentId,
      issueId,
      reason: "issue_commented",
      requestedByActorType: "agent",
      requestedByAgentId: agentId,
    });
    expect(after.admitted, `wake refused: ${after.receiptError ?? "no receipt"}`).toBe(true);
    expect(after.blocker).toBeNull();
  });

  // Case 7, the reproduction the human evidence names (2026-10-01, 16:40
  // Lisboa, tag v2026.916.0): an agent reassigns the issue it is working on
  // from inside its own run. `routes/issues.ts` cancels that run
  // (`cancelRunInternal`) and then wakes the new owner; the cancellation used
  // to leave the lease `active`, so in the window before `executeRun`'s
  // `finally` — which a cancellation from inside the run never reaches in time
  // — `getExecutionBlocker` answered `execution_owner_active` and the new
  // owner's `issue_assigned` wake was `skipped` and never retried. Measured on
  // UMA-1644, UMA-1645 and UMA-1573.
  it("admits the new owner's wake when the agent reassigns from inside its own run", async () => {
    const companyId = randomUUID();
    const coderAgentId = randomUUID();
    const reviewerAgentId = randomUUID();
    const issueId = randomUUID();
    const runId = randomUUID();

    await db.insert(companies).values({
      id: companyId,
      name: "Paperclip",
      issuePrefix: `T${companyId.replace(/-/g, "").slice(0, 6).toUpperCase()}`,
      requireBoardApprovalForNewAgents: false,
      defaultResponsibleUserId: "responsible-user",
    });
    seeded.companyIds.push(companyId);
    await db.insert(agents).values([
      {
        id: coderAgentId,
        companyId,
        name: "Coder",
        role: "engineer",
        status: "running",
        adapterType: "codex_local",
        adapterConfig: {},
        runtimeConfig: {},
        permissions: {},
      },
      {
        id: reviewerAgentId,
        companyId,
        name: "Reviewer",
        role: "engineer",
        status: "idle",
        adapterType: "codex_local",
        adapterConfig: {},
        runtimeConfig: {},
        permissions: {},
      },
    ]);
    // The run doing the reassignment: a real conversation run of the coder,
    // holding a lease and the issue lock. Its provider process is provably gone
    // (`DEAD_PID`), which is deliberate and is what makes this case measure the
    // lease and nothing else. `getConversationOwnershipBlocker` holds an issue
    // for a terminal run when the process is still alive *or* the lease is
    // still `active`; a live pid would keep the issue blocked for a different,
    // correct reason and the case would pass whether or not the fix exists.
    // With the process gone, the lease is the only thing that can block the new
    // owner — and nothing but the cancellation can release it, because a
    // cancellation from inside a run never reaches `executeRun`'s `finally` in
    // time to matter.
    await db.insert(heartbeatRuns).values({
      id: runId,
      companyId,
      agentId: coderAgentId,
      invocationSource: "automation",
      triggerDetail: "system",
      status: "running",
      runtimeMode: "legacy",
      processPid: DEAD_PID,
      processStartedAt: new Date("2026-10-01T08:00:00.000Z"),
      contextSnapshot: { issueId, taskId: issueId, wakeReason: "issue_assigned" },
      startedAt: new Date("2026-10-01T08:00:00.000Z"),
      // The provider acknowledged the stop, which is the production shape of a
      // reassignment issued from inside the run: `cancelRunInternal` writes this
      // once the abort lands. It matters because an acknowledged cancellation is
      // what retires the run's *recovery action* hold. With that hold retired,
      // the lease is the only thing left that can keep the issue blocked, so
      // this case measures the lease release and nothing else. Without it the
      // case would still pass with the patch reverted, on the strength of a
      // different mechanism.
      resultJson: {
        executionCancellation: {
          state: "acknowledged",
          acknowledgedAt: "2026-10-01T08:05:00.000Z",
        },
      },
      runnerProfileJson: { adapterDispatch: { adapterType: "codex_local" } },
    });
    await db.insert(issues).values({
      id: issueId,
      companyId,
      title: "Reassigned by the agent that owns the run",
      status: "in_progress",
      priority: "high",
      assigneeAgentId: coderAgentId,
      executionRunId: runId,
      executionAgentNameKey: "coder",
      executionLockedAt: new Date(),
      issueNumber: 1,
      identifier: `T${companyId.replace(/-/g, "").slice(0, 4)}-1`,
    });
    const [environment] = await db
      .insert(environments)
      .values({ name: `Env ${runId}`, driver: "sandbox" })
      .returning();
    seeded.environmentIds.push(environment.id);
    const [lease] = await db
      .insert(environmentLeases)
      .values({
        companyId,
        issueId,
        environmentId: environment.id,
        heartbeatRunId: runId,
        status: "active",
        leasePolicy: "ephemeral",
      })
      .returning();

    // Step 1 — the reassignment, as the route performs it: cancel the active
    // run, then hand the issue to the new owner.
    const cancelled = await heartbeat().cancelRun(
      runId,
      "Cancelled before issue reassignment",
      {
        errorCode: "issue_reassigned",
        resultJson: { reassignmentStopConfirmed: true },
        eventMessage: "run cancelled before issue reassignment",
        eventPayload: { issueId },
      },
    );
    expect(cancelled?.status).toBe("cancelled");
    await db
      .update(issues)
      .set({ assigneeAgentId: reviewerAgentId })
      .where(eq(issues.id, issueId));

    // The lease is gone in the same step, while the run's process is still up.
    expect((await leaseRow(lease.id))?.status).not.toBe("active");
    expect(await getExecutionBlocker(db, companyId, issueId)).toBeNull();

    // Step 2 — the new owner's wake, which the route issues right after.
    const wake = await admitWake({
      companyId,
      agentId: reviewerAgentId,
      issueId,
      reason: "issue_assigned",
    });
    expect(wake.admitted, `wake refused: ${wake.receiptError ?? "no receipt"}`).toBe(true);
    expect(wake.receiptStatus).not.toBe("skipped");
    expect(wake.run?.agentId).toBe(reviewerAgentId);
    expect(wake.blocker).toBeNull();
  });

  // Case 8: the checkout staleness gate — and a measurement, not a gate. This is
  // the second caller of the staleness gate the queue claim uses. A resolved
  // interaction continuation is claimed as `running` and then loses the issue
  // between claim and checkout, so the checkout raises a conflict and
  // `executeRun` terminalizes the run.
  //
  // This case is green with the patch reverted, and that is the finding. A
  // release trace taken on 2026-10-01 showed the teardown's own
  // `releaseEnvironmentLeasesForRun` running for this exact run and leaving the
  // lease `expired` with a `releasedAt`, so the gate at checkout is already
  // covered: it lives inside `executeRun`, and `executeRun`'s teardown releases
  // the lease of any run it terminalized. An earlier revision of this
  // correction carried a release hunk here; measuring it showed the hunk
  // changed no observable state, so it was removed rather than shipped. The case
  // stays because it is what pins that measurement: if a future change breaks
  // the teardown's release, this goes red.
  //
  // The adapter call count is asserted so what the case exercises is the gate
  // and not a dispatch that happened to fail.
  it("covers the checkout staleness gate, which the native teardown already releases", async () => {
    const companyId = randomUUID();
    const agentId = randomUUID();
    const replacementAgentId = randomUUID();
    const issueId = randomUUID();
    const runId = randomUUID();

    await db.insert(companies).values({
      id: companyId,
      name: "Paperclip",
      issuePrefix: `T${companyId.replace(/-/g, "").slice(0, 6).toUpperCase()}`,
      requireBoardApprovalForNewAgents: false,
      defaultResponsibleUserId: "responsible-user",
    });
    seeded.companyIds.push(companyId);
    await db.insert(agents).values([
      {
        id: agentId,
        companyId,
        name: "Coder",
        role: "engineer",
        status: "active",
        adapterType: "codex_local",
        adapterConfig: {},
        runtimeConfig: { heartbeat: { wakeOnDemand: true, maxConcurrentRuns: 1 } },
        permissions: {},
      },
      {
        id: replacementAgentId,
        companyId,
        name: "ReplacementCoder",
        role: "engineer",
        status: "active",
        adapterType: "codex_local",
        adapterConfig: {},
        runtimeConfig: { heartbeat: { wakeOnDemand: true, maxConcurrentRuns: 1 } },
        permissions: {},
      },
    ]);
    await db.insert(issues).values({
      id: issueId,
      companyId,
      title: "Continuation reassigned between claim and checkout",
      status: "in_progress",
      priority: "medium",
      assigneeAgentId: agentId,
      issueNumber: 1,
      identifier: `T${companyId.replace(/-/g, "").slice(0, 4)}-1`,
    });
    // A resolved interaction continuation: this is the context shape the
    // checkout gate is written for, and the one that reaches the hunk. The run
    // is an `assignment` run, which is what the checkout-gate case in the
    // neighbouring stale-queue suite uses: the chat-control recovery gate only
    // fences `automation` invocations, and this case is about the checkout gate.
    await db.insert(heartbeatRuns).values({
      id: runId,
      companyId,
      agentId,
      invocationSource: "assignment",
      triggerDetail: "system",
      status: "queued",
      // `legacy`, because that is the runtime mode
      // `getConversationOwnershipBlocker` filters on: a terminal run that is not
      // a legacy conversation run is never named as an issue's owner, so an
      // `active` lease on it would block nothing and this case would pass with
      // the patch reverted.
      runtimeMode: "legacy",
      contextSnapshot: {
        issueId,
        taskId: issueId,
        wakeReason: "issue_commented",
        interactionId: randomUUID(),
        interactionKind: "connection_intent",
        interactionStatus: "accepted",
        interactionResolvedAt: "2026-10-01T08:00:00.000Z",
        mutation: "interaction",
        source: "connection_intent.resolved",
      },
      runnerProfileJson: { adapterDispatch: { adapterType: "codex_local" } },
    });
    const [environment] = await db
      .insert(environments)
      .values({ name: `Env ${runId}`, driver: "sandbox" })
      .returning();
    seeded.environmentIds.push(environment.id);
    // A continuation run keeps its warm sandbox attached across the queue
    // boundary, so a `queued` run can legitimately hold an `active` lease. That
    // is the lease the gate has to release.
    const [lease] = await db
      .insert(environmentLeases)
      .values({
        companyId,
        issueId,
        environmentId: environment.id,
        heartbeatRunId: runId,
        status: "active",
        leasePolicy: "ephemeral",
      })
      .returning();

    // The race the gate exists for: the issue changes hands after the run was
    // claimed, so the checkout cannot win.
    beforeContinuationCheckout = async ({ runId: guardedRunId, issueId: guardedIssueId }) => {
      expect(guardedRunId).toBe(runId);
      expect(guardedIssueId).toBe(issueId);
      await db
        .update(issues)
        .set({ assigneeAgentId: replacementAgentId, updatedAt: new Date() })
        .where(eq(issues.id, issueId));
    };

    await heartbeat().resumeQueuedRuns();
    await drainHeartbeatRunsToQuiescence(db, heartbeat());

    expect(await runStatusOf(runId)).toMatchObject({
      status: "cancelled",
      errorCode: "issue_assignee_changed",
    });

    // The gate fired before dispatch, so no provider was ever started.
    expect(executeCallsFor(runId)).toBe(0);
    expect((await leaseRow(lease.id))?.status).not.toBe("active");
    expect(await getExecutionBlocker(db, companyId, issueId)).toBeNull();

    const after = await admitWake({
      companyId,
      agentId: replacementAgentId,
      issueId,
      reason: "issue_assigned",
    });
    expect(after.admitted, `wake refused: ${after.receiptError ?? "no receipt"}`).toBe(true);
    expect(after.blocker).toBeNull();
  });
});
