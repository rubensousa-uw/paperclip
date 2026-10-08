import { randomUUID } from "node:crypto";
import express from "express";
import request from "supertest";
import { and, eq, inArray, sql } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  agentTaskSessions,
  agentWakeupRequests,
  agents,
  authUsers,
  companyMemberships,
  companies,
  createDb,
  decisions,
  heartbeatRuns,
  issueComments,
  issueRecoveryActions,
  issues,
} from "@paperclipai/db";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";
import { agentService } from "../services/agents.ts";
import { approvalService } from "../services/approvals.ts";
import { drainHeartbeatRunsToQuiescence } from "./helpers/drain-heartbeat-runs.js";
import { heartbeatService } from "../services/heartbeat.ts";
import { issueService } from "../services/issues.ts";
import { issueRecoveryActionService } from "../services/issue-recovery-actions.ts";
import { recoveryService } from "../services/recovery/service.ts";
import { decisionService } from "../services/decisions.ts";
import { createDecisionWakeOriginAgent } from "../services/decision-wakeup.ts";
import { isAgentInvokabilityConflict } from "../services/agent-invokability.ts";
import { healthRoutes } from "../routes/health.ts";
import { conflict } from "../errors.ts";

// CAP-15: exercise the startup recovery services in index.ts order, then
// mount the real health route. Only agent execution is replaced by a test adapter.
const testHome = await vi.hoisted(async () => {
  const { mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const home = mkdtempSync(join(tmpdir(), "paperclip-cap15-home-"));
  vi.stubEnv("PAPERCLIP_HOME", home);
  vi.stubEnv("PAPERCLIP_IN_WORKTREE", "false");
  vi.stubEnv("PAPERCLIP_TELEMETRY_ENABLED", "false");
  return home;
});

vi.mock("../telemetry.ts", () => ({
  getTelemetryClient: () => ({ track: vi.fn() }),
}));
vi.mock("@paperclipai/shared/telemetry", async () => {
  const actual = await vi.importActual<typeof import("@paperclipai/shared/telemetry")>("@paperclipai/shared/telemetry");
  return { ...actual, trackAgentFirstHeartbeat: vi.fn() };
});

const mockAdapterExecute = vi.hoisted(() =>
  vi.fn(async () => ({
    exitCode: 0,
    signal: null,
    timedOut: false,
    errorMessage: null,
    summary: "CAP-15 boot recovery test run.",
    provider: "test",
    model: "test-model",
  })),
);

vi.mock("../adapters/index.ts", async () => {
  const actual = await vi.importActual<typeof import("../adapters/index.ts")>("../adapters/index.ts");
  return {
    ...actual,
    getServerAdapter: vi.fn(() => ({
      supportsLocalAgentJwt: false,
      execute: mockAdapterExecute,
    })),
  };
});

const support = await getEmbeddedPostgresTestSupport();
const describePg = support.supported ? describe : describe.skip;

if (!support.supported) {
  console.warn(
    `Skipping CAP-15 boot recovery tests on this host: ${support.reason ?? "unsupported environment"}`,
  );
}

type SeededAgent = { companyId: string; agentId: string; issueId: string };

describePg("boot recovery with uninvokable agents holding pending wakes", () => {
  let db!: ReturnType<typeof createDb>;
  let heartbeat!: ReturnType<typeof heartbeatService>;
  let tempDb: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | null = null;

  beforeAll(async () => {
    tempDb = await startEmbeddedPostgresTestDatabase("paperclip-boot-recovery-");
    db = createDb(tempDb.connectionString);
    heartbeat = heartbeatService(db, {
      runtimeEnv: { ...process.env, PAPERCLIP_IN_WORKTREE: "false" },
    });
    await db.insert(authUsers).values([
      { id: "boot-recovery-user", name: "Operator", email: "cap15@example.test", createdAt: new Date(), updatedAt: new Date() },
      { id: "board-user", name: "Commenter", email: "cap15-board@example.test", createdAt: new Date(), updatedAt: new Date() },
    ]);
    // End each synthetic turn with a durable disposition, preventing native
    // 1005 legacy-disposition repair from starting unrelated background turns.
    mockAdapterExecute.mockImplementation(async (...args: unknown[]) => {
      const context = (args[0] as { context?: Record<string, unknown> })?.context;
      if (typeof context?.issueId === "string") {
        await db.update(issues).set({ status: "done" }).where(eq(issues.id, context.issueId));
      }
      return { exitCode: 0, signal: null, timedOut: false, errorMessage: null,
        summary: "CAP-15 boot recovery test run.", provider: "test", model: "test-model" };
    });
  }, 20_000);

  afterEach(async () => {
    delete process.env.PAPERCLIP_DECISIONS_SWEEP_BATCH_SIZE;
    await drainHeartbeatRunsToQuiescence(db, heartbeat);
    await db.execute(sql.raw(`TRUNCATE TABLE "companies" RESTART IDENTITY CASCADE`));
  });

  afterAll(async () => {
    await tempDb?.cleanup();
    const { rmSync } = await import("node:fs");
    rmSync(testHome, { recursive: true, force: true });
    vi.unstubAllEnvs();
  });

  const decisionExecutor = (wakeOriginAgent?: Parameters<typeof decisionService>[1]["wakeOriginAgent"]) =>
    decisionService(db, {
      wakeOriginAgent: wakeOriginAgent ?? createDecisionWakeOriginAgent(heartbeat.wakeup),
    });

  const bootRecovery = async () => {
    await heartbeat.promoteDueScheduledRetries();
    await heartbeat.resumeQueuedRuns();
    await heartbeat.recoverPendingSessionGoalActions();
    const goals = await heartbeat.recoverActiveSessionGoals();
    const stranded = await heartbeat.reconcileStrandedAssignedIssues();
    const swept = await decisionExecutor().sweepExpired();
    await drainHeartbeatRunsToQuiescence(db, heartbeat);
    return { goals, stranded, swept };
  };

  const healthStatus = async () => {
    const app = express();
    app.use("/api/health", healthRoutes(db, {
      deploymentMode: "local_trusted",
      deploymentExposure: "private",
      authReady: true,
      companyDeletionEnabled: true,
    }));
    const response = await request(app).get("/api/health");
    return response.status;
  };

  async function seedCompany() {
    const companyId = randomUUID();
    await db.insert(companies).values({
      id: companyId,
      name: "Boot Recovery",
      issuePrefix: `B${companyId.replace(/-/g, "").slice(0, 6).toUpperCase()}`,
      status: "active",
      defaultResponsibleUserId: "boot-recovery-user",
      requireBoardApprovalForNewAgents: false,
    });
    await db.insert(companyMemberships).values([
      { companyId, principalType: "user", principalId: "boot-recovery-user", status: "active", membershipRole: "owner" },
      { companyId, principalType: "user", principalId: "board-user", status: "active", membershipRole: "member" },
    ]);
    return companyId;
  }

  async function seedAgent(companyId: string, status: string, name = "Agent") {
    const agentId = randomUUID();
    await db.insert(agents).values({
      id: agentId,
      companyId,
      name: `${name}-${agentId.slice(0, 6)}`,
      role: "engineer",
      status,
      adapterType: "codex_local",
      adapterConfig: {},
      runtimeConfig: { heartbeat: { wakeOnDemand: true, maxConcurrentRuns: 1 } },
      permissions: {},
    });
    return agentId;
  }

  async function seedIssue(companyId: string, agentId: string, title: string) {
    const issueId = randomUUID();
    await db.insert(issues).values({
      id: issueId,
      companyId,
      title,
      status: "in_progress",
      priority: "medium",
      assigneeAgentId: agentId,
      responsibleUserId: "boot-recovery-user",
    });
    return issueId;
  }

  async function seedAgentWithEverythingPending(input: {
    companyId: string;
    status: string;
    name: string;
  }): Promise<
    SeededAgent & {
      goalIssueId: string;
      decisionId: string;
      decisionIssueId: string;
      queueId: string;
      commentId: string;
      commentIssueId: string;
    }
  > {
    const agentId = await seedAgent(input.companyId, input.status, input.name);
    const commentIssueId = await seedIssue(input.companyId, agentId, `${input.name} commented issue`);
    const strandedIssueId = await seedIssue(input.companyId, agentId, `${input.name} stranded issue`);
    const goalIssueId = await seedIssue(input.companyId, agentId, `${input.name} goal issue`);
    const decisionIssueId = await seedIssue(input.companyId, agentId, `${input.name} decision issue`);
    // The decision owns this task's continuation; keep generic stranded-work
    // recovery from starting a separate disposition repair before the sweep.
    await db.update(issues).set({ status: "blocked" }).where(eq(issues.id, decisionIssueId));
    const now = new Date();

    const held = ["paused", "pending_approval"].includes(input.status);
    // A saved comment behind an unsafe legacy execution requires board
    // reconciliation. Invokable controls use a safely completed predecessor.
    const commentRunId = randomUUID();
    await db.insert(heartbeatRuns).values({
      id: commentRunId,
      companyId: input.companyId,
      agentId,
      status: held ? "failed" : "succeeded",
      runtimeMode: "legacy",
      invocationSource: "on_demand",
      triggerDetail: "manual",
      error: held ? "legacy turn failed" : null,
      startedAt: now,
      finishedAt: now,
      contextSnapshot: { issueId: commentIssueId, wakeReason: "issue_commented" },
    });
    if (held) await db.insert(issueRecoveryActions).values({
      companyId: input.companyId,
      sourceIssueId: commentIssueId,
      kind: "issue_execution_reconciliation",
      status: "active",
      cause: "uncertain_provider_action",
      fingerprint: `fp-${commentRunId}`,
      evidence: { runId: commentRunId },
      nextAction: "reconcile",
    });

    const commentId = randomUUID();
    await db.insert(issueComments).values({
      id: commentId,
      companyId: input.companyId,
      issueId: commentIssueId,
      body: "Please take another look at this.",
      authorType: "user",
      authorUserId: "board-user",
    });
    const queueId = randomUUID();
    await db.insert(agentWakeupRequests).values({
      id: queueId,
      companyId: input.companyId,
      agentId,
      source: "comment",
      triggerDetail: "mention",
      // The shape a board comment really leaves behind: `routes/issues.ts`
      // writes `wakeReason: "issue_commented"`, and `resumeSavedLegacyComments`
      // re-offers the same queue under `reason: "issue_commented"`
      reason: "issue_commented",
      payload: {
        issueId: commentIssueId,
        _paperclipWakeContext: {
          issueId: commentIssueId,
          wakeReason: "issue_commented",
          wakeCommentId: commentId,
          wakeCommentIds: [commentId],
        },
        wakeCommentIds: [commentId],
      },
      status: "deferred_issue_execution",
      requestedByActorType: "user",
      requestedByActorId: "board-user",
    });

    // 1005 routes successful legacy predecessors to disposition repair. A
    // completed native predecessor exercises productive continuation recovery.
    await db.insert(heartbeatRuns).values({
      id: randomUUID(),
      companyId: input.companyId,
      agentId,
      status: "succeeded",
      livenessState: "completed",
      runtimeMode: "native",
      invocationSource: "assignment",
      startedAt: now,
      finishedAt: now,
      contextSnapshot: { issueId: strandedIssueId, wakeReason: "issue_assigned" },
    });

    // An active durable session goal.
    await db.insert(agentTaskSessions).values({
      companyId: input.companyId,
      agentId,
      adapterType: "codex_local",
      taskKey: goalIssueId,
      goalStatus: "active",
      goalDesiredState: "active",
      goalRevision: 1,
    }).returning();

    // An expired decision whose continuation is owed to the same agent.
    const decisionRunId = randomUUID();
    await db.insert(heartbeatRuns).values({
      id: decisionRunId,
      companyId: input.companyId,
      agentId,
      status: "succeeded",
      livenessState: "completed",
      runtimeMode: "legacy",
      startedAt: now,
      finishedAt: now,
      contextSnapshot: { issueId: decisionIssueId },
    });
    const decisionId = await seedExpiredDecision(
      input.companyId,
      agentId,
      decisionIssueId,
      decisionRunId,
    );

    return {
      companyId: input.companyId,
      agentId,
      issueId: strandedIssueId,
      goalIssueId,
      decisionId,
      queueId,
      commentId,
      commentIssueId,
      decisionIssueId,
    };
  }

  async function seedExpiredDecision(
    companyId: string,
    agentId: string,
    issueId: string,
    runId: string,
    overrides: Partial<typeof decisions.$inferInsert> = {},
  ) {
    const [row] = await db.insert(decisions).values({
      companyId,
      originAgentId: agentId,
      originIssueId: issueId,
      originRunId: runId,
      title: "Proceed?",
      body: "The deadline passed.",
      options: [{ id: "yes", label: "Yes", effects: [] }],
      status: "expired",
      executionStatus: null,
      continuationPolicy: "wake_origin_agent",
      expiresAt: new Date(Date.now() - 60_000),
      signedSpec: "test-signature",
      targetSnapshots: {},
      metadata: { continuationPending: true, expiredReason: "ttl" },
      ...overrides,
    }).returning();
    return row!.id;
  }

  const runsOnIssue = async (agentId: string, issueId: string) =>
    db
      .select({ id: heartbeatRuns.id })
      .from(heartbeatRuns)
      .where(and(
        eq(heartbeatRuns.agentId, agentId),
        sql`${heartbeatRuns.contextSnapshot}->>'issueId' = ${issueId}`,
      ));


  type SeededEverything = Awaited<ReturnType<typeof seedAgentWithEverythingPending>>;

  const assertGoalDelivered = async (seeded: SeededEverything) => {
    const [session] = await db
      .select()
      .from(agentTaskSessions)
      .where(eq(agentTaskSessions.taskKey, seeded.goalIssueId));
    const receipts = await db
      .select()
      .from(agentWakeupRequests)
      .where(eq(agentWakeupRequests.idempotencyKey, `goal_recovery:${session!.id}:1`));
    // The boot that deferred this goal already wrote its `skipped` receipt
    // under this same key. That receipt must not stand in the way of the
    // delivery that follows it.
    expect(receipts.filter((row) => row.status === "skipped")).toHaveLength(0);
    const delivered = receipts.filter((row) => row.status !== "skipped");
    expect(delivered.map((row) => row.status)).toContain("claimed");
    expect(delivered.some((row) => row.reason === "goal_control")).toBe(true);
  };

  const assertDecisionContinuationDelivered = async (seeded: SeededEverything) => {
    const [decision] = await db.select().from(decisions).where(eq(decisions.id, seeded.decisionId));
    // The debt is cleared with the acknowledgement stamp, not just flipped off.
    expect((decision!.metadata as Record<string, unknown>).continuationPending).toBe(false);
    expect((decision!.metadata as Record<string, unknown>).continuationDeliveredAt).toEqual(
      expect.any(String),
    );

    // Scoped to *this* decision on *this* issue. A receipt for the agent's other
    // decisions, or for another issue, is not this origin's delivery — and the
    // receipt a paused agent leaves behind (`reason: "agent.not_invokable"`,
    // `skipped`) is a refusal, not a delivery, so it cannot satisfy this either.
    const receipts = await db
      .select()
      .from(agentWakeupRequests)
      .where(and(
        eq(agentWakeupRequests.agentId, seeded.agentId),
        eq(agentWakeupRequests.reason, "decision_expired"),
        sql`${agentWakeupRequests.payload}->>'decisionId' = ${seeded.decisionId}`,
        sql`${agentWakeupRequests.payload}->>'issueId' = ${seeded.decisionIssueId}`,
      ));
    expect(receipts.length).toBeGreaterThanOrEqual(1);
    // A receipt still parked behind the issue execution blocker is not delivery.
    expect(receipts.some((row) => row.status === "deferred_issue_execution")).toBe(false);
    expect(receipts.some((row) => row.status === "skipped")).toBe(false);
    // `deliverContinuation` stamps `runId` from the wake it just took, so a
    // receipt with a turn is a wake that reached the queue, not one that only
    // recorded an attempt.
    const delivered = receipts.filter((row) => row.runId !== null);
    expect(delivered.length).toBeGreaterThanOrEqual(1);

    // And the turn is the delivery: it is the only way the continuation reaches
    // the agent, so it has to name this decision's issue and this wake reason.
    const turns = await db
      .select()
      .from(heartbeatRuns)
      .where(inArray(heartbeatRuns.id, delivered.map((row) => row.runId!)));
    expect(turns.length).toBeGreaterThanOrEqual(1);
    expect(turns.some((turn) => {
      const context = turn.contextSnapshot as Record<string, unknown>;
      return context.issueId === seeded.decisionIssueId && context.wakeReason === "decision_expired";
    })).toBe(true);
  };

  const assertCommentStillHeld = async (seeded: SeededEverything) => {
    const [queue] = await db
      .select()
      .from(agentWakeupRequests)
      .where(eq(agentWakeupRequests.id, seeded.queueId));
    expect(queue!.status).toBe("deferred_issue_execution");
    const saved = await db.select().from(issueComments).where(eq(issueComments.id, seeded.commentId));
    expect(saved).toHaveLength(1);
    expect(saved[0]!.deletedAt).toBeNull();
    expect(saved[0]!.createdByRunId).toBeNull();
  };

  const resolveBoardHold = async (seeded: SeededEverything, issueId: string) => {
    const updated = await issueService(db).update(issueId, { status: "in_progress" });
    expect(updated).not.toBeNull();
    const resolved = await issueRecoveryActionService(db).resolveActiveForIssue({
      companyId: seeded.companyId,
      sourceIssueId: issueId,
      status: "resolved",
      outcome: "restored",
      resolutionNote: "test_board_resolution",
    });
    expect(resolved).not.toBeNull();
    return resolved!;
  };

  const reofferSavedComment = async (seeded: SeededEverything) => {
    await heartbeat.wakeup(seeded.agentId, {
      source: "automation",
      triggerDetail: "system",
      reason: "issue_commented",
      payload: {
        issueId: seeded.commentIssueId,
        commentId: seeded.commentId,
        mutation: "comment",
      },
      requestedByActorType: "user",
      requestedByActorId: "board-user",
      contextSnapshot: {
        issueId: seeded.commentIssueId,
        taskId: seeded.commentIssueId,
        commentId: seeded.commentId,
        wakeCommentId: seeded.commentId,
        source: "issue.comment",
        wakeReason: "issue_commented",
      },
    });
  };

  const assertSavedCommentDelivered = async (seeded: SeededEverything) => {
    // The saved receipt is not left waiting: admission coalesced it into the
    // successor turn.
    const [queue] = await db
      .select()
      .from(agentWakeupRequests)
      .where(eq(agentWakeupRequests.id, seeded.queueId));
    expect(["coalesced", "claimed"]).toContain(queue!.status);
    expect(queue!.runId).not.toBeNull();

    // And the successor turn is the delivery: it carries the saved comment id,
    // which is the only way the agent ever reads it.
    const successor = await db
      .select()
      .from(heartbeatRuns)
      .where(eq(heartbeatRuns.id, queue!.runId!));
    expect(successor).toHaveLength(1);
    const context = successor[0]!.contextSnapshot as Record<string, unknown>;
    const carried = [
      ...(Array.isArray(context.wakeCommentIds) ? context.wakeCommentIds : []),
      context.wakeCommentId,
    ];
    expect(carried).toContain(seeded.commentId);
    expect(context.issueId).toBe(seeded.commentIssueId);

    // The comment itself is still on file, now consumed by that turn.
    const saved = await db.select().from(issueComments).where(eq(issueComments.id, seeded.commentId));
    expect(saved).toHaveLength(1);
    expect(saved[0]!.deletedAt).toBeNull();
  };

  const assertStrandedIssueRequeued = async (seeded: SeededEverything) => {
    const receipts = await db
      .select()
      .from(agentWakeupRequests)
      .where(and(
        eq(agentWakeupRequests.agentId, seeded.agentId),
        eq(agentWakeupRequests.reason, "issue_continuation_needed"),
        sql`${agentWakeupRequests.payload}->>'issueId' = ${seeded.issueId}`,
      ));
    expect(receipts.some((row) => ["queued", "claimed", "coalesced"].includes(row.status))).toBe(true);
    expect((await runsOnIssue(seeded.agentId, seeded.issueId)).length).toBeGreaterThanOrEqual(2);
  };

  it("finishes the startup recovery block and answers /api/health with 200 while paused and pending_approval agents hold every kind of pending item", async () => {
    const companyId = await seedCompany();
    const paused = await seedAgentWithEverythingPending({ companyId, status: "paused", name: "Paused" });
    const approval = await seedAgentWithEverythingPending({ companyId, status: "pending_approval", name: "Approval" });

    const result = await bootRecovery();

    expect(result.goals.deferred).toBe(2);
    expect(result.swept.deferredContinuations).toBe(2);
    expect(await healthStatus()).toBe(200);

    // Nothing was lost: each origin record is still pending, exactly as before
    // the boot, and each is still owned by its agent.
    for (const seeded of [paused, approval]) {
      const [decision] = await db.select().from(decisions).where(eq(decisions.id, seeded.decisionId));
      expect((decision!.metadata as Record<string, unknown>).continuationPending).toBe(true);

      const [queue] = await db.select().from(agentWakeupRequests).where(eq(agentWakeupRequests.id, seeded.queueId));
      expect(queue!.status).toBe("deferred_issue_execution");

      const [issue] = await db.select().from(issues).where(eq(issues.id, seeded.issueId));
      expect(issue!.assigneeAgentId).toBe(seeded.agentId);

      const [goal] = await db
        .select()
        .from(agentTaskSessions)
        .where(eq(agentTaskSessions.taskKey, seeded.goalIssueId));
      expect(goal!.goalStatus).toBe("active");
      expect(goal!.goalDesiredState).toBe("active");
    }
  }, 30_000);

  it("delivers all four pending origins of a resumed paused agent, and never loses the saved comment", async () => {
    const companyId = await seedCompany();
    const seeded = await seedAgentWithEverythingPending({ companyId, status: "paused", name: "Paused" });
    await bootRecovery();

    await agentService(db).resume(seeded.agentId);
    const result = await bootRecovery();

    expect(result.goals.deferred).toBe(0);

    // Origin 1 — `recoverActiveSessionGoals`: the receipt under
    // `goal_recovery:<session>:<revision>` is claimed, not skipped.
    await assertGoalDelivered(seeded);

    // Origin 2 — `decisionExecutor.sweepExpired`: the continuation the decision
    // owed is delivered and the debt is cleared.
    await assertDecisionContinuationDelivered(seeded);

    // Origin 3 — the saved board comment. While the board hold is open this is
    // D2, not delivery: the receipt waits and the comment is untouched. The
    // hold is the board's, and it is what `deferBlockedExecution` reports.
    await assertCommentStillHeld(seeded);

    // Origin 4 — the stranded assignment. While the agent was uninvokable the
    // sweep escalated the issue into a board-owned recovery; that is native and
    // is not this correction's to change. Once the board settles the hold and
    // puts the issue back in a working status, the same path requeues it.
    await resolveBoardHold(seeded, seeded.issueId);
    const requeued = await heartbeat.reconcileStrandedAssignedIssues();
    expect(requeued.continuationRequeued).toBeGreaterThanOrEqual(1);
    expect(requeued.issueIds).toContain(seeded.issueId);
    await drainHeartbeatRunsToQuiescence(db, heartbeat);
    await assertStrandedIssueRequeued(seeded);

    // And the saved comment, once its own hold is settled the same way. The
    // delivery is the coalesced receipt plus the successor turn that carries
    // the comment id — not the comment surviving.
    await resolveBoardHold(seeded, seeded.commentIssueId);
    await reofferSavedComment(seeded);
    await drainHeartbeatRunsToQuiescence(db, heartbeat);
    await assertSavedCommentDelivered(seeded);
  }, 30_000);

  it("delivers all four pending origins of an approved pending_approval agent", async () => {
    const companyId = await seedCompany();
    const seeded = await seedAgentWithEverythingPending({ companyId, status: "pending_approval", name: "Approval" });
    await bootRecovery();

    const approvals = approvalService(db);
    const approval = await approvals.create(companyId, {
      type: "hire_agent", status: "pending", payload: { agentId: seeded.agentId },
    });
    await approvals.approve(approval.id, "board-user");
    const result = await bootRecovery();

    expect(result.goals.deferred).toBe(0);
    await assertGoalDelivered(seeded);
    await assertDecisionContinuationDelivered(seeded);
    await assertCommentStillHeld(seeded);

    await resolveBoardHold(seeded, seeded.issueId);
    const requeued = await heartbeat.reconcileStrandedAssignedIssues();
    expect(requeued.continuationRequeued).toBeGreaterThanOrEqual(1);
    expect(requeued.issueIds).toContain(seeded.issueId);
    await assertStrandedIssueRequeued(seeded);

    await resolveBoardHold(seeded, seeded.commentIssueId);
    await reofferSavedComment(seeded);
    await drainHeartbeatRunsToQuiescence(db, heartbeat);
    await assertSavedCommentDelivered(seeded);
  }, 30_000);

  it("delivers the idle agent's continuation in the same sweep as 100 continuations stuck on uninvokable agents", async () => {
    const companyId = await seedCompany();
    const paused = await seedAgent(companyId, "paused", "Paused");
    const idle = await seedAgent(companyId, "idle", "Idle");
    const pausedRunId = randomUUID();
    const idleRunId = randomUUID();
    await db.insert(heartbeatRuns).values([
      { id: pausedRunId, companyId, agentId: paused, status: "failed", runtimeMode: "legacy", startedAt: new Date(), finishedAt: new Date(), contextSnapshot: {} },
      { id: idleRunId, companyId, agentId: idle, status: "failed", runtimeMode: "legacy", startedAt: new Date(), finishedAt: new Date(), contextSnapshot: {} },
    ]);
    const pausedIssueId = await seedIssue(companyId, paused, "Paused issue");
    const idleIssueId = await seedIssue(companyId, idle, "Idle issue");

    const stale = new Date(Date.now() - 10 * 60_000);
    // 100 continuations on the paused agent, all older than the idle agent's.
    for (let index = 0; index < 100; index += 1) {
      await seedExpiredDecision(companyId, paused, pausedIssueId, pausedRunId, { updatedAt: stale });
    }
    const idleDecisionId = await seedExpiredDecision(companyId, idle, idleIssueId, idleRunId);

    const swept = await decisionExecutor().sweepExpired();
    await drainHeartbeatRunsToQuiescence(db, heartbeat);

    expect(swept.deferredContinuations).toBe(100);
    const [idleDecision] = await db.select().from(decisions).where(eq(decisions.id, idleDecisionId));
    expect((idleDecision!.metadata as Record<string, unknown>).continuationPending).toBe(false);
    const idleReceipts = await db.select().from(agentWakeupRequests).where(and(
      eq(agentWakeupRequests.agentId, idle), eq(agentWakeupRequests.reason, "decision_expired"),
      sql`${agentWakeupRequests.payload}->>'decisionId' = ${idleDecisionId}`,
    ));
    expect(idleReceipts.some(receipt => receipt.runId !== null)).toBe(true);
    const stuck = await db.select().from(decisions).where(eq(decisions.originAgentId, paused));
    expect(stuck).toHaveLength(100);
    expect(stuck.every(row => row.metadata.continuationPending === true)).toBe(true);
  }, 60_000);

  it("advances past a blocked prefix larger than the bounded delivery passes across sweeps", async () => {
    process.env.PAPERCLIP_DECISIONS_SWEEP_BATCH_SIZE = "1";
    const companyId = await seedCompany();
    const paused = await seedAgent(companyId, "paused");
    const idle = await seedAgent(companyId, "idle");
    const issueId = await seedIssue(companyId, paused, "Blocked continuations");
    const runId = randomUUID();
    await db.insert(heartbeatRuns).values({ id: runId, companyId, agentId: paused, status: "succeeded" });
    for (let index = 0; index < 11; index += 1) {
      await seedExpiredDecision(companyId, paused, issueId, runId, {
        updatedAt: new Date(Date.now() - 60_000 + index),
      });
    }
    const healthyId = await seedExpiredDecision(companyId, idle, issueId, runId);
    const delivered: string[] = [];
    const executor = decisionExecutor(async input => {
      if (input.agentId === paused) throw conflict("Agent is not invokable in its current state");
      delivered.push(input.decisionId);
    });
    expect((await executor.sweepExpired()).deferredContinuations).toBe(10);
    expect(delivered).toEqual([]);
    await executor.sweepExpired();
    expect(delivered).toEqual([healthyId]);
  });

  it("delivers at boot to an error agent and an idle agent, which are invokable", async () => {
    const companyId = await seedCompany();
    const errored = await seedAgentWithEverythingPending({ companyId, status: "error", name: "Error" });
    const idle = await seedAgentWithEverythingPending({ companyId, status: "idle", name: "Idle" });

    const result = await bootRecovery();

    expect(result.goals.deferred).toBe(0);
    expect(result.goals.enqueued).toBeGreaterThanOrEqual(2);
    expect(result.stranded.continuationRequeued).toBeGreaterThanOrEqual(2);
    for (const seeded of [errored, idle]) {
      await assertGoalDelivered(seeded);
      await assertDecisionContinuationDelivered(seeded);
      await assertStrandedIssueRequeued(seeded);
      await assertSavedCommentDelivered(seeded);
    }
    expect(await healthStatus()).toBe(200);
  }, 30_000);

  it("still aborts the decision sweep on an error that is not the invokability conflict", async () => {
    const companyId = await seedCompany();
    const paused = await seedAgent(companyId, "paused", "Paused");
    const runId = randomUUID();
    await db.insert(heartbeatRuns).values({
      id: runId, companyId, agentId: paused, status: "failed", runtimeMode: "legacy",
      startedAt: new Date(), finishedAt: new Date(), contextSnapshot: {},
    });
    const issueId = await seedIssue(companyId, paused, "Paused issue");
    await seedExpiredDecision(companyId, paused, issueId, runId);

    const failing = decisionExecutor(async () => {
      throw new Error("origin wake exploded");
    });

    await expect(failing.sweepExpired()).rejects.toThrow("origin wake exploded");
  }, 30_000);

  it("keeps a non-invokability conflict inside the recovery sweep, so one item does not abandon the rest", async () => {
    const companyId = await seedCompany();
    const blocked = await seedAgent(companyId, "active", "Blocked");
    const healthy = await seedAgent(companyId, "active", "Healthy");
    const blockedIssueId = await seedIssue(companyId, blocked, "Blocked issue");
    const healthyIssueId = await seedIssue(companyId, healthy, "Healthy issue");
    const now = new Date();
    await db.insert(heartbeatRuns).values([
      { id: randomUUID(), companyId, agentId: blocked, status: "succeeded", livenessState: "completed", runtimeMode: "native", invocationSource: "assignment", startedAt: now, finishedAt: now, contextSnapshot: { issueId: blockedIssueId, wakeReason: "issue_assigned" } },
      { id: randomUUID(), companyId, agentId: healthy, status: "succeeded", livenessState: "completed", runtimeMode: "native", invocationSource: "assignment", startedAt: now, finishedAt: now, contextSnapshot: { issueId: healthyIssueId, wakeReason: "issue_assigned" } },
    ]);

    const recovery = recoveryService(db, {
      enqueueWakeup: async (agentId) => {
        if (agentId === blocked) {
          throw conflict("Agent is not invokable in its current state", {
            status: "paused",
            reason: "paused",
            agentId,
          });
        }
        return { id: randomUUID() };
      },
    });

    const result = await recovery.reconcileStrandedAssignedIssues();

    expect(result.continuationRequeued).toBe(1);
    expect(result.issueIds).toContain(healthyIssueId);
    expect(result.issueIds).not.toContain(blockedIssueId);
  }, 30_000);

  it("still aborts the recovery sweep on an error that is not the invokability conflict", async () => {
    const companyId = await seedCompany();
    const agentId = await seedAgent(companyId, "active", "Agent");
    const issueId = await seedIssue(companyId, agentId, "Agent issue");
    const now = new Date();
    await db.insert(heartbeatRuns).values({
      id: randomUUID(), companyId, agentId, status: "succeeded", livenessState: "completed",
      runtimeMode: "native", invocationSource: "assignment", startedAt: now, finishedAt: now,
      contextSnapshot: { issueId, wakeReason: "issue_assigned" },
    });

    const recovery = recoveryService(db, {
      enqueueWakeup: async () => {
        throw new Error("provider exploded");
      },
    });

    await expect(recovery.reconcileStrandedAssignedIssues()).rejects.toThrow("provider exploded");
  }, 30_000);
});

describe("isAgentInvokabilityConflict", () => {
  it("recognises only the 409s the invokability check produces", () => {
    expect(isAgentInvokabilityConflict(conflict("Agent is not invokable in its current state", {
      status: "paused", reason: "paused",
    }))).toBe(true);
    expect(isAgentInvokabilityConflict(conflict("Agent is not invokable because its reporting chain is invalid", {
      reason: "manager_terminated",
    }))).toBe(true);
  });

  it("does not swallow the other conflicts enqueueWakeup throws", () => {
    expect(isAgentInvokabilityConflict(conflict("Daily invocation budget exhausted", {
      scopeType: "company", scopeId: "company-1",
    }))).toBe(false);
    expect(isAgentInvokabilityConflict(new Error("Agent is not invokable in its current state"))).toBe(false);
    expect(isAgentInvokabilityConflict(conflict("decision_already_resolved", {
      code: "decision_already_resolved",
    }))).toBe(false);
    expect(isAgentInvokabilityConflict(null)).toBe(false);
  });
});
