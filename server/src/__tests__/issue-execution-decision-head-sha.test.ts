import { randomUUID } from "node:crypto";
import express from "express";
import request from "supertest";
import { asc, eq, sql } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  activityLog,
  agentRuntimeState,
  agentTaskSessions,
  agentWakeupRequests,
  agents,
  companies,
  companyMemberships,
  createDb,
  executionWorkspaces,
  heartbeatRunEvents,
  heartbeatRuns,
  issueComments,
  issueExecutionDecisions,
  issueInboxArchives,
  issueRecoveryActions,
  issueThreadInteractions,
  issues,
  projects,
} from "@paperclipai/db";
import { errorHandler } from "../middleware/index.js";
import { issueRoutes } from "../routes/issues.js";
import { heartbeatService } from "../services/heartbeat.js";
import { issueRecoveryActionService } from "../services/issue-recovery-actions.js";
import { drainHeartbeatRunsToQuiescence } from "./helpers/drain-heartbeat-runs.js";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";

// An execution decision records the commit the deciding actor declares it
// examined (`headSha`). These tests cover every decision-creating route, the
// issue's `executionState.lastDecisionHeadSha` projection and the ordered
// decision history returned by GET /issues/:id/execution-decisions.

const embeddedPostgresSupport = await getEmbeddedPostgresTestSupport();
const describeEmbeddedPostgres = embeddedPostgresSupport.supported ? describe : describe.skip;

if (!embeddedPostgresSupport.supported) {
  console.warn(
    `Skipping embedded Postgres execution decision headSha tests on this host: ${embeddedPostgresSupport.reason ?? "unsupported environment"}`,
  );
}

const SHA_A = "a".repeat(40);
const SHA_B = "0123456789abcdef0123456789abcdef01234567";
const SHA_256 = "0123456789abcdef".repeat(4);

describeEmbeddedPostgres("execution decision headSha", () => {
  let db!: ReturnType<typeof createDb>;
  let tempDb: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | null = null;
  const enqueueWakeup = vi.fn(async () => ({ id: randomUUID() }));

  beforeAll(async () => {
    tempDb = await startEmbeddedPostgresTestDatabase("paperclip-execution-decision-head-sha-");
    db = createDb(tempDb.connectionString);
  }, 30_000);

  afterEach(async () => {
    enqueueWakeup.mockClear();
    // Stage wakes are fire-and-forget; let them settle before deleting rows.
    await drainHeartbeatRunsToQuiescence(db, heartbeatService(db));
    await db.delete(issueExecutionDecisions);
    await db.delete(issueThreadInteractions);
    await db.delete(issueComments);
    await db.delete(issueRecoveryActions);
    await db.delete(activityLog);
    await db.delete(heartbeatRunEvents);
    await db.delete(agentTaskSessions);
    await db.delete(heartbeatRuns);
    await db.delete(agentWakeupRequests);
    await db.delete(issueInboxArchives);
    await db.delete(issues);
    await db.delete(executionWorkspaces);
    await db.delete(projects);
    await db.delete(companyMemberships);
    await db.delete(agentRuntimeState);
    await db.delete(agents);
    await db.delete(companies);
  });

  afterAll(async () => {
    await tempDb?.cleanup();
  });

  function app(actor: Record<string, unknown>) {
    const testApp = express();
    testApp.use(express.json());
    testApp.use((req, _res, next) => {
      (req as any).actor = actor;
      next();
    });
    testApp.use("/api", issueRoutes(db, {} as any, {
      stalledReviewDecisionEnqueueWakeup: enqueueWakeup as any,
      recoveryActionEnqueueWakeup: enqueueWakeup as any,
    }));
    testApp.use(errorHandler);
    return testApp;
  }

  /**
   * An app whose database runs `hook` once, right before the request's first
   * transaction opens: after the route read its issue snapshot and computed the
   * stage transition, before the decision write locks the row. It stands in for
   * a concurrent writer committing in that window.
   */
  function appWithConcurrentWrite(actor: Record<string, unknown>, hook: () => Promise<void>) {
    let pending: (() => Promise<void>) | null = hook;
    const racingDb = new Proxy(db, {
      get(target, property, receiver) {
        if (property === "transaction") {
          return async (...args: Parameters<typeof db.transaction>) => {
            const run = pending;
            pending = null;
            if (run) await run();
            return target.transaction(...args);
          };
        }
        const value = Reflect.get(target, property, receiver);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const testApp = express();
    testApp.use(express.json());
    testApp.use((req, _res, next) => {
      (req as any).actor = actor;
      next();
    });
    testApp.use("/api", issueRoutes(racingDb as typeof db, {} as any, {
      stalledReviewDecisionEnqueueWakeup: enqueueWakeup as any,
      recoveryActionEnqueueWakeup: enqueueWakeup as any,
    }));
    testApp.use(errorHandler);
    return testApp;
  }

  function boardActor(companyId: string, userId: string) {
    return {
      type: "board",
      source: "session",
      userId,
      companyIds: [companyId],
      memberships: [{ companyId, status: "active", membershipRole: "operator" }],
      isInstanceAdmin: false,
    };
  }

  function agentActor(companyId: string, agentId: string, runId: string) {
    return { type: "agent", source: "agent_key", companyId, agentId, runId };
  }

  async function seedCompany(prefix: string) {
    const companyId = randomUUID();
    const reviewerAgentId = randomUUID();
    const coderAgentId = randomUUID();
    const memberUserId = `${prefix.toLowerCase()}-member`;
    await db.insert(companies).values({
      id: companyId,
      name: `${prefix} Company`,
      issuePrefix: prefix,
      requireBoardApprovalForNewAgents: false,
    });
    await db.insert(agents).values(
      [reviewerAgentId, coderAgentId].map((id, index) => ({
        id,
        companyId,
        name: `${prefix} ${index === 0 ? "Reviewer" : "Coder"}`,
        role: "engineer",
        status: "idle",
        // Stage wakes are real heartbeat work: a process adapter without a
        // command fails before spawning anything, so no agent CLI ever runs.
        adapterType: "process",
        adapterConfig: {},
        runtimeConfig: {},
        permissions: {},
      })),
    );
    await db.insert(companyMemberships).values({
      companyId,
      principalType: "user",
      principalId: memberUserId,
      status: "active",
      membershipRole: "operator",
    });
    return { companyId, reviewerAgentId, coderAgentId, memberUserId };
  }

  /** An issue in_review whose single review stage is pending on `participant`. */
  async function seedPendingReview(input: {
    companyId: string;
    identifier: string;
    participant: { type: "agent"; agentId: string } | { type: "user"; userId: string };
    returnAgentId: string;
  }) {
    const issueId = randomUUID();
    const stageId = randomUUID();
    const participant = input.participant.type === "agent"
      ? { type: "agent" as const, agentId: input.participant.agentId }
      : { type: "user" as const, userId: input.participant.userId };
    await db.insert(issues).values({
      id: issueId,
      companyId: input.companyId,
      identifier: input.identifier,
      title: input.identifier,
      status: "in_review",
      priority: "medium",
      assigneeAgentId: participant.type === "agent" ? participant.agentId : null,
      assigneeUserId: participant.type === "user" ? participant.userId : null,
      executionPolicy: {
        mode: "normal",
        commentRequired: true,
        stages: [{
          id: stageId,
          type: "review",
          approvalsNeeded: 1,
          participants: [{ id: randomUUID(), ...participant }],
        }],
      },
      executionState: {
        status: "pending",
        currentStageId: stageId,
        currentStageIndex: 0,
        currentStageType: "review",
        currentParticipant: participant,
        returnAssignee: { type: "agent", agentId: input.returnAgentId },
        completedStageIds: [],
        lastDecisionId: null,
        lastDecisionOutcome: null,
      },
    });
    return { issueId, stageId };
  }

  async function seedRun(companyId: string, agentId: string, issueId: string) {
    const runId = randomUUID();
    await db.insert(heartbeatRuns).values({
      id: runId,
      companyId,
      agentId,
      invocationSource: "assignment",
      triggerDetail: "system",
      status: "running",
      contextSnapshot: { issueId, wakeReason: "issue_assigned" },
    });
    return runId;
  }

  async function decisionRows(issueId: string) {
    return db
      .select()
      .from(issueExecutionDecisions)
      .where(eq(issueExecutionDecisions.issueId, issueId))
      .orderBy(asc(issueExecutionDecisions.createdAt), asc(issueExecutionDecisions.id));
  }

  async function issueRow(issueId: string) {
    const [row] = await db.select().from(issues).where(eq(issues.id, issueId));
    return row!;
  }

  async function reviewerPatch(
    seeded: Awaited<ReturnType<typeof seedCompany>>,
    issueId: string,
    body: Record<string, unknown>,
  ) {
    const runId = await seedRun(seeded.companyId, seeded.reviewerAgentId, issueId);
    return request(app(agentActor(seeded.companyId, seeded.reviewerAgentId, runId)))
      .patch(`/api/issues/${issueId}`)
      .send(body);
  }

  async function activityRows(issueId: string) {
    return db.select().from(activityLog).where(eq(activityLog.entityId, issueId));
  }

  /** The activity entries of the issue that carry a recorded execution decision. */
  async function decisionActivity(issueId: string) {
    return (await activityRows(issueId))
      .map((row) => (row.details as Record<string, unknown> | null)?.executionDecision)
      .filter((entry) => entry !== undefined);
  }

  /**
   * Complete write counts, unfiltered: every activity row and every comment in
   * the database. A rejected request must leave both exactly as they were.
   */
  async function writeCounts() {
    const [activity] = await db.select({ n: sql<number>`count(*)::int` }).from(activityLog);
    const [comments] = await db.select({ n: sql<number>`count(*)::int` }).from(issueComments);
    return { activity: activity!.n, comments: comments!.n };
  }

  async function seedRecoveryAction(companyId: string, issueId: string, ownerAgentId: string) {
    return issueRecoveryActionService(db).upsertSourceScoped({
      companyId,
      sourceIssueId: issueId,
      kind: "missing_disposition",
      ownerType: "agent",
      ownerAgentId,
      cause: "successful_run_missing_issue_disposition",
      fingerprint: `missing-disposition:${issueId}`,
      evidence: { sourceRunId: "run-1" },
      nextAction: "Choose a valid issue disposition.",
      wakePolicy: { type: "wake_owner" },
    });
  }

  function expectHeadShaWithoutDecision(res: request.Response) {
    expect(res.status, JSON.stringify(res.body)).toBe(422);
    expect(res.body).toMatchObject({ details: { code: "head_sha_without_decision" } });
  }

  async function listDecisions(actor: Record<string, unknown>, issueId: string) {
    return request(app(actor)).get(`/api/issues/${issueId}/execution-decisions`);
  }

  it("round-trips headSha through PATCH, the issue execution state and the decision list", async () => {
    const seeded = await seedCompany("HRT");
    const { issueId, stageId } = await seedPendingReview({
      companyId: seeded.companyId,
      identifier: "HRT-1",
      participant: { type: "agent", agentId: seeded.reviewerAgentId },
      returnAgentId: seeded.coderAgentId,
    });

    const res = await reviewerPatch(seeded, issueId, { status: "done", comment: "Approved.", headSha: SHA_A });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    expect(res.body.executionState).toMatchObject({ lastDecisionOutcome: "approved", lastDecisionHeadSha: SHA_A });

    const [row] = await decisionRows(issueId);
    expect(row).toMatchObject({ stageId, outcome: "approved", headSha: SHA_A, actorAgentId: seeded.reviewerAgentId });
    expect((await issueRow(issueId)).executionState).toMatchObject({ lastDecisionId: row!.id, lastDecisionHeadSha: SHA_A });

    const listed = await listDecisions(boardActor(seeded.companyId, seeded.memberUserId), issueId);
    expect(listed.status, JSON.stringify(listed.body)).toBe(200);
    expect(listed.body).toEqual([
      {
        id: row!.id,
        stageId,
        stageType: "review",
        outcome: "approved",
        actorAgentId: seeded.reviewerAgentId,
        actorUserId: null,
        createdByRunId: row!.createdByRunId,
        createdAt: row!.createdAt.toISOString(),
        headSha: SHA_A,
      },
    ]);
    expect(row!.createdByRunId).toEqual(expect.any(String));

    // The decision's activity names the declared head.
    expect(await decisionActivity(issueId)).toContainEqual({
      id: row!.id,
      stageId,
      outcome: "approved",
      headSha: SHA_A,
    });
  });

  it("accepts a SHA-256 (64 hex) headSha", async () => {
    const seeded = await seedCompany("HSX");
    const { issueId } = await seedPendingReview({
      companyId: seeded.companyId,
      identifier: "HSX-1",
      participant: { type: "agent", agentId: seeded.reviewerAgentId },
      returnAgentId: seeded.coderAgentId,
    });

    const res = await reviewerPatch(seeded, issueId, { status: "done", comment: "Approved.", headSha: SHA_256 });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const [row] = await decisionRows(issueId);
    expect(row).toMatchObject({ outcome: "approved", headSha: SHA_256 });
    expect((await issueRow(issueId)).executionState).toMatchObject({ lastDecisionHeadSha: SHA_256 });
  });

  it("rejects headSha with 422 on a PATCH that records no decision, and persists nothing", async () => {
    const seeded = await seedCompany("HNP");
    const { issueId } = await seedPendingReview({
      companyId: seeded.companyId,
      identifier: "HNP-1",
      participant: { type: "agent", agentId: seeded.reviewerAgentId },
      returnAgentId: seeded.coderAgentId,
    });
    const before = await issueRow(issueId);
    const runId = await seedRun(seeded.companyId, seeded.reviewerAgentId, issueId);
    const countsBefore = await writeCounts();

    const res = await request(app(agentActor(seeded.companyId, seeded.reviewerAgentId, runId)))
      .patch(`/api/issues/${issueId}`)
      .send({ comment: "Still looking.", headSha: SHA_A });
    expectHeadShaWithoutDecision(res);
    expect(await decisionRows(issueId)).toEqual([]);
    const after = await issueRow(issueId);
    expect(after.status).toBe("in_review");
    expect(after.executionState).toEqual(before.executionState);
    expect(after.updatedAt).toEqual(before.updatedAt);
    expect(await writeCounts()).toEqual(countsBefore);
  });

  it.each([
    ["a plain comment", "Looks fine so far."],
    ["a changes-request comment (comments only auto-approve)", "kind: review\ndecision: changes_requested"],
  ])("rejects headSha with 422 on %s, and persists nothing", async (_label, body) => {
    const seeded = await seedCompany(_label.startsWith("a plain") ? "HCP" : "HCR");
    const { issueId } = await seedPendingReview({
      companyId: seeded.companyId,
      identifier: `${_label.startsWith("a plain") ? "HCP" : "HCR"}-1`,
      participant: { type: "agent", agentId: seeded.reviewerAgentId },
      returnAgentId: seeded.coderAgentId,
    });
    const before = await issueRow(issueId);
    const runId = await seedRun(seeded.companyId, seeded.reviewerAgentId, issueId);
    const countsBefore = await writeCounts();

    const res = await request(app(agentActor(seeded.companyId, seeded.reviewerAgentId, runId)))
      .post(`/api/issues/${issueId}/comments`)
      .send({ body, headSha: SHA_A });
    expectHeadShaWithoutDecision(res);
    expect(await db.select().from(issueComments).where(eq(issueComments.issueId, issueId))).toEqual([]);
    expect(await decisionRows(issueId)).toEqual([]);
    expect((await issueRow(issueId)).executionState).toEqual(before.executionState);
    expect(await writeCounts()).toEqual(countsBefore);
  });

  it.each(["false_positive", "cancelled"] as const)(
    "rejects headSha with 422 on a %s recovery resolution that records no decision, and persists nothing",
    async (outcome) => {
      const seeded = await seedCompany(outcome === "cancelled" ? "HRC" : "HRF");
      const { issueId } = await seedPendingReview({
        companyId: seeded.companyId,
        identifier: `${outcome === "cancelled" ? "HRC" : "HRF"}-1`,
        participant: { type: "agent", agentId: seeded.reviewerAgentId },
        returnAgentId: seeded.coderAgentId,
      });
      const action = await seedRecoveryAction(seeded.companyId, issueId, seeded.reviewerAgentId);
      const before = await issueRow(issueId);
      const countsBefore = await writeCounts();

      const res = await request(app({ type: "board", source: "local_implicit", userId: "local-board" }))
        .post(`/api/issues/${issueId}/recovery-actions/resolve`)
        .send({ actionId: action.id, outcome, sourceIssueStatus: "done", headSha: SHA_A });
      expectHeadShaWithoutDecision(res);
      expect(await decisionRows(issueId)).toEqual([]);
      const after = await issueRow(issueId);
      expect(after.status).toBe("in_review");
      expect(after.executionState).toEqual(before.executionState);
      expect(await issueRecoveryActionService(db).getActiveForIssue(seeded.companyId, issueId)).toMatchObject({
        id: action.id,
        status: "active",
      });
      expect(await writeCounts()).toEqual(countsBefore);
    },
  );

  it("rejects a non-participant's interrupting approval comment with headSha before cancelling the active run", async () => {
    const seeded = await seedCompany("HIN");
    const { issueId } = await seedPendingReview({
      companyId: seeded.companyId,
      identifier: "HIN-1",
      participant: { type: "agent", agentId: seeded.reviewerAgentId },
      returnAgentId: seeded.coderAgentId,
    });
    const activeRunId = await seedRun(seeded.companyId, seeded.reviewerAgentId, issueId);
    await db.update(issues).set({ executionRunId: activeRunId }).where(eq(issues.id, issueId));
    const before = await issueRow(issueId);
    const countsBefore = await writeCounts();

    // The board user may interrupt, but is not the stage participant: no decision.
    const res = await request(app(boardActor(seeded.companyId, seeded.memberUserId)))
      .post(`/api/issues/${issueId}/comments`)
      .send({ body: "kind: review\ndecision: approved", interrupt: true, headSha: SHA_A });
    expectHeadShaWithoutDecision(res);

    const [run] = await db.select().from(heartbeatRuns).where(eq(heartbeatRuns.id, activeRunId));
    expect(run!.status).toBe("running");
    expect(await writeCounts()).toEqual(countsBefore);
    expect(await decisionRows(issueId)).toEqual([]);
    const after = await issueRow(issueId);
    expect(after.status).toBe(before.status);
    expect(after.executionRunId).toBe(activeRunId);
    expect(after.updatedAt).toEqual(before.updatedAt);
  });

  it("rejects a reopening approval comment with headSha on a closed issue before reopening anything", async () => {
    const seeded = await seedCompany("HRO");
    const projectId = randomUUID();
    await db.insert(projects).values({ id: projectId, companyId: seeded.companyId, name: "HRO project" });
    const workspaceId = randomUUID();
    const closedAt = new Date("2026-10-15T10:00:00.000Z");
    await db.insert(executionWorkspaces).values({
      id: workspaceId,
      companyId: seeded.companyId,
      projectId,
      mode: "isolated_workspace",
      strategyType: "git_worktree",
      name: "HRO workspace",
      status: "archived",
      closedAt,
    });
    const issueId = randomUUID();
    await db.insert(issues).values({
      id: issueId,
      companyId: seeded.companyId,
      projectId,
      identifier: "HRO-1",
      title: "HRO-1",
      status: "done",
      priority: "medium",
      assigneeAgentId: seeded.coderAgentId,
      executionWorkspaceId: workspaceId,
    });
    const [workspaceBefore] = await db.select().from(executionWorkspaces).where(eq(executionWorkspaces.id, workspaceId));
    const runsBefore = await db.select({ id: heartbeatRuns.id, status: heartbeatRuns.status }).from(heartbeatRuns);
    const before = await issueRow(issueId);
    const countsBefore = await writeCounts();

    const res = await request(app(boardActor(seeded.companyId, seeded.memberUserId)))
      .post(`/api/issues/${issueId}/comments`)
      .send({ body: "kind: review\ndecision: approved", reopen: true, headSha: SHA_A });
    expectHeadShaWithoutDecision(res);

    expect(await writeCounts()).toEqual(countsBefore);
    const after = await issueRow(issueId);
    expect(after.status).toBe("done");
    expect(after.executionState).toEqual(before.executionState);
    expect(after.updatedAt).toEqual(before.updatedAt);
    const [workspaceAfter] = await db.select().from(executionWorkspaces).where(eq(executionWorkspaces.id, workspaceId));
    expect(workspaceAfter).toEqual(workspaceBefore);
    // No retry or other run was created, cancelled or resumed.
    expect(await db.select({ id: heartbeatRuns.id, status: heartbeatRuns.status }).from(heartbeatRuns)).toEqual(runsBefore);
  });

  it("rejects headSha on a board conversation message before saving it", async () => {
    const seeded = await seedCompany("HCV");
    const issueId = randomUUID();
    await db.insert(issues).values({
      id: issueId,
      companyId: seeded.companyId,
      identifier: "HCV-1",
      title: "HCV-1",
      status: "todo",
      priority: "medium",
      assigneeAgentId: seeded.reviewerAgentId,
      conversationAgentId: seeded.reviewerAgentId,
      conversationUserId: seeded.memberUserId,
      conversationState: "active",
    });
    const countsBefore = await writeCounts();

    const res = await request(app(boardActor(seeded.companyId, seeded.memberUserId)))
      .post(`/api/issues/${issueId}/comments`)
      .send({ body: "kind: review\ndecision: approved", clientRequestId: randomUUID(), headSha: SHA_A });
    expectHeadShaWithoutDecision(res);
    expect(await writeCounts()).toEqual(countsBefore);
    expect(await db.select().from(issueComments).where(eq(issueComments.issueId, issueId))).toEqual([]);
  });

  describe("a decision computed from a stale snapshot", () => {
    const cases = [
      ["PATCH", SHA_A],
      ["PATCH", undefined],
      ["review-approval comment", SHA_A],
      ["review-approval comment", undefined],
    ] as const;

    it.each(cases)(
      "is refused with 409 by a %s (headSha %s) when a concurrent rejection lands first, and writes nothing",
      async (route, headSha) => {
        const prefix = `HX${route === "PATCH" ? "P" : "C"}${headSha ? "S" : "N"}`;
        const seeded = await seedCompany(prefix);
        const { issueId, stageId } = await seedPendingReview({
          companyId: seeded.companyId,
          identifier: `${prefix}-1`,
          participant: { type: "agent", agentId: seeded.reviewerAgentId },
          returnAgentId: seeded.coderAgentId,
        });
        const runId = await seedRun(seeded.companyId, seeded.reviewerAgentId, issueId);
        const concurrentDecisionId = randomUUID();
        const concurrentState = {
          status: "changes_requested",
          currentStageId: stageId,
          currentStageIndex: 0,
          currentStageType: "review",
          currentParticipant: { type: "agent", agentId: seeded.reviewerAgentId },
          returnAssignee: { type: "agent", agentId: seeded.coderAgentId },
          completedStageIds: [],
          lastDecisionId: concurrentDecisionId,
          lastDecisionOutcome: "changes_requested",
        };
        const countsBefore = await writeCounts();

        const racingApp = appWithConcurrentWrite(
          agentActor(seeded.companyId, seeded.reviewerAgentId, runId),
          async () => {
            await db
              .update(issues)
              .set({ status: "in_progress", assigneeAgentId: seeded.coderAgentId, executionState: concurrentState })
              .where(eq(issues.id, issueId));
          },
        );
        const extra = headSha ? { headSha } : {};
        const res = route === "PATCH"
          ? await request(racingApp).patch(`/api/issues/${issueId}`).send({ status: "done", comment: "Approved.", ...extra })
          : await request(racingApp)
            .post(`/api/issues/${issueId}/comments`)
            .send({ body: "kind: review\ndecision: approved", ...extra });

        expect(res.status, JSON.stringify(res.body)).toBe(409);
        expect(res.body).toMatchObject({ details: { code: "execution_state_changed" } });
        expect(await decisionRows(issueId)).toEqual([]);
        const after = await issueRow(issueId);
        expect(after.status).toBe("in_progress");
        expect(after.assigneeAgentId).toBe(seeded.coderAgentId);
        expect(after.executionState).toEqual(concurrentState);
        expect(await writeCounts()).toEqual(countsBefore);
      },
    );
  });

  describe("a decision recomputed from the locked row", () => {
    const routes = ["PATCH", "review-approval comment"] as const;

    async function seedRace(prefix: string) {
      const seeded = await seedCompany(prefix);
      const review = await seedPendingReview({
        companyId: seeded.companyId,
        identifier: `${prefix}-1`,
        participant: { type: "agent", agentId: seeded.reviewerAgentId },
        returnAgentId: seeded.coderAgentId,
      });
      const runId = await seedRun(seeded.companyId, seeded.reviewerAgentId, review.issueId);
      return { seeded, ...review, runId };
    }

    function approve(route: (typeof routes)[number], racingApp: express.Express, issueId: string) {
      return route === "PATCH"
        ? request(racingApp).patch(`/api/issues/${issueId}`).send({ status: "done", comment: "Approved.", headSha: SHA_A })
        : request(racingApp)
          .post(`/api/issues/${issueId}/comments`)
          .send({ body: "kind: review\ndecision: approved", headSha: SHA_A });
    }

    // Chosen behaviour: a concurrent policy change that adds an approval stage
    // makes the recomputed outcome differ from the one the request was
    // validated with (the issue would move to the approval stage instead of
    // closing), so the stale approval is refused with 409 rather than
    // silently re-routed; the reviewer decides again on the new policy.
    it.each(routes)("refuses with 409 when only the policy changed to add an approval stage (%s)", async (route) => {
      const prefix = route === "PATCH" ? "HQPP" : "HQPC";
      const { seeded, issueId, stageId, runId } = await seedRace(prefix);
      const before = await issueRow(issueId);
      const widenedPolicy = {
        ...(before.executionPolicy as Record<string, unknown>),
        stages: [
          ...((before.executionPolicy as { stages: unknown[] }).stages),
          {
            id: randomUUID(),
            type: "approval",
            approvalsNeeded: 1,
            participants: [{ id: randomUUID(), type: "user", userId: seeded.memberUserId }],
          },
        ],
      };
      const countsBefore = await writeCounts();
      const racingApp = appWithConcurrentWrite(
        agentActor(seeded.companyId, seeded.reviewerAgentId, runId),
        async () => {
          await db.update(issues).set({ executionPolicy: widenedPolicy }).where(eq(issues.id, issueId));
        },
      );

      const res = await approve(route, racingApp, issueId);
      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(res.body).toMatchObject({ details: { code: "execution_state_changed" } });
      expect(await decisionRows(issueId)).toEqual([]);
      const after = await issueRow(issueId);
      expect(after.status).toBe("in_review");
      expect(after.executionPolicy).toEqual(widenedPolicy);
      expect(after.executionState).toEqual(before.executionState);
      expect((after.executionState as { currentStageId: string }).currentStageId).toBe(stageId);
      expect(await writeCounts()).toEqual(countsBefore);
    });

    it.each(routes)("refuses with 409 when only the stage participant changed (%s)", async (route) => {
      const prefix = route === "PATCH" ? "HQAP" : "HQAC";
      const { seeded, issueId, runId } = await seedRace(prefix);
      const before = await issueRow(issueId);
      const reassignedState = {
        ...(before.executionState as Record<string, unknown>),
        currentParticipant: { type: "agent", agentId: seeded.coderAgentId },
      };
      const countsBefore = await writeCounts();
      const racingApp = appWithConcurrentWrite(
        agentActor(seeded.companyId, seeded.reviewerAgentId, runId),
        async () => {
          await db
            .update(issues)
            .set({ assigneeAgentId: seeded.coderAgentId, executionState: reassignedState })
            .where(eq(issues.id, issueId));
        },
      );

      const res = await approve(route, racingApp, issueId);
      expect(res.status, JSON.stringify(res.body)).toBe(409);
      expect(res.body).toMatchObject({ details: { code: "execution_state_changed" } });
      expect(await decisionRows(issueId)).toEqual([]);
      const after = await issueRow(issueId);
      expect(after.assigneeAgentId).toBe(seeded.coderAgentId);
      expect(after.executionState).toEqual(reassignedState);
      expect(await writeCounts()).toEqual(countsBefore);
    });

    it.each(routes)("records the approval normally after a concurrent title edit (%s)", async (route) => {
      const prefix = route === "PATCH" ? "HQTP" : "HQTC";
      const { seeded, issueId, stageId, runId } = await seedRace(prefix);
      const racingApp = appWithConcurrentWrite(
        agentActor(seeded.companyId, seeded.reviewerAgentId, runId),
        async () => {
          await db.update(issues).set({ title: "Renamed concurrently" }).where(eq(issues.id, issueId));
        },
      );

      const res = await approve(route, racingApp, issueId);
      expect(res.status, JSON.stringify(res.body)).toBe(route === "PATCH" ? 200 : 201);
      const [row] = await decisionRows(issueId);
      expect(row).toMatchObject({ stageId, outcome: "approved", headSha: SHA_A });
      const after = await issueRow(issueId);
      expect(after.title).toBe("Renamed concurrently");
      expect(after.status).toBe("done");
      expect(after.executionState).toMatchObject({ lastDecisionId: row!.id, lastDecisionHeadSha: SHA_A });
    });
  });

  it("carries the sha from a review stage into the approval stage of a review→approval policy", async () => {
    const seeded = await seedCompany("HMS");
    const issueId = randomUUID();
    const reviewStageId = randomUUID();
    const approvalStageId = randomUUID();
    // The approver must be an active company member to be assigned the stage.
    const approverUserId = seeded.memberUserId;
    await db.insert(issues).values({
      id: issueId,
      companyId: seeded.companyId,
      identifier: "HMS-1",
      title: "HMS-1",
      status: "in_review",
      priority: "medium",
      assigneeAgentId: seeded.reviewerAgentId,
      executionPolicy: {
        mode: "normal",
        commentRequired: true,
        stages: [
          {
            id: reviewStageId,
            type: "review",
            approvalsNeeded: 1,
            participants: [{ id: randomUUID(), type: "agent", agentId: seeded.reviewerAgentId }],
          },
          {
            id: approvalStageId,
            type: "approval",
            approvalsNeeded: 1,
            participants: [{ id: randomUUID(), type: "user", userId: approverUserId }],
          },
        ],
      },
      executionState: {
        status: "pending",
        currentStageId: reviewStageId,
        currentStageIndex: 0,
        currentStageType: "review",
        currentParticipant: { type: "agent", agentId: seeded.reviewerAgentId },
        returnAssignee: { type: "agent", agentId: seeded.coderAgentId },
        completedStageIds: [],
        lastDecisionId: null,
        lastDecisionOutcome: null,
      },
    });

    const reviewed = await reviewerPatch(seeded, issueId, { status: "done", comment: "Review passed.", headSha: SHA_A });
    expect(reviewed.status, JSON.stringify(reviewed.body)).toBe(200);
    expect(reviewed.body.executionState).toMatchObject({
      status: "pending",
      currentStageId: approvalStageId,
      currentStageType: "approval",
      lastDecisionOutcome: "approved",
      lastDecisionHeadSha: SHA_A,
    });

    const approved = await request(app(boardActor(seeded.companyId, approverUserId)))
      .patch(`/api/issues/${issueId}`)
      .send({ status: "done", comment: "Approved for release.", headSha: SHA_B });
    expect(approved.status, JSON.stringify(approved.body)).toBe(200);
    expect(approved.body.executionState).toMatchObject({ status: "completed", lastDecisionHeadSha: SHA_B });

    const listed = await listDecisions(boardActor(seeded.companyId, seeded.memberUserId), issueId);
    expect(listed.body.map((entry: { stageId: string; stageType: string; headSha: string }) => [
      entry.stageId,
      entry.stageType,
      entry.headSha,
    ])).toEqual([
      [reviewStageId, "review", SHA_A],
      [approvalStageId, "approval", SHA_B],
    ]);
  });

  it("stores headSha on a changes_requested decision recorded by a recovery-action resolution", async () => {
    // A board actor resolving to todo/blocked takes the board override and
    // records no decision, so the deciding participant here is the reviewer agent.
    const seeded = await seedCompany("HRQ");
    const { issueId } = await seedPendingReview({
      companyId: seeded.companyId,
      identifier: "HRQ-1",
      participant: { type: "agent", agentId: seeded.reviewerAgentId },
      returnAgentId: seeded.coderAgentId,
    });
    const action = await seedRecoveryAction(seeded.companyId, issueId, seeded.reviewerAgentId);
    const runId = await seedRun(seeded.companyId, seeded.reviewerAgentId, issueId);

    const res = await request(app(agentActor(seeded.companyId, seeded.reviewerAgentId, runId)))
      .post(`/api/issues/${issueId}/recovery-actions/resolve`)
      .send({
        actionId: action.id,
        outcome: "restored",
        sourceIssueStatus: "todo",
        resolutionNote: "Changes requested on this head.",
        headSha: SHA_A,
      });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const [row] = await decisionRows(issueId);
    expect(row).toMatchObject({ outcome: "changes_requested", actorAgentId: seeded.reviewerAgentId, headSha: SHA_A });
    expect((await issueRow(issueId)).executionState).toMatchObject({
      lastDecisionOutcome: "changes_requested",
      lastDecisionHeadSha: SHA_A,
    });
    const resolvedActivity = (await activityRows(issueId)).find(
      (entry) => entry.action === "issue.recovery_action_resolved",
    );
    expect((resolvedActivity?.details as Record<string, unknown>).executionDecision).toEqual({
      id: row!.id,
      stageId: row!.stageId,
      outcome: "changes_requested",
      headSha: SHA_A,
    });
  });

  it.each([
    ["omitted", {}],
    ["explicit null", { headSha: null }],
  ])("stores null when headSha is %s", async (_label, extra) => {
    const seeded = await seedCompany(_label === "omitted" ? "HOM" : "HNL");
    const { issueId } = await seedPendingReview({
      companyId: seeded.companyId,
      identifier: `${_label === "omitted" ? "HOM" : "HNL"}-1`,
      participant: { type: "agent", agentId: seeded.reviewerAgentId },
      returnAgentId: seeded.coderAgentId,
    });

    const res = await reviewerPatch(seeded, issueId, { status: "done", comment: "Approved.", ...extra });
    expect(res.status, JSON.stringify(res.body)).toBe(200);
    const [row] = await decisionRows(issueId);
    expect(row).toMatchObject({ outcome: "approved", headSha: null });
    expect((await issueRow(issueId)).executionState).toMatchObject({ lastDecisionHeadSha: null });
  });

  it.each([
    ["39 characters", "a".repeat(39)],
    ["41 characters", "a".repeat(41)],
    ["uppercase hex", "A".repeat(40)],
    ["non-hex characters", "g".repeat(40)],
  ])("rejects a malformed headSha (%s) with 400 and records no decision", async (_label, headSha) => {
    const seeded = await seedCompany("HBD");
    const { issueId } = await seedPendingReview({
      companyId: seeded.companyId,
      identifier: "HBD-1",
      participant: { type: "agent", agentId: seeded.reviewerAgentId },
      returnAgentId: seeded.coderAgentId,
    });

    const res = await reviewerPatch(seeded, issueId, { status: "done", comment: "Approved.", headSha });
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    expect(await decisionRows(issueId)).toEqual([]);
    expect((await issueRow(issueId)).status).toBe("in_review");
  });

  it("stores headSha from a recovery-action resolution that decides the stage", async () => {
    const seeded = await seedCompany("HRA");
    const operatorUserId = "local-board";
    const { issueId } = await seedPendingReview({
      companyId: seeded.companyId,
      identifier: "HRA-1",
      participant: { type: "user", userId: operatorUserId },
      returnAgentId: seeded.coderAgentId,
    });
    const action = await seedRecoveryAction(seeded.companyId, issueId, seeded.reviewerAgentId);

    const res = await request(app({ type: "board", source: "local_implicit", userId: operatorUserId }))
      .post(`/api/issues/${issueId}/recovery-actions/resolve`)
      .send({
        actionId: action.id,
        outcome: "restored",
        sourceIssueStatus: "done",
        resolutionNote: "Reviewed the head and approved it.",
        headSha: SHA_B,
      });
    expect(res.status, JSON.stringify(res.body)).toBe(200);

    const [row] = await decisionRows(issueId);
    expect(row).toMatchObject({ outcome: "approved", actorUserId: operatorUserId, headSha: SHA_B });
    expect((await issueRow(issueId)).executionState).toMatchObject({ lastDecisionId: row!.id, lastDecisionHeadSha: SHA_B });
  });

  it("rejects a malformed headSha on the strict recovery-action resolution schema", async () => {
    const seeded = await seedCompany("HRB");
    const { issueId } = await seedPendingReview({
      companyId: seeded.companyId,
      identifier: "HRB-1",
      participant: { type: "user", userId: "local-board" },
      returnAgentId: seeded.coderAgentId,
    });

    const res = await request(app({ type: "board", source: "local_implicit", userId: "local-board" }))
      .post(`/api/issues/${issueId}/recovery-actions/resolve`)
      .send({ outcome: "restored", sourceIssueStatus: "done", headSha: "not-a-sha" });
    expect(res.status, JSON.stringify(res.body)).toBe(400);
    // The strict schema knows the field: the 400 is the format rule, not an unknown key.
    expect(JSON.stringify(res.body)).toContain("headSha must be a full lowercase hex commit SHA");
    expect(await decisionRows(issueId)).toEqual([]);
  });

  it("stores headSha from a review-approval comment that auto-approves the stage", async () => {
    const seeded = await seedCompany("HCM");
    const { issueId } = await seedPendingReview({
      companyId: seeded.companyId,
      identifier: "HCM-1",
      participant: { type: "agent", agentId: seeded.reviewerAgentId },
      returnAgentId: seeded.coderAgentId,
    });
    const runId = await seedRun(seeded.companyId, seeded.reviewerAgentId, issueId);

    const res = await request(app(agentActor(seeded.companyId, seeded.reviewerAgentId, runId)))
      .post(`/api/issues/${issueId}/comments`)
      .send({ body: "kind: review\ndecision: approved", headSha: SHA_A });
    expect(res.status, JSON.stringify(res.body)).toBe(201);

    const [row] = await decisionRows(issueId);
    expect(row).toMatchObject({ outcome: "approved", actorAgentId: seeded.reviewerAgentId, headSha: SHA_A });
    const issue = await issueRow(issueId);
    expect(issue.status).toBe("done");
    expect(issue.executionState).toMatchObject({ lastDecisionId: row!.id, lastDecisionHeadSha: SHA_A });
    expect(await decisionActivity(issueId)).toContainEqual({
      id: row!.id,
      stageId: row!.stageId,
      outcome: "approved",
      headSha: SHA_A,
    });
  });

  it("lists every round in order with its headSha, rejected rounds included, and keeps the sha across state transitions", async () => {
    const seeded = await seedCompany("HRD");
    const { issueId, stageId } = await seedPendingReview({
      companyId: seeded.companyId,
      identifier: "HRD-1",
      participant: { type: "agent", agentId: seeded.reviewerAgentId },
      returnAgentId: seeded.coderAgentId,
    });

    // The coder's run exists before the stage hands the issue back, so the
    // returned-work wake coalesces into it instead of racing a new run.
    const coderRunId = await seedRun(seeded.companyId, seeded.coderAgentId, issueId);
    const rejected = await reviewerPatch(seeded, issueId, {
      status: "in_progress",
      comment: "Changes requested.",
      headSha: SHA_A,
    });
    expect(rejected.status, JSON.stringify(rejected.body)).toBe(200);
    expect(rejected.body).toMatchObject({ status: "in_progress", assigneeAgentId: seeded.coderAgentId });
    expect(rejected.body.executionState).toMatchObject({
      status: "changes_requested",
      lastDecisionOutcome: "changes_requested",
      lastDecisionHeadSha: SHA_A,
    });

    // A status change that records no decision keeps the last decision's sha.
    const resubmitted = await request(app(agentActor(seeded.companyId, seeded.coderAgentId, coderRunId)))
      .patch(`/api/issues/${issueId}`)
      .send({ status: "in_review", comment: "Addressed the review." });
    expect(resubmitted.status, JSON.stringify(resubmitted.body)).toBe(200);
    expect(resubmitted.body.executionState).toMatchObject({
      status: "pending",
      lastDecisionOutcome: "changes_requested",
      lastDecisionHeadSha: SHA_A,
    });
    expect(await decisionRows(issueId)).toHaveLength(1);

    const approved = await reviewerPatch(seeded, issueId, { status: "done", comment: "Approved.", headSha: SHA_B });
    expect(approved.status, JSON.stringify(approved.body)).toBe(200);
    expect(approved.body.executionState).toMatchObject({ lastDecisionOutcome: "approved", lastDecisionHeadSha: SHA_B });

    const listed = await listDecisions(boardActor(seeded.companyId, seeded.memberUserId), issueId);
    expect(listed.status, JSON.stringify(listed.body)).toBe(200);
    expect(listed.body.map((entry: { stageId: string; outcome: string; headSha: string | null }) => ({
      stageId: entry.stageId,
      outcome: entry.outcome,
      headSha: entry.headSha,
    }))).toEqual([
      { stageId, outcome: "changes_requested", headSha: SHA_A },
      { stageId, outcome: "approved", headSha: SHA_B },
    ]);
    expect(listed.body.at(-1).headSha).toBe(SHA_B);
  });

  it("clears lastDecisionHeadSha when a newer decision carries no headSha", async () => {
    const seeded = await seedCompany("HCL");
    const { issueId } = await seedPendingReview({
      companyId: seeded.companyId,
      identifier: "HCL-1",
      participant: { type: "agent", agentId: seeded.reviewerAgentId },
      returnAgentId: seeded.coderAgentId,
    });

    const coderRunId = await seedRun(seeded.companyId, seeded.coderAgentId, issueId);
    await reviewerPatch(seeded, issueId, { status: "in_progress", comment: "Changes requested.", headSha: SHA_A })
      .then((res) => expect(res.status, JSON.stringify(res.body)).toBe(200));
    await request(app(agentActor(seeded.companyId, seeded.coderAgentId, coderRunId)))
      .patch(`/api/issues/${issueId}`)
      .send({ status: "in_review", comment: "Addressed the review." })
      .then((res) => expect(res.status, JSON.stringify(res.body)).toBe(200));
    expect((await issueRow(issueId)).executionState).toMatchObject({ lastDecisionHeadSha: SHA_A });

    const approved = await reviewerPatch(seeded, issueId, { status: "done", comment: "Approved." });
    expect(approved.status, JSON.stringify(approved.body)).toBe(200);
    expect(approved.body.executionState).toMatchObject({ lastDecisionOutcome: "approved", lastDecisionHeadSha: null });
    expect((await decisionRows(issueId)).map((row) => row.headSha)).toEqual([SHA_A, null]);
  });

  it("orders decisions with the same createdAt by id, stably, and reads rows without headSha as null", async () => {
    const seeded = await seedCompany("HTI");
    const { issueId, stageId } = await seedPendingReview({
      companyId: seeded.companyId,
      identifier: "HTI-1",
      participant: { type: "agent", agentId: seeded.reviewerAgentId },
      returnAgentId: seeded.coderAgentId,
    });
    const createdAt = new Date("2026-10-15T12:00:00.000Z");
    const lowId = "00000000-0000-4000-8000-000000000001";
    const highId = "ffffffff-ffff-4fff-bfff-ffffffffffff";
    // Inserted high id first, and the legacy-shaped row omits head_sha the way
    // rows written before migration 0307 do.
    await db.insert(issueExecutionDecisions).values([
      {
        id: highId,
        companyId: seeded.companyId,
        issueId,
        stageId,
        stageType: "review",
        actorAgentId: seeded.reviewerAgentId,
        outcome: "approved",
        body: "Second by id.",
        headSha: SHA_B,
        createdAt,
      },
      {
        id: lowId,
        companyId: seeded.companyId,
        issueId,
        stageId,
        stageType: "review",
        actorAgentId: seeded.reviewerAgentId,
        outcome: "changes_requested",
        body: "First by id.",
        createdAt,
      },
    ]);

    const actor = boardActor(seeded.companyId, seeded.memberUserId);
    const first = await listDecisions(actor, issueId);
    const second = await listDecisions(actor, issueId);
    expect(first.status, JSON.stringify(first.body)).toBe(200);
    expect(first.body.map((entry: { id: string }) => entry.id)).toEqual([lowId, highId]);
    expect(second.body).toEqual(first.body);
    expect(first.body[0]).toMatchObject({ id: lowId, headSha: null });
  });

  it("keeps the decision list behind company access", async () => {
    const seeded = await seedCompany("HAC");
    const foreign = await seedCompany("HFX");
    const { issueId } = await seedPendingReview({
      companyId: seeded.companyId,
      identifier: "HAC-1",
      participant: { type: "agent", agentId: seeded.reviewerAgentId },
      returnAgentId: seeded.coderAgentId,
    });

    const own = await listDecisions(boardActor(seeded.companyId, seeded.memberUserId), issueId);
    expect(own.status, JSON.stringify(own.body)).toBe(200);
    expect(own.body).toEqual([]);

    const crossCompany = await listDecisions(boardActor(foreign.companyId, foreign.memberUserId), issueId);
    expect(crossCompany.status).toBe(404);
  });
});
