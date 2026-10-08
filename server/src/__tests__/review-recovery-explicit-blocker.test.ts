/**
 * CAP-11 (paperclipai/paperclip#14822): a review-participant recovery that
 * ended `succeeded` without a decision must not block an issue that is
 * explicitly waiting on an unresolved blocker.
 *
 * The four cases are the acceptance of the local fix
 * (`integrations/paperclip/local-fixes/review-recovery-explicit-blocker/`).
 * This file is NOT part of `source.patch` on purpose: with the patch reverted
 * and this suite still in place, cases 1, 2 and 4 must fail and case 3 — the
 * negative control — must stay green. That is what proves the gate measures
 * this correction and is not a permanent false positive.
 */
import { randomUUID } from "node:crypto";
import { describe, expect, it, vi, beforeAll, afterAll, afterEach } from "vitest";
import { eq } from "drizzle-orm";
import {
  agents,
  agentWakeupRequests,
  authUsers,
  companies,
  createDb,
  heartbeatRuns,
  issueRelations,
  issues,
} from "@paperclipai/db";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";
import { decideReleaseRecovery } from "../modules/wake-queue/domain/policy.js";
import { createReleaseIssueExecution } from "../modules/wake-queue/application/use-cases.js";
import type {
  InvokableAgentSnapshot,
  IssueSnapshot,
  RunSnapshot,
  WakeQueueHost,
  WakeQueueTransaction,
} from "../modules/wake-queue/application/ports.js";
import { recoveryService } from "../services/recovery/service.js";

const embeddedPostgresSupport = await getEmbeddedPostgresTestSupport();
const describeEmbeddedPostgres = embeddedPostgresSupport.supported
  ? describe
  : describe.skip;

const REVIEWER_AGENT_ID = "review-agent";
const WAKE_REASON = "execution_review_participant_recovery";

/** A review-participant recovery run that finished `succeeded` with no decision. */
function reviewRecoveryRun(overrides: Partial<RunSnapshot> = {}): RunSnapshot {
  return {
    id: "run-1",
    companyId: "company-1",
    agentId: REVIEWER_AGENT_ID,
    status: "succeeded",
    runtimeMode: "process",
    errorCode: null,
    responsibleUserId: "user-1",
    // `retryReason` is what makes this run a review-participant recovery run,
    // and `succeeded` is what used to fall straight into `blocked`.
    contextSnapshot: {
      issueId: "issue-1",
      taskId: "issue-1",
      wakeReason: WAKE_REASON,
      retryReason: WAKE_REASON,
    },
    configurationIncompletePayload: null,
    ...overrides,
  };
}

/**
 * The same branch, but the very first review wake: `wakeReason`
 * `execution_review_requested` and NO retry reason, so it is not a
 * review-participant recovery run.
 */
function firstReviewWakeRun(overrides: Partial<RunSnapshot> = {}): RunSnapshot {
  return {
    ...reviewRecoveryRun(overrides),
    id: "run-first-review",
    contextSnapshot: {
      issueId: "issue-1",
      taskId: "issue-1",
      wakeReason: "execution_review_requested",
    },
  };
}

/** The same issue, `in_review`, waiting on the finishing run as its participant. */
function inReviewIssue(overrides: Partial<IssueSnapshot> = {}): IssueSnapshot {
  return {
    id: "issue-1",
    companyId: "company-1",
    identifier: "ISSUE-1",
    status: "in_review",
    assigneeAgentId: REVIEWER_AGENT_ID,
    assigneeUserId: null,
    hiddenAt: null,
    originKind: null,
    monitorNextCheckAt: null,
    executionState: {
      status: "pending",
      currentStageId: "stage-1",
      currentStageIndex: 0,
      currentStageType: "review",
      currentParticipant: {
        type: "agent",
        agentId: REVIEWER_AGENT_ID,
        userId: null,
      },
      returnAssignee: {
        type: "agent",
        agentId: REVIEWER_AGENT_ID,
        userId: null,
      },
      reviewRequest: null,
      completedStageIds: [],
      lastDecisionId: null,
      lastDecisionOutcome: null,
    },
    responsibleUserId: null,
    parentId: null,
    originId: null,
    originRunId: null,
    ...overrides,
  };
}

const RECOVERY_AGENT: InvokableAgentSnapshot = {
  id: "review-agent",
  companyId: "company-1",
  name: "Reviewer",
  invokable: true,
};

function fakeHost(): WakeQueueHost {
  return {
    resolveResponsibleUserId: vi.fn(async () => "user-1"),
    getRoutineEnv: vi.fn(async () => ({
      routineId: null,
      env: null,
      responsibleUserId: null,
    })),
    resolveSessionBeforeForWakeup: vi.fn(async () => null),
  };
}

function fakeTransaction(overrides: Partial<WakeQueueTransaction> = {}): WakeQueueTransaction {
  const runSummary = {
    id: "queued-recovery",
    companyId: "company-1",
    agentId: REVIEWER_AGENT_ID,
    invocationSource: "automation" as const,
    triggerDetail: null,
    wakeupRequestId: "wakeup-queued-recovery",
  };
  return {
    findInvokableAgent: vi.fn(async () => RECOVERY_AGENT),
    findNextDeferredWake: vi.fn(async () => null),
    getQueuedCommentLiveness: vi.fn(async () => ({
      liveNonSelfCommentIds: [],
      containedSelfAuthoredComment: false,
    })),
    cancelDeferredWake: vi.fn(async () => true),
    normalizeDeferredWakeCommentIds: vi.fn(async () => {
      throw new Error("not reached in this suite");
    }),
    failDeferredWake: vi.fn(async () => true),
    getPauseHoldFacts: vi.fn(async () => ({
      activePauseHold: false,
      treeHoldInteractionWake: false,
      holdId: null,
      rootIssueId: null,
      mode: null,
      reason: null,
      releasePolicy: null,
    })),
    getCommentSelfAuthorship: vi.fn(async () => ({ allSelfAuthored: false })),
    isCompletedDelegationMention: vi.fn(async () => false),
    reopenIssue: vi.fn(async () => null),
    claimDeferredWakeForPromotion: vi.fn(async () => true),
    finalizePromotedWake: vi.fn(async () => runSummary),
    hasExistingExecutionPath: vi.fn(async () => false),
    hasExplicitBlockerPath: vi.fn(async () => false),
    isAutomaticRecoverySuppressedByPauseHold: vi.fn(async () => false),
    isImmediateRecoverySourceBlocked: vi.fn(async () => false),
    queueReviewParticipantRecoveryRun: vi.fn(async () => runSummary),
    queueImmediateRecoveryRun: vi.fn(async () => runSummary),
    ...overrides,
  };
}

function releaseWith(
  transaction: WakeQueueTransaction,
  issue: IssueSnapshot,
  run: RunSnapshot,
) {
  const host = fakeHost();
  const release = createReleaseIssueExecution({
    issueLock: {
      withIssueExecutionLock: vi.fn(async (_input, fn) => {
        const result = await fn({ primaryIssue: issue, run }, { host, transaction });
        return { ...result, run };
      }),
    } as never,
    recovery: {
      escalateStrandedAssignedIssue: vi.fn(async () => {}),
      escalateStrandedRecoveryIssueInPlace: vi.fn(async () => {}),
    } as never,
  });
  return release({ companyId: run.companyId, runId: run.id, now: new Date() });
}

describe("decideReleaseRecovery, review-participant branch (CAP-11)", () => {
  const baseFacts = {
    suppressImmediateRecovery: false,
    reviewParticipant: {
      applies: true,
      isExecutionReviewParticipantRecoveryRun: true,
    },
    immediate: {
      applies: false,
      isDispositionRepairRetry: false,
      hasExplicitBlockerPath: false,
      isWorkspaceValidationFailedRun: false,
      isConfigurationIncompleteFailedRun: false,
      automaticRecoveryAlreadyFailed: false,
    },
    shared: {
      hasExistingExecutionPath: false,
      hasPersistedMonitor: false,
      suppressedByPauseHold: false,
      isStrandedRecoveryOrigin: false,
      recoveryAgentPresent: true,
      recoveryAgentInvokable: true,
    },
  };

  // Case 1. Without the patch this is `blocked` /
  // `execution_review_participant`, and only the board could free the issue.
  it("releases a review recovery that succeeded with no decision when a blocker is still open", () => {
    const decision = decideReleaseRecovery({
      ...baseFacts,
      reviewParticipant: {
        ...baseFacts.reviewParticipant,
        hasExplicitBlockerPath: true,
        participantRunSucceeded: true,
      },
    });

    expect(decision).toEqual({ kind: "released" });
  });

  // Case 3, the negative control. Green with and without the patch on purpose:
  // it proves the guard is scoped to the blocker, not a blanket release.
  it("keeps blocking a review recovery that succeeded with no decision when no blocker is open", () => {
    const decision = decideReleaseRecovery({
      ...baseFacts,
      reviewParticipant: {
        ...baseFacts.reviewParticipant,
        hasExplicitBlockerPath: false,
        participantRunSucceeded: true,
      },
    });

    expect(decision).toEqual({
      kind: "blocked",
      notice: "execution_review_participant",
    });
  });

  // Cases 5 and 6, the scope the first review of !517 demanded. The review
  // branch admits ANY terminal status, so an open blocker alone is not enough:
  // only a `succeeded` participant run is the reviewer's answer. A `failed` or
  // `cancelled` one is a failure to retry, and the native `blocked` is what
  // recovers it. Green with and without the patch on purpose — they are the
  // regression pair for the guard's scope, not part of the 1/2/4 red set.
  it("keeps the native blocked outcome for a failed participant run even with a blocker open", () => {
    const decision = decideReleaseRecovery({
      ...baseFacts,
      reviewParticipant: {
        ...baseFacts.reviewParticipant,
        hasExplicitBlockerPath: true,
        participantRunSucceeded: false,
      },
    });

    expect(decision).toEqual({
      kind: "blocked",
      notice: "execution_review_participant",
    });
  });

  it("keeps the native blocked outcome for a cancelled participant run even with a blocker open", () => {
    const decision = decideReleaseRecovery({
      ...baseFacts,
      reviewParticipant: {
        ...baseFacts.reviewParticipant,
        hasExplicitBlockerPath: true,
        participantRunSucceeded: false,
      },
    });

    expect(decision).toEqual({
      kind: "blocked",
      notice: "execution_review_participant",
    });
  });

  // Case 9: the scope the second review of !517 demanded. The review branch
  // also admits terminal runs whose `wakeReason` is `execution_review_requested`
  // or `execution_approval_requested` with no retry reason — the very first
  // review wake, not a recovery. Natively those fall through to
  // `queue_review_participant_recovery`; a guard on blocker + `succeeded` alone
  // released them too.
  it("keeps the native queue decision for a first review wake that is not a recovery run", () => {
    const decision = decideReleaseRecovery({
      ...baseFacts,
      reviewParticipant: {
        ...baseFacts.reviewParticipant,
        isExecutionReviewParticipantRecoveryRun: false,
        hasExplicitBlockerPath: true,
        participantRunSucceeded: true,
      },
    });

    expect(decision).toEqual({ kind: "queue_review_participant_recovery" });
  });
});

describe("releaseIssueExecution, review-participant branch (CAP-11)", () => {
  // Case 2. The end-to-end shape of the UMA-1508 timeline: the issue is in
  // review, a blocker is open, the recovery run ends `succeeded` with no
  // decision, and the issue must stay `in_review`.
  it("keeps the issue in review when the review recovery succeeded behind an open blocker", async () => {
    const transaction = fakeTransaction({
      hasExplicitBlockerPath: vi.fn(async () => true),
    });

    const result = await releaseWith(transaction, inReviewIssue(), reviewRecoveryRun());

    expect(result.outcome.kind).toBe("released");
    expect(transaction.queueReviewParticipantRecoveryRun).not.toHaveBeenCalled();
  });

  it("blocks the issue when the same recovery succeeded with no open blocker", async () => {
    const transaction = fakeTransaction({
      hasExplicitBlockerPath: vi.fn(async () => false),
    });

    const result = await releaseWith(transaction, inReviewIssue(), reviewRecoveryRun());

    expect(result.outcome.kind).toBe("blocked");
  });

  // Cases 7 and 8: the same pair at the real call site, where the status is
  // what decides the conjunct. Without the `participantRunSucceeded` wiring a
  // future change can widen the guard again and these two go red.
  it("keeps the native blocked outcome for a failed participant run behind an open blocker", async () => {
    const transaction = fakeTransaction({
      hasExplicitBlockerPath: vi.fn(async () => true),
    });

    const result = await releaseWith(
      transaction,
      inReviewIssue(),
      reviewRecoveryRun({ status: "failed" }),
    );

    // The native blocked transition, not the release the guard gives a
    // `succeeded` run: same notice kind and previous status as the base.
    expect(result.outcome).toMatchObject({
      kind: "blocked",
      noticeKind: "execution_review_participant",
      previousStatus: "in_review",
    });
    expect(transaction.queueReviewParticipantRecoveryRun).not.toHaveBeenCalled();
  });

  it("keeps the native blocked outcome for a cancelled participant run behind an open blocker", async () => {
    const transaction = fakeTransaction({
      hasExplicitBlockerPath: vi.fn(async () => true),
    });

    const result = await releaseWith(
      transaction,
      inReviewIssue(),
      reviewRecoveryRun({ status: "cancelled" }),
    );

    expect(result.outcome).toMatchObject({
      kind: "blocked",
      noticeKind: "execution_review_participant",
      previousStatus: "in_review",
    });
    expect(transaction.queueReviewParticipantRecoveryRun).not.toHaveBeenCalled();
  });

  // Case 10: the same scope at the real call site. A first review wake that is
  // not a recovery must keep the native outcome, which is to enqueue the review
  // recovery — the guard must not turn an ordinary first review into a release.
  it("keeps the native enqueue for a first review wake behind an open blocker", async () => {
    const transaction = fakeTransaction({
      hasExplicitBlockerPath: vi.fn(async () => true),
    });

    const result = await releaseWith(
      transaction,
      inReviewIssue(),
      firstReviewWakeRun(),
    );

    // The native enqueue, not the release: outcome `queued_…` is what
    // use-cases returns once the policy decided to enqueue.
    expect(result.outcome).toMatchObject({
      kind: "queued_review_participant_recovery",
    });
    expect(transaction.queueReviewParticipantRecoveryRun).toHaveBeenCalledTimes(1);
  });
});

describeEmbeddedPostgres("reconcileStrandedAssignedIssues, in_review branch (CAP-11)", () => {
  let tempDb: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | null = null;
  let db: ReturnType<typeof createDb>;

  beforeAll(async () => {
    tempDb = await startEmbeddedPostgresTestDatabase(
      "paperclip-review-recovery-explicit-blocker-",
    );
    db = createDb(tempDb.connectionString);
  }, 30_000);

  afterEach(async () => {
    await db.delete(issueRelations);
    await db.delete(heartbeatRuns);
    await db.delete(agentWakeupRequests);
    await db.delete(issues);
    await db.delete(agents);
    await db.delete(companies);
    await db.delete(authUsers);
  });

  afterAll(async () => {
    await tempDb?.cleanup();
  });

  async function seedInReviewWithSucceededParticipant(input?: {
    blockerStatus?: "todo" | "done";
  }) {
    const companyId = randomUUID();
    const agentId = randomUUID();
    const runId = randomUUID();
    const wakeupRequestId = randomUUID();
    const issueId = randomUUID();
    const blockerIssueId = randomUUID();
    const stageId = randomUUID();
    const now = new Date("2026-10-01T21:35:00.000Z");
    const finishedAt = new Date("2026-10-01T21:38:00.000Z");
    const prefix = `RB${companyId.replaceAll("-", "").slice(0, 6).toUpperCase()}`;

    await db.insert(companies).values({
      id: companyId,
      name: "Paperclip",
      issuePrefix: prefix,
      defaultResponsibleUserId: "responsible-user",
      requireBoardApprovalForNewAgents: false,
    });
    await db.insert(authUsers).values({
      id: "responsible-user",
      name: "Responsible User",
      email: "responsible-user@example.test",
      emailVerified: true,
      createdAt: now,
      updatedAt: now,
    });
    await db.insert(agents).values({
      id: agentId,
      companyId,
      name: "CodexReviewer",
      role: "engineer",
      status: "idle",
      adapterType: "codex_local",
      adapterConfig: {},
      runtimeConfig: {},
      permissions: {},
    });
    await db.insert(agentWakeupRequests).values({
      id: wakeupRequestId,
      companyId,
      agentId,
      source: "automation",
      triggerDetail: "system",
      reason: WAKE_REASON,
      payload: { issueId },
      status: "completed",
      runId,
      requestedAt: now,
      updatedAt: finishedAt,
      finishedAt,
    });
    await db.insert(heartbeatRuns).values({
      id: runId,
      companyId,
      agentId,
      invocationSource: "automation",
      triggerDetail: "system",
      status: "succeeded",
      wakeupRequestId,
      contextSnapshot: {
        issueId,
        taskId: issueId,
        wakeReason: WAKE_REASON,
        retryReason: WAKE_REASON,
      },
      startedAt: now,
      finishedAt,
      updatedAt: finishedAt,
    });
    await db.insert(issues).values([
      {
        id: issueId,
        companyId,
        title: "Review behind an open blocker",
        status: "in_review",
        priority: "medium",
        assigneeAgentId: agentId,
        assigneeUserId: null,
        executionRunId: runId,
        executionAgentNameKey: "codexreviewer",
        executionLockedAt: now,
        responsibleUserId: "responsible-user",
        issueNumber: 1,
        identifier: `${prefix}-1`,
        executionState: {
          status: "pending",
          currentStageId: stageId,
          currentStageIndex: 0,
          currentStageType: "review",
          currentParticipant: { type: "agent", agentId, userId: null },
          returnAssignee: { type: "agent", agentId, userId: null },
          reviewRequest: null,
          completedStageIds: [],
          lastDecisionId: null,
          lastDecisionOutcome: null,
        },
      },
      {
        id: blockerIssueId,
        companyId,
        title: "The blocker the review is waiting on",
        status: input?.blockerStatus ?? "todo",
        priority: "medium",
        issueNumber: 2,
        identifier: `${prefix}-2`,
      },
    ]);
    await db.insert(issueRelations).values({
      companyId,
      issueId: blockerIssueId,
      relatedIssueId: issueId,
      type: "blocks",
    });

    // The reconciler's prologue already skips an `in_review` issue whose own
    // latest run succeeded while a wait path is persisted. A newer run by
    // ANOTHER agent is what makes the review participant's succeeded run the
    // one the in_review branch has to judge — which is the case this guard
    // exists for.
    const otherAgentId = randomUUID();
    const otherRunId = randomUUID();
    await db.insert(agents).values({
      id: otherAgentId,
      companyId,
      name: "CodexImplementor",
      role: "engineer",
      status: "idle",
      adapterType: "codex_local",
      adapterConfig: {},
      runtimeConfig: {},
      permissions: {},
    });
    await db.insert(heartbeatRuns).values({
      id: otherRunId,
      companyId,
      agentId: otherAgentId,
      invocationSource: "manual",
      triggerDetail: null,
      status: "failed",
      error: "Implementer run failed before the review stage.",
      errorCode: "adapter_failed",
      contextSnapshot: { issueId, taskId: issueId, wakeReason: "issue_commented" },
      startedAt: finishedAt,
      finishedAt: new Date("2026-10-01T21:40:00.000Z"),
      updatedAt: new Date("2026-10-01T21:40:00.000Z"),
    });

    return { companyId, agentId, runId, issueId, blockerIssueId, otherRunId };
  }

  // Case 4. Without the patch the reconciler enqueues a review recovery on
  // every pass, and a `succeeded` recovery never moves the automatic-recovery
  // counter, so the loop is what the issue actually experiences.
  it("does not enqueue a review recovery while the blocker is still open", async () => {
    const { agentId, runId, otherRunId, issueId } =
      await seedInReviewWithSucceededParticipant();
    const enqueueWakeup = vi.fn(async () => null);
    const recovery = recoveryService(db, { enqueueWakeup });

    const result = await recovery.reconcileStrandedAssignedIssues();

    expect(result.reviewParticipantRequeued).toBe(0);
    expect(result.escalated).toBe(0);
    expect(enqueueWakeup).not.toHaveBeenCalled();
    const runs = await db
      .select()
      .from(heartbeatRuns)
      .where(eq(heartbeatRuns.agentId, agentId));
    expect(runs.map((row) => row.id)).toEqual([runId]);
    const [issue] = await db.select().from(issues).where(eq(issues.id, issueId));
    expect(issue?.status).toBe("in_review");
    expect(otherRunId).toBeTruthy();
  });
});
