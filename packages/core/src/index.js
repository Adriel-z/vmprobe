/**
 * VMProbe 核心层出口。零 DSH 依赖 —— 因此可以在没有 DSH 的环境里单测与复用（CLI 也走这里）。
 */

export {
  Risk,
  DEFAULT_POLICY,
  maxRisk,
  decideApproval,
  buildApprovalReason,
} from './risk.js';

export {
  GENESIS,
  ALGO_SHA256,
  ALGO_HMAC,
  canonicalJson,
  hashRecord,
  sha256Hex,
  chainRecord,
  tailHash,
  verifyChain,
  createAuditLog,
  generateAuditKey,
  keyIdOf,
} from './audit.js';

export {
  crc32,
  zipCreate,
  zipRead,
  zipEntry,
  ZipError,
} from './zip.js';

export {
  ARCHIVE_SCHEMA,
  MANIFEST_NAME,
  SECRETS_NAME,
  NEVER_ARCHIVE,
  SECRET_PATHS,
  REDACTION_LEVELS,
  redactValue,
  collectEntries,
  encryptSecrets,
  decryptSecrets,
  exportArchive,
  readArchive,
  diffArchive,
  applyImport,
} from './archive.js';

export {
  assertSecretFree,
  isSecretKeyName,
  assertSafeId,
  openStore,
  makeTarget,
  writeJsonAtomic,
} from './store.js';

export { redactText, redactDeep, createRedactor } from './redact.js';

export { validateParams, normalizeParams, findUnwiredParams } from './params.js';

export { extractMetrics, buildDailyReport, reportNeedsAttention } from './report-builder.js';

export {
  REPORT_SCHEMA,
  dayKey,
  assertDayKey,
  reportDir,
  reportPath,
  writeReport,
  readDay,
  listDays,
  latestReport,
  findGaps,
  pruneReports,
  buildTrend,
} from './reports.js';

export {
  buildPlan,
  resolveRiskFromAction,
  resolveCommands,
  summarizePlan,
  PLAN_TTL_MS,
  checkFingerprint,
  checkPlanFreshness,
} from './plan.js';
