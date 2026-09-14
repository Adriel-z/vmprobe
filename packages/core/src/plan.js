/**
 * 计划构建 —— plan → approve → apply → verify 里的第一步（DESIGN.md §3 D7）。
 *
 * plan 阶段**只读**：把「将做什么」算清楚（差分、真实 argv、影响面），
 * 以及由运行时事实推导出的最终风险级。审批决策基于 plan 的结果，
 * 而不是基于模型或调用方声明的风险级 —— 这是不可绕过的。
 *
 * ── M0 推演后的加固（每条都对应一个已复现的缺陷）────────────────────────
 *   F1  plan 现在携带 `side`，controller 侧动作不再被误当远端命令。
 *   F2  参数未接线时 **fail-closed 阻断**，而不是静默忽略（防"谎报行为"）。
 *   F5  参数按动作声明的 `params` schema 校验。
 *   F14 无法为发行版解析出命令时 **阻断**，而不是返回空 argv 假装成功。
 */

import { createHash } from 'node:crypto';

import { Risk, decideApproval, maxRisk } from './risk.js';
import { findUnwiredParams, validateParams } from './params.js';
import { canonicalJson } from './audit.js';

const ORDER = ['R0', 'R1', 'R2', 'R3'];

/** plan 的默认有效期。 */
export const PLAN_TTL_MS = 5 * 60 * 1000;

/**
 * check 结果里的**易变字段**：不参与指纹。
 *
 * 取舍说明：这里用**排除法**而不是白名单 —— 新增的 check 字段默认会被纳入指纹，
 * 于是"环境变了"更容易被发现（宁可多要求一次重新计划，也不要静默按旧计划执行）。
 * 代价是：若某个 check 生产者往结果里塞时间戳，会造成"永远过期"。
 * 因此约定：**易变信息放 `note`，不要新增时间戳类字段**。
 */
const VOLATILE_CHECK_FIELDS = new Set([
  'note', 'probedAt', 'checkedAt', 'durationMs', 'elapsedMs', 'ts', 'timestamp',
  'stdout', 'stderr', 'raw', 'probed',
]);

/**
 * 计算 check 结果的状态指纹。
 *
 * 这是 TOCTOU 防护（推演发现 I7）的核心：plan 生成时环境是一个状态，
 * 用户审批期间环境可能已经变了（别人装了包、重启了服务）。
 * 只靠"计划里写着 12 个包要更新"是不够的 —— 必须能在执行前**验证环境是否还是那个环境**。
 *
 * @param {object} checkResult
 * @returns {string|null} 未探测（`probed !== true`）时返回 null，表示"无法验证"
 */
export function checkFingerprint(checkResult) {
  if (!checkResult || typeof checkResult !== 'object') return null;
  if (checkResult.probed !== true) return null;

  const relevant = {};
  for (const [key, val] of Object.entries(checkResult)) {
    if (VOLATILE_CHECK_FIELDS.has(key)) continue;
    relevant[key] = val;
  }
  // 空对象指纹无意义（说明该 check 没有提供任何可比较的状态）
  if (Object.keys(relevant).length === 0) return null;

  return createHash('sha256').update(canonicalJson(relevant)).digest('hex');
}

/**
 * 校验一个 plan 是否仍然"新鲜"。
 *
 * 两道关：**有效期**（时间维度）与**状态指纹**（内容维度）。
 * 注意 `canVerify` 为 false 的情形要由调用方决定策略（agent 侧应 fail-closed）。
 *
 * @param {object} plan
 * @param {object} recheck 重新探测得到的 check 结果
 * @param {{ now?: number }} [options]
 * @returns {{ ok: boolean, reason: string|null, canVerify: boolean, expired: boolean, fingerprintChanged: boolean }}
 */
export function checkPlanFreshness(plan, recheck, options = {}) {
  const now = options.now ?? Date.now();
  const expiresAt = plan?.expiresAt ? Date.parse(plan.expiresAt) : null;

  const expired = expiresAt !== null && Number.isFinite(expiresAt) && now > expiresAt;
  if (expired) {
    const ageSec = Math.round((now - Date.parse(plan.checkedAt)) / 1000);
    return {
      ok: false,
      canVerify: plan.stateFingerprint !== null,
      expired: true,
      fingerprintChanged: false,
      reason: `计划已过期（生成于 ${ageSec} 秒前，有效期 ${plan.ttlMs ?? PLAN_TTL_MS}ms）。环境可能已变化，请重新计划。`,
    };
  }

  if (!plan.stateFingerprint) {
    return {
      ok: false,
      canVerify: false,
      expired: false,
      fingerprintChanged: false,
      reason: '计划生成时未实际探测（check 未执行），因此无法验证环境是否仍然一致。',
    };
  }

  const fresh = checkFingerprint(recheck);
  if (fresh === null) {
    return {
      ok: false,
      canVerify: false,
      expired: false,
      fingerprintChanged: false,
      reason: '执行前重新探测未返回可比对的状态，无法验证计划是否仍然有效。',
    };
  }

  if (fresh !== plan.stateFingerprint) {
    return {
      ok: false,
      canVerify: true,
      expired: false,
      fingerprintChanged: true,
      reason:
        `环境已变化（状态指纹 ${plan.stateFingerprint.slice(0, 12)}… → ${fresh.slice(0, 12)}…）。` +
        '按原计划执行可能与用户批准的内容不一致，请重新计划并重新确认。',
    };
  }

  return { ok: true, reason: null, canVerify: true, expired: false, fingerprintChanged: false };
}

/**
 * 解析动作的基线风险级。动作目录里可以写 `dynamic`，表示基线由 check 阶段的运行时事实决定。
 * 保守默认 R1（可逆变更），绝不默认 R0。
 */
export function resolveRiskFromAction(action) {
  const raw = action?.risk;
  if (raw === 'dynamic' || raw === undefined || raw === null) return Risk.R1;
  if (!ORDER.includes(raw)) throw new Error(`动作 ${action?.id} 的 risk 非法: ${raw}`);
  return raw;
}

/**
 * 从动作定义里按发行版选出实际要跑的命令，并把参数接进 argv。
 *
 * 返回值新增 `unresolved`：**没有任何分支匹配**时必须显式报告，
 * 而不是像原来那样静默返回空 argv（推演发现 F14：空 argv 会让"计划成功、实执空转"）。
 *
 * ── 参数接线机制（M1-②）───────────────────────────────────────────────────
 * argv 元素支持三种写法，全部**在动作定义里就地声明**：
 *
 *   1. 普通字符串                      → 原样
 *   2. `{"$param":"x"}`                → 用 params.x 的值替换；数组会展开成多个参数
 *      `{"$param":"x","prefix":"--p="}` → 每个值前面加 prefix
 *   3. `{"$when":"x","argv":[...]}`    → params.x 为真时才插入这些参数
 *
 * 分支级还支持 `dryRun`：当 `params.dryRun === true` 且有 `dryRun` argv 时，
 * **用它替换 cmd 并跳过 pre**（预演不该顺带去刷新仓库元数据）。
 *
 * ★ 关键设计：**接线情况是"用出来"的，不是"声明"出来的。**
 *   函数返回 `consumedParams`（argv 里真正引用到的参数名）。
 *   buildPlan 用它判断"传了但没人消费"的参数并 fail-closed 阻断 ——
 *   于是缺陷 F2（声明已接线、实际被静默忽略，导致"以为只装安全更新、实际全量升级"）
 *   在结构上不可能再发生：**没被 argv 引用的参数，一定被拦下**。
 *   也因此不再需要作者手写 `wiredParams` 清单（旧的静态声明已废弃、被忽略）。
 *
 * ★ 另一个自然结果：**参数支持是按发行版区分的。**
 *   例如 `securityOnly` 只在 dnf/zypper 分支里有对应 flag，Debian 分支里没引用它 →
 *   在 Debian 上传这个参数会被阻断并说明原因，而不是假装支持。
 *
 * @param {object} action
 * @param {string|undefined} distro 来自 facts 的发行版 id（如 'ubuntu'）
 * @param {string[]} [idLike] 来自 facts 的 ID_LIKE（如 ubuntu → ['debian']）
 * @param {object} [params] 调用方给出的参数（已校验）
 * @returns {{ distroKey: string|null, pre: string[][], cmd: string[][], env: Record<string,string>,
 *            unresolved: boolean, consumedParams: string[], dryRunApplied: boolean }}
 */
export function resolveCommands(action, distro, idLike = [], params = {}) {
  const table = action?.apply ?? {};
  // 容错：`ID_LIKE` 在 os-release 里是**空格分隔的字符串**，但概念上是列表。
  // 两种形态都接受，否则 `...idLike` 会把字符串拆成单个字符（真实踩过）。
  const likeList = Array.isArray(idLike)
    ? idLike
    : String(idLike ?? '').split(/\s+/).filter(Boolean);
  const candidates = [distro, ...likeList].filter(Boolean);

  for (const key of candidates) {
    if (table[key]) return branchOf(key, table[key], action, params);
  }
  if (table.default) return branchOf('default', table.default, action, params);

  return {
    distroKey: null, pre: [], cmd: [], env: {},
    unresolved: true, consumedParams: [], dryRunApplied: false,
  };
}

/** 把参数值取成"要做成几个参数"的数组。 */
function valuesOf(value) {
  if (Array.isArray(value)) return value;
  if (value === undefined || value === null) return [];
  return [value];
}

/** 标量转成 argv 片段（对象一律拒绝，避免把结构塞进命令行）。 */
function toArg(value) {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'boolean') return String(value);
  throw new Error(`参数值不能用作命令行参数：${JSON.stringify(value)}（只支持字符串/数值/布尔）`);
}

/**
 * 展开一个 argv 元素（含 `{{name}}` 插值）。
 * @param {unknown} element
 * @param {object} params
 * @param {Set<string>} consumed 被引用到的参数名（就地累加）
 * @returns {string[]} 展开后的 0..N 个参数
 */
function expandElement(element, params, consumed) {
  // 条件参数：{"$when":"x","argv":[...]}
  if (element !== null && typeof element === 'object' && !Array.isArray(element) && '$when' in element) {
    const name = element.$when;
    consumed.add(name);
    if (!params[name]) return [];
    const inner = element.argv ?? [];
    return inner.flatMap((e) => expandElement(e, params, consumed));
  }

  // 参数替换：{"$param":"x"} / {"$param":"x","prefix":"--p="}
  if (element !== null && typeof element === 'object' && !Array.isArray(element) && '$param' in element) {
    const name = element.$param;
    consumed.add(name);
    const prefix = typeof element.prefix === 'string' ? element.prefix : '';
    return valuesOf(params[name]).map((v) => `${prefix}${toArg(v)}`);
  }

  if (typeof element === 'string') {
    // 字符串内插值：--exclude={{pkg}}
    return [element.replace(/\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}/g, (_m, name) => {
      consumed.add(name);
      const v = params[name];
      return v === undefined || v === null ? '' : toArg(v);
    })];
  }

  return [toArg(element)];
}

/** 展开一串 argv（每个元素可能裂变成多个参数）。 */
function expandArgv(argv, params, consumed) {
  const out = [];
  for (const element of argv ?? []) out.push(...expandElement(element, params, consumed));
  return out;
}

function branchOf(distroKey, branch, action, params) {
  const consumed = new Set();

  // dryRun：用 dryRun argv 替换 cmd，并跳过 pre
  const dryRunApplied = params?.dryRun === true && Array.isArray(branch.dryRun) && branch.dryRun.length > 0;
  consumed.add('dryRun'); // dryRun 是被机制消费的（而不是被 argv 引用），显式算作已接线

  const pre = dryRunApplied ? [] : (branch.pre ?? []).map((a) => expandArgv(a, params, consumed));
  const cmdSource = dryRunApplied ? branch.dryRun : (branch.cmd ?? []);
  const cmd = cmdSource.map((a) => expandArgv(a, params, consumed));

  return {
    distroKey,
    pre,
    cmd,
    env: branch.env ?? {},
    unresolved: false,
    consumedParams: [...consumed].sort(),
    dryRunApplied,
  };
}

/**
 * 构建一个 plan。
 *
 * @param {object} input
 * @param {object} input.action 动作目录条目
 * @param {object} input.target 目标记录（含 tags / label / hostname）
 * @param {object} [input.params] 调用方给出的动作参数
 * @param {object} [input.checkResult] `check` 阶段的只读探测结果
 * @param {string} [input.distro] 发行版 id（来自 facts）
 * @param {string[]} [input.idLike] 发行版 ID_LIKE（来自 facts）
 * @param {object} [input.policy]
 * @param {'ask'|'never'} [input.approvalPolicy]
 * @param {number} [input.ttlMs] plan 有效期，默认 PLAN_TTL_MS
 */
export function buildPlan(input) {
  const {
    action,
    target = {},
    params = {},
    checkResult = {},
    distro,
    idLike = [],
    policy,
    approvalPolicy = 'ask',
    ttlMs = PLAN_TTL_MS,
  } = input;

  if (!action || !action.id) throw new Error('buildPlan 需要带 id 的动作定义');

  // 先解析命令：它会告诉我们"哪些参数真的被 argv 用到了"（接线情况由用法决定）
  const resolved = resolveCommands(action, distro, idLike, params);

  // ── 参数校验（F5）：不合法就地阻断，不进入后续流程 ──
  const paramErrors = validateParams(action, params);
  const unwired = findUnwiredParams(action, params, resolved.consumedParams);

  const baseRisk = resolveRiskFromAction(action);
  const escalate = {
    kernelUpgradePending: Boolean(checkResult.kernelUpgradePending),
    rebootRequired: Boolean(checkResult.rebootRequired),
  };

  const decision = decideApproval({
    risk: baseRisk,
    target,
    ...(policy ? { policy } : {}),
    approvalPolicy,
    escalate,
  });

  const blockers = [];
  if (paramErrors.length) blockers.push(`参数不合法：${paramErrors.join('；')}`);
  if (unwired.length) {
    const branch = resolved.distroKey ?? '（无匹配分支）';
    const wired = resolved.consumedParams.length ? resolved.consumedParams.join('、') : '无';
    blockers.push(
      `参数 ${unwired.join('、')} 尚未接线 —— 在 ${branch} 分支里没有被任何命令引用`
      + `（该分支已接线的参数：${wired}）。`
      + '为避免"以为只做了 X、实际做了 Y"，此处按 fail-closed 阻断。',
    );
  }
  if (resolved.unresolved) {
    const likeStr = (Array.isArray(idLike) ? idLike : String(idLike ?? '').split(/\s+/).filter(Boolean)).join('/');
    blockers.push(
      `无法为发行版 ${JSON.stringify(distro ?? null)} 解析执行命令` +
      `${likeStr ? `（ID_LIKE=${likeStr}）` : ''}。` +
      '通常是尚未采集 facts，或该发行版不在动作支持列表内。',
    );
  }

  const noop = checkResult.alreadySatisfied === true;

  const impactParts = [];
  if (typeof checkResult.count === 'number') impactParts.push(`${checkResult.count} 项待处理`);
  if (typeof checkResult.sizeBytes === 'number') {
    impactParts.push(`约占 ${(checkResult.sizeBytes / 1048576).toFixed(0)} MiB`);
  }
  if (escalate.kernelUpgradePending) impactParts.push('含内核升级，需重启后生效');
  if (escalate.rebootRequired) impactParts.push('当前系统已标记需要重启');

  const blockedByCheck = checkResult.blocked ? String(checkResult.blocked) : null;
  const blocked = decision.blocked || Boolean(blockedByCheck) || blockers.length > 0;

  // 同一个时刻算 checkedAt 与 expiresAt。
  // 单测发现原来分两次取 now，导致 expiresAt - checkedAt 会漂 1~2ms
  // （对"有效期恰为 ttlMs"这个可审计的不变式是破坏）。
  const nowMs = Date.now();
  const checkedAt = new Date(nowMs).toISOString();

  return {
    traceId: input.traceId ?? null,
    actionId: action.id,
    actionVersion: action.version ?? 1,
    // F1：side 必须随 plan 传递，applyPlan 才能区分"远端执行"与"主控端本地执行"
    side: action.side ?? 'agent',
    title: action.title ?? { zh: action.id, en: action.id },
    targetId: target.id ?? null,
    targetLabel: target.label ?? target.hostname ?? null,
    params,
    distroKey: resolved.distroKey,
    risk: decision.effectiveRisk,
    baseRisk: decision.baseRisk,
    escalatedBy: decision.escalatedBy,
    requiresApproval: decision.requiresApproval,
    requireEchoHostname: decision.requireEchoHostname,
    approvalReason: decision.approvalReason,
    blocked,
    blockedReason: decision.blockedReason ?? blockedByCheck
      ?? (blockers.length ? blockers.join(' ') : null),
    blockers,
    paramErrors,
    unwiredParams: unwired,
    noop,
    resolvedArgv: [...resolved.pre, ...resolved.cmd],
    env: resolved.env,
    // ── 参数接线情况（由 argv 用法推导，供审计与"为什么被拦下"的解释）──
    consumedParams: resolved.consumedParams,
    dryRunApplied: resolved.dryRunApplied,
    // ── TOCTOU 防护（I7）：把"当时的环境状态"与"有效期"钉进计划 ──
    stateFingerprint: checkFingerprint(checkResult),
    checkedAt,
    ttlMs,
    expiresAt: new Date(nowMs + ttlMs).toISOString(),
    impact: {
      summary: impactParts.length ? impactParts.join('；') : '无显著影响面信息',
      changedEstimate: typeof checkResult.count === 'number' ? checkResult.count : null,
      rebootRequired: escalate.rebootRequired || escalate.kernelUpgradePending,
    },
    rollbackHint: action.rollback?.strategy ?? null,
  };
}

/** 供测试与展示：把 plan 压成一行。 */
export function summarizePlan(plan) {
  const t = plan.title?.zh ?? plan.actionId;
  if (plan.blocked) return `✗ ${t}：${plan.blockedReason}`;
  if (plan.noop) return `= ${t}：已是目标态，无需执行`;
  return `→ ${t} [${plan.risk}] ${plan.impact.summary}`;
}

export { maxRisk };
