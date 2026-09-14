/**
 * VMProbe 引擎 —— 把 core + catalog + transport 组装成工具层可用的能力集合。
 *
 * 本文件**不依赖 DSH**（便于独立单测与 CLI 复用）。审批由工具层发起，
 * 因为只有那里才拿得到 `exec.agent`。
 *
 * ── 缺陷修复历史（对应 ISSUES.md 编号）────────────────────────────────────
 *   F1  applyPlan 按 plan.side 分发；controller 侧动作绝不进传输层。
 *   F8  审计落 JSONL 并在启动时重放。
 *   F9  目标存储的读-改-写加互斥。
 *   F12 审计内存窗口封顶（完整历史在文件里）。
 *   I6  审计文件**按大小轮转**，且轮转不打断哈希链（跨文件可校验）。
 *   I7  plan 带状态指纹 + 有效期，审批前与执行前**各校验一次**（防 TOCTOU）。
 *   I8  所有审计字段与错误文本**过统一脱敏**后才落盘。
 *   I11 报告文件写完后把 sha256 记入审计链，报告被篡改可检出。
 */

import {
  appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync,
  writeFileSync,
} from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  buildDailyReport,
  buildPlan,
  checkPlanFreshness as evaluateFreshness,
  createAuditLog,
  createRedactor,
  DEFAULT_POLICY,
  assertSafeId,
  writeJsonAtomic,
  dayKey,
  latestReport,
  makeTarget,
  openStore,
  pruneReports as pruneReportsCore,
  readDay,
  redactDeep,
  reportPath,
  sha256Hex,
  tailHash,
  verifyChain,
  writeReport as writeReportFile,
  GENESIS,
} from '../../core/src/index.js';
import { loadCatalog, listCatalog } from '../../catalog/src/index.js';
import { whyCancelled } from '../../transport/src/ssh.js';
import { assertSafeRunId, MAX_RUN_BYTES, newRunId, persistRun, renderRun, verifyRunSeal } from './runs.js';

const HERE = dirname(fileURLToPath(import.meta.url));

/** 内置动作目录位置。 */
export const DEFAULT_CATALOG_DIR = join(HERE, '..', '..', 'catalog', 'actions');

/** 默认审计文件轮转阈值。 */
export const DEFAULT_MAX_AUDIT_BYTES = 8 * 1024 * 1024;

/**
 * 执行被取消（M2-③）。
 *
 * 与"失败"刻意分开：取消是**可预期的结局**，不是故障。
 * 它仍要留痕（`action.cancelled` + 运行记录），否则"任务去哪了"无人能答，
 * 但不该被当成错误去告警、也不该影响失败率统计。
 */
export class RunCancelledError extends Error {
  constructor(message, runId = null) {
    super(message);
    this.name = 'RunCancelledError';
    this.code = 'aborted';
    this.runId = runId;
  }
}

/** 尚未实现的能力。 */
export class NotImplementedError extends Error {
  constructor(what, milestone = 'M1') {
    super(`${what} 尚未实现（计划于 ${milestone} 落地）。`);
    this.name = 'NotImplementedError';
    this.code = 'not_implemented';
    this.milestone = milestone;
  }
}

/** 兼容 M0 时期的名字。 */
export class NotImplementedInM0Error extends NotImplementedError {
  constructor(what, milestone = 'M1') {
    super(what, milestone);
    this.name = 'NotImplementedInM0Error';
  }
}

/** plan 已失效（过期或环境已变）—— 必须重新计划，不能沿用。 */
export class PlanStaleError extends Error {
  constructor(verdict) {
    super(`计划已失效：${verdict.reason}`);
    this.name = 'PlanStaleError';
    this.code = 'plan_stale';
    this.verdict = verdict;
  }
}

/**
 * 创建引擎。**同步**返回 —— 插件 apply() 需要在初始化期就拿到句柄。
 */
export function createEngine(options = {}) {
  const { dir, transport = null, controllerHandlers = new Map() } = options;
  if (!dir) throw new Error('createEngine 需要 dir（存储目录）');

  const catalogDir = options.catalogDir ?? DEFAULT_CATALOG_DIR;
  const rawConfig = { ...(options.config ?? {}) };

  /**
   * 配置键白名单（技术债 #1）。
   *
   * 为什么需要它：配置里写错一个键名（比如 `reportAtUTC`）在别处通常表现为
   * "改了没效果"，而这里**改的是审批阈值** —— 静默忽略会让人以为策略已生效。
   * 所以：未知键 → 明确告警并记台账，而不是悄悄吃掉。
   *
   * ⚠️ 刻意**不在 apply() 里抛错**：抛错会让整棵插件树加载失败（DSH 的硬行为），
   *    一个拼错的配置键不该导致 DSH 起不来。告警 + 台账 + 状态工具可见，三重可见性足够。
   */
  const KNOWN_CONFIG_KEYS = new Set([
    'autoAllowUpTo', 'prodEscalatesTo', 'alwaysAskFrom', 'echoHostnameAt', 'auditReadOnly',
    'planTtlMs', 'maxAuditBytes', 'auditStartupFiles', 'maxRunBytes',
    'agentScriptPath', 'transport', 'hostKeyPolicy', 'connectTimeoutMs', 'commandTimeoutMs',
    'dailyReport', 'reportAtUtc', 'reportRetentionDays', 'reportTargets', 'tickMs',
    'heartbeat', 'heartbeatIntervalMs', 'heartbeatTimeoutMs',
    'catalogDir', 'storageDir', 'loadMarkerFile',
    // 已实现但**刻意拒绝**的键也登记在册，好把"未知键"与"已知但未实现"区分开
    'allowRawShell',
  ]);

  const configWarnings = [];
  for (const key of Object.keys(rawConfig)) {
    if (!KNOWN_CONFIG_KEYS.has(key)) {
      configWarnings.push(`未知配置键 "${key}" 已被忽略（拼写错误？）。已知键见 README 配置一节。`);
    }
  }

  // allowRawShell：T3 原始 shell **尚未实现**。静默接受它等于让用户以为已经开了这个能力。
  if (rawConfig.allowRawShell === true) {
    configWarnings.push(
      'allowRawShell=true 已被拒绝：T3 原始 shell 尚未实现。'
      + '它不作为"已开启的开关"存在 —— 当前所有执行都必须经过动作目录与审批（fail-closed）。',
    );
  } else if (rawConfig.allowRawShell === false) {
    configWarnings.push('allowRawShell 已废弃（T3 未实现，默认就是关闭），请从配置里删掉这个键。');
  }

  const RISK_ORDER = ['R0', 'R1', 'R2', 'R3'];
  const autoAllowUpTo = rawConfig.autoAllowUpTo ?? DEFAULT_POLICY.autoAllowUpTo;
  if (!RISK_ORDER.includes(autoAllowUpTo)) {
    configWarnings.push(
      `autoAllowUpTo=${JSON.stringify(autoAllowUpTo)} 不是合法风险级（${RISK_ORDER.join('/')}），`
      + `已回退到默认 ${DEFAULT_POLICY.autoAllowUpTo}。`,
    );
  } else if (RISK_ORDER.indexOf(autoAllowUpTo) > RISK_ORDER.indexOf(DEFAULT_POLICY.autoAllowUpTo)) {
    // 放宽免审批范围是**安全相关**的改动，必须显眼地说出来
    configWarnings.push(
      `注意：autoAllowUpTo=${autoAllowUpTo} 比默认（${DEFAULT_POLICY.autoAllowUpTo}）更宽松 —— `
      + '更多动作将在**不弹窗**的情况下执行（仍会写审计）。',
    );
  }

  const config = {
    /** plan 有效期（防 TOCTOU 的时间维度）。 */
    planTtlMs: 5 * 60 * 1000,
    /** 审计文件轮转阈值。 */
    maxAuditBytes: DEFAULT_MAX_AUDIT_BYTES,
    /** 单次运行记录（runs/*.log）的落盘上限。 */
    maxRunBytes: MAX_RUN_BYTES,
    /** 单文件读取上限（启动时最多回溯几个轮转文件做连续性校验）。 */
    auditStartupFiles: 3,
    ...(options.config ?? {}),
    // ⚠️ 下面两项必须放在展开**之后**：否则配置里的原值会把规范化结果盖回去。
    //    这里踩过一次：policy 读到的是未规范化的 'R9'，而 'R9' 在 ORDER 里下标为 -1，
    //    会让"是否需审批"的判定进入无意义区间 —— 一个"看起来只是警告、实际影响判定"的 bug。
    autoAllowUpTo: RISK_ORDER.includes(rawConfig.autoAllowUpTo)
      ? rawConfig.autoAllowUpTo
      : DEFAULT_POLICY.autoAllowUpTo,
    maxRunBytes: Number.isInteger(rawConfig.maxRunBytes) && rawConfig.maxRunBytes > 0
      ? rawConfig.maxRunBytes
      : MAX_RUN_BYTES,
  };

  /** 透传给 buildPlan 的审批策略：只有**已核实**的字段才生效，其余用默认。 */
  const policy = {
    ...DEFAULT_POLICY,
    autoAllowUpTo: config.autoAllowUpTo,
    ...(RISK_ORDER.includes(rawConfig.prodEscalatesTo) ? { prodEscalatesTo: rawConfig.prodEscalatesTo } : {}),
    ...(RISK_ORDER.includes(rawConfig.alwaysAskFrom) ? { alwaysAskFrom: rawConfig.alwaysAskFrom } : {}),
    ...(RISK_ORDER.includes(rawConfig.echoHostnameAt) ? { echoHostnameAt: rawConfig.echoHostnameAt } : {}),
    ...(typeof rawConfig.auditReadOnly === 'boolean' ? { auditReadOnly: rawConfig.auditReadOnly } : {}),
  };
  // 配置里显式写了键却值非法 → 也说清楚（否则又是"改了没效果"）
  for (const key of ['prodEscalatesTo', 'alwaysAskFrom', 'echoHostnameAt']) {
    if (rawConfig[key] !== undefined && !RISK_ORDER.includes(rawConfig[key])) {
      configWarnings.push(`${key}=${JSON.stringify(rawConfig[key])} 不是合法风险级，已回退到默认 ${policy[key]}。`);
    }
  }

  const store = openStore({ dir });
  const { actions, sources } = loadCatalog(catalogDir);

  const logDir = join(dir, 'logs');
  mkdirSync(logDir, { recursive: true });
  const auditFile = join(logDir, 'audit.jsonl');
  const ROTATED_RE = /^audit\.(\d{4})\.jsonl$/;

  /** 运行时秘密登记表：认证切换期间用它保证密码不出现在任何输出里。 */
  const redactor = createRedactor();

  // ── 审计：读取历史、跨文件校验、装载内存窗口 ──────────────────────────
  function rotatedFiles() {
    return readdirSync(logDir)
      .map((f) => ROTATED_RE.exec(f))
      .filter(Boolean)
      .map((m) => ({ seq: Number(m[1]), name: m[0] }))
      .sort((a, b) => a.seq - b.seq)
      .map((x) => x.name);
  }

  function readFileRecords(path) {
    const out = [];
    let corrupt = 0;
    for (const line of readFileSync(path, 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try {
        out.push(JSON.parse(line));
      } catch {
        corrupt++;
      }
    }
    return { records: out, corrupt };
  }

  /**
   * 读取审计序列。
   * @param {{ maxFiles?: number }} [o] 只回溯最近 N 个文件（含当前文件）
   */
  function readAuditSequence(o = {}) {
    const rotated = rotatedFiles();
    const files = [...rotated.map((n) => join(logDir, n)), auditFile].filter((p) => existsSync(p));
    const selected = o.maxFiles ? files.slice(-o.maxFiles) : files;
    const records = [];
    let corrupt = 0;
    for (const p of selected) {
      const r = readFileRecords(p);
      records.push(...r.records);
      corrupt += r.corrupt;
    }
    return { files: selected, records, corrupt };
  }

  const startup = readAuditSequence({ maxFiles: config.auditStartupFiles });
  // 先校验完整（含跨轮转接续），再装载窗口 —— 顺序很重要，
  // 否则裁剪窗口会让校验起点不对，把"裁剪"误报成"篡改"。
  const historyCheck = startup.records.length
    ? { ...verifyChain(startup.records, GENESIS), files: startup.files.length }
    : { ok: true, length: 0, files: 0 };

  const audit = createAuditLog({ maxRecords: options.maxAuditRecords });
  audit.hydrate(startup.records);

  let auditDegraded = null;
  let rotations = rotatedFiles().length;

  // ── 写互斥（F9）────────────────────────────────────────────────────────
  let writeChain = Promise.resolve();
  function withWriteLock(fn) {
    const run = writeChain.then(fn, fn);
    writeChain = run.then(() => {}, () => {});
    return run;
  }

  const factsByTarget = new Map();
  /** 心跳统计（内存即可：它描述的是"当下连接状态"，重启后本就应重新观察）。 */
  const heartbeatStats = new Map();
  /**
   * 每个目标**最近一次真实失败**的原因（含错误文本与时间）。
   *
   * 为什么需要单独存：transport 在心跳失败时会把会话标成 `detached`，于是**下一次**
   * 心跳看到的是"没有会话"→ 返回 `no-session`。如果只保留最后一次探测结果，
   * "断线原因"就会在第二次探测后消失，人只能看到 `no-session`，无法回答
   * "它为什么掉了"。所以失败原因单独记住，成功恢复时清空。
   */
  const heartbeatFailure = new Map();

  /** 审计文件超阈值时轮转；跨文件哈希链接续（I6）。 */
  function rotateAuditIfNeeded() {
    let size = 0;
    try {
      size = statSync(auditFile).size;
    } catch {
      return null; // 文件还不存在
    }
    if (size <= config.maxAuditBytes) return null;

    rotations += 1;
    const seq = String(rotations).padStart(4, '0');
    const target = join(logDir, `audit.${seq}.jsonl`);
    renameSync(auditFile, target);

    // 在新文件里写一条轮转记录：它接续旧文件的尾哈希，
    // 因此**跨文件的链是可校验的** —— 否则每次轮转都会切断证据链。
    const marker = audit.append({
      event: 'audit.rotate',
      seq,
      previousFile: basename(target),
      sizeBytes: size,
    });
    appendFileSync(auditFile, `${JSON.stringify(marker)}\n`, 'utf8');
    return { seq, file: target, sizeBytes: size };
  }

  const engine = {
    dir,
    catalogDir,
    store,
    actions,
    sources,
    audit,
    auditFile,
    historyCheck,
    redactor,
    config,
    /** 实际生效的审批策略（技术债 #1 修复后，它真的会参与决策）。 */
    policy,
    /** 配置层面的问题（未知键、非法值、比默认更宽松的策略…），供工具与台账展示。 */
    configWarnings,
    transport,
    controllerHandlers,
    factsByTarget,

    get corruptLines() {
      return startup.corrupt;
    },
    get auditDegraded() {
      return auditDegraded;
    },
    get rotations() {
      return rotations;
    },

    // ---------- 审计 ----------

    /**
     * 追加一条审计记录：**先脱敏**，再入内存窗口，再落盘。
     *
     * 脱敏在写入之前发生，所以哈希链覆盖的是脱敏后的内容 —— 审计要能证明
     * "发生过什么"，但不能成为秘密的第二个副本（I8）。
     * 同时保留 `redactedPaths`：既看不到秘密，又**知道秘密曾经经过**。
     */
    record(event, fields = {}) {
      const { value: safe, redactedPaths } = redactDeep(fields, { rootPath: '$' });
      const payload = redactedPaths.length ? { ...safe, redactedPaths } : safe;

      // ⚠️ 顺序是关键，且被推演探针抓到过一次真 bug：
      //   轮转**本身**也会往链里追加一条 audit.rotate 记录。
      //   如果先把自己的记录加入内存链、再轮转，那条轮转记录的 prev 就会指向
      //   "尚未落盘的本条"，于是新文件里两条记录的先后与链序相反 —— 磁盘上的链就断了。
      //   所以必须：先轮转（可能追加标记），再追加本条。
      try {
        rotateAuditIfNeeded();
      } catch (err) {
        auditDegraded = err?.message ?? String(err);
      }

      const chained = audit.append({ event, ...payload });
      try {
        appendFileSync(auditFile, `${JSON.stringify(chained)}\n`, 'utf8');
      } catch (err) {
        auditDegraded = err?.message ?? String(err);
      }
      return chained;
    },

    /** 快速校验：内存窗口 + 启动时的历史连续性结论。 */
    verifyAudit() {
      return {
        ...audit.verify(),
        corruptLines: startup.corrupt,
        historyOk: historyCheck.ok,
        historyReason: historyCheck.ok ? null : historyCheck.reason,
        historyFiles: historyCheck.files ?? 0,
        rotations,
        degraded: auditDegraded,
      };
    },

    /** 完整校验：读取全部轮转文件 + 当前文件，逐条验证（含跨文件接续）。 */
    verifyAuditFull() {
      const all = readAuditSequence();
      const v = verifyChain(all.records, GENESIS);
      return {
        ...v,
        files: all.files.map((f) => basename(f)),
        corruptLines: all.corrupt,
        degraded: auditDegraded,
      };
    },

    // ---------- 目标 ----------

    async listTargets() {
      return (await store.readTargets()).targets;
    },

    async findTarget(id) {
      const targets = await this.listTargets();
      return targets.find((t) => t.id === id || t.label === id) ?? null;
    },

    async addTarget(input) {
      const target = makeTarget(input);
      return withWriteLock(async () => {
        const doc = await store.readTargets();
        if (doc.targets.some((t) => t.id === target.id)) {
          throw new Error(`目标 id 已存在: ${target.id}`);
        }
        doc.targets.push(target);
        await store.writeTargets(doc);
        this.record('target.add', { targetId: target.id, hostname: target.hostname, user: target.user });
        return target;
      });
    },

    async removeTarget(id) {
      return withWriteLock(async () => {
        const doc = await store.readTargets();
        const idx = doc.targets.findIndex((t) => t.id === id || t.label === id);
        if (idx < 0) throw new Error(`目标不存在: ${id}`);
        const [removed] = doc.targets.splice(idx, 1);
        await store.writeTargets(doc);
        factsByTarget.delete(removed.id);
        this.record('target.remove', { targetId: removed.id });
        return removed;
      });
    },

    // ---------- 目录 ----------

    catalogList() {
      return listCatalog(actions);
    },

    getAction(id) {
      const action = actions.get(id);
      if (!action) {
        const known = [...actions.keys()].sort().join(', ');
        throw new Error(`未知动作 "${id}"。可用动作：${known}。请先用 vmprobe_catalog 查看。`);
      }
      return action;
    },

    controllerHandlerFor(action) {
      return action?.apply?.default?.handler ?? null;
    },

    // ---------- 计划 ----------

    /**
     * 采集 facts 并**落盘**。
     *
     * 落盘放在这一处（而不是让每个调用方记得写），否则迟早有路径只放内存 ——
     * 那会让插件重启后"忘记"目标的发行版，进而无法按发行版分流。
     */
    async collectFacts(target) {
      const facts = typeof this.factsProvider === 'function'
        ? await this.factsProvider(target)
        : (transport && typeof transport.probeFacts === 'function'
          ? await transport.probeFacts(target)
          : (() => { throw new NotImplementedError('facts 采集（transport.probeFacts）', 'M1'); })());

      if (facts && target?.id) {
        factsByTarget.set(target.id, facts);
        try {
          await this.persistFacts(target.id, facts);
        } catch (err) {
          // 落盘失败不能吞掉采集结果，但必须留痕（否则"重启后画像丢了"会变成谜）
          this.record('facts.persist.failed', { targetId: target.id, reason: err?.message ?? String(err) });
        }
      }
      return facts;
    },

    async runCheck(action, target, facts, opts = {}) {
      if (!transport) return { probed: false, note: '无传输层，check 未实际执行' };
      return transport.check(action, target, facts, opts);
    },

    /** 只读地构建一个 plan。不产生任何副作用。 */
    async planAction({ targetId, actionId, params = {}, approvalPolicy = 'ask', ttlMs, signal = null }) {
      const action = this.getAction(actionId);
      const target = await this.findTarget(targetId);
      if (!target) throw new Error(`目标不存在: ${targetId}`);

      // 画像：内存优先，其次落盘（插件重启后仍能按发行版分流）
      const facts = this.factsFor(target.id);
      const checkResult = await this.runCheck(action, target, facts, { signal });

      const plan = buildPlan({
        action,
        target,
        params,
        checkResult,
        distro: facts?.os?.id ?? undefined,
        // os-release 里的 ID_LIKE 是空格分隔字符串；这里统一成数组再交给 buildPlan
        // （buildPlan 也做了容错，但归一化放在边界上更清楚）
        idLike: Array.isArray(facts?.os?.idLike)
          ? facts.os.idLike
          : String(facts?.os?.idLike ?? '').split(/\s+/).filter(Boolean),
        approvalPolicy,
        // 技术债 #1 的修复：策略（含 autoAllowUpTo）从配置**真正**透传到决策层。
        // 在此之前 engine.config.autoAllowUpTo 是个死键 —— 改了没有任何效果。
        policy,
        ttlMs: ttlMs ?? config.planTtlMs,
      });

      this.record('action.plan', {
        actionId,
        targetId: target.id,
        side: plan.side,
        params,
        risk: plan.risk,
        escalatedBy: plan.escalatedBy,
        noop: plan.noop,
        blocked: plan.blocked,
        blockedReason: plan.blockedReason,
        resolvedArgv: plan.resolvedArgv,
        stateFingerprint: plan.stateFingerprint,
        expiresAt: plan.expiresAt,
      });

      return plan;
    },

    /** 为某个 plan 重新探测环境（TOCTOU 校验的输入）。 */
    async recheckForPlan(plan, opts = {}) {
      const action = this.actions.get(plan.actionId);
      const target = await this.findTarget(plan.targetId);
      return this.runCheck(action, target, factsByTarget.get(plan.targetId) ?? null, opts);
    },

    /**
     * 校验 plan 是否仍然新鲜。
     *
     * **两道关**：有效期（时间）与状态指纹（内容）。任何一道不过都必须重新计划 ——
     * 因为用户批准的"12 个包待更新"如果已经变成"3 个包"，那已经**不是他批准的那件事**。
     *
     * 策略从严：拿不到指纹可比对时（未探测）也判为不新鲜，不做"控制器侧动作就放行"的例外。
     * 宁可多要求一次重新计划，也不静默按旧计划执行。
     */
    async verifyPlanFresh(plan, opts = {}) {
      if (!plan) return { ok: false, canVerify: false, reason: '缺少 plan', expired: false, fingerprintChanged: false };
      const recheck = await this.recheckForPlan(plan, { signal: opts.signal ?? null });
      return evaluateFreshness(plan, recheck, opts);
    },

    // ---------- 执行 ----------

    get canExecute() {
      return transport !== null;
    },

    /**
     * 当前连接状态。
     *
     * 修掉 I9 的原因：状态工具原来硬编码返回 `'detached'`，
     * 那是**一个看起来像真状态的假值** —— 无论实际是否接线都显示"未连接"。
     * 与其给个像样的错值，不如如实说"未接线"。
     */
    get connectionState() {
      if (!transport) return 'not-wired';
      if (typeof transport.state === 'function') return transport.state();
      return 'unknown';
    },

    /** 某动作此刻是否具备执行条件（工具据此在**申请审批之前**判断）。 */
    canApply(plan) {
      if (!plan || plan.blocked) return false;
      if (plan.side === 'controller') {
        const handler = this.controllerHandlerFor(this.actions.get(plan.actionId));
        return handler !== null && controllerHandlers.has(handler);
      }
      return this.canExecute;
    },

    /**
     * 执行 apply。按 side 分发（F1），并在执行前**再次**校验 plan 新鲜度（I7）。
     *
     * M2 增补三件事：
     *   ① **verify 真正执行**（`action.verify` 声明的探测在变更后重跑并判定）；
     *   ② **运行输出落盘**（`runs/<runId>.log`，审计只留 `{path, sha256, bytes}` 引用）;
     *   ③ **取消贯通**（`signal` 一路传到 SSH 通道，中断即给远端发 TERM）。
     */
    async applyPlan(plan, { runId, now, signal = null } = {}) {
      if (!plan) throw new Error('applyPlan 需要 plan');
      if (plan.blocked) throw new Error(`plan 已被阻断，拒绝执行：${plan.blockedReason}`);

      const id = runId ?? newRunId();
      assertSafeRunId(id);
      const startedAt = new Date().toISOString();

      // 执行前复检：审批与执行之间可能又过去了时间
      const verdict = await this.verifyPlanFresh(plan, { now, signal });
      if (!verdict.ok) {
        this.record('action.stale', {
          actionId: plan.actionId,
          targetId: plan.targetId,
          expired: verdict.expired,
          fingerprintChanged: verdict.fingerprintChanged,
          reason: verdict.reason,
        });
        throw new PlanStaleError(verdict);
      }

      if (signal?.aborted) throw new RunCancelledError(`执行前已取消（${whyCancelled(signal)}）`, id);

      const action = this.actions.get(plan.actionId);

      /** 统一的收尾：落盘 + 审计。**无论成功失败都落盘** —— 失败更需要复盘。 */
      const finishRun = async ({ result = null, verify = null, exit = null, error = null }) => {
        const finishedAt = new Date().toISOString();
        const text = renderRun({
          runId: id, plan, result, verify, startedAt, finishedAt, exit, error, redactor,
        });
        let run = null;
        try {
          run = persistRun({ root: dir, runId: id, text, maxBytes: config.maxRunBytes });
        } catch (err) {
          // 落盘失败不能吞掉执行结果，但必须留痕（否则"输出哪去了"会变成谜）
          this.record('action.run.persist.failed', {
            runId: id, actionId: plan.actionId, targetId: plan.targetId,
            reason: err?.message ?? String(err),
          });
        }
        this.record(error ? 'action.run.failed' : 'action.run', {
          runId: id,
          actionId: plan.actionId,
          targetId: plan.targetId,
          risk: plan.risk,
          exit,
          // 审计里只放**引用与摘要**，不放输出正文
          runPath: run?.relPath ?? null,
          runSha256: run?.sha256 ?? null,
          runBytes: run?.bytes ?? null,
          verify: verify
            ? {
              probe: verify.probe ?? null,
              satisfied: verify.satisfied ?? null,
              skipped: verify.skipped === true,
              reason: verify.reason ?? null,
            }
            : null,
        });
        return run;
      };

      /** 变更后按目录声明校验（M2-①）。 */
      const runDeclaredVerify = async () => {
        if (!action?.verify) return { skipped: true, reason: '动作未声明 verify' };
        if (plan.dryRunApplied) {
          // 预演什么都没改，去"校验目标态"只会得出误导性的结论
          return { skipped: true, reason: 'dryRun 预演未产生变更，不做目标态校验' };
        }
        if (!transport || typeof transport.runProbe !== 'function') {
          return { skipped: true, reason: '传输层不支持 runProbe' };
        }
        const target = await this.findTarget(plan.targetId);
        if (!target) return { skipped: true, reason: '目标不存在' };
        try {
          const res = await transport.runProbe({
            probe: action.verify.probe,
            expect: action.verify.expect ?? null,
            maxWaitMs: action.verify.maxWaitMs ?? 0,
            target,
            facts: factsByTarget.get(plan.targetId) ?? null,
            signal,
          });
          return { skipped: false, ...res };
        } catch (err) {
          // 校验本身失败也要如实报告 —— 不能因为"没验成"就默认成功
          return {
            skipped: false,
            probed: false,
            probe: action.verify.probe,
            satisfied: null,
            error: this.redactor.text(err?.message ?? String(err)),
          };
        }
      };

      try {
        if (plan.side === 'controller') {
          const handlerName = this.controllerHandlerFor(action);
          const handler = handlerName ? controllerHandlers.get(handlerName) : undefined;
          if (!handler) {
            throw new NotImplementedError(`controller 侧动作处理器 ${handlerName ?? '(未声明)'}`, 'M1');
          }
          this.record('action.apply.controller', {
            actionId: plan.actionId, targetId: plan.targetId, risk: plan.risk, handler: handlerName, runId: id,
          });
          const handlerResult = await handler(plan, { runId: id, redactor, signal });
          this.record('action.apply', {
            actionId: plan.actionId,
            targetId: plan.targetId,
            side: plan.side,
            risk: plan.risk,
            handler: handlerName,
            runId: id,
            exit: handlerResult?.exit ?? null,
          });
          const verify = await runDeclaredVerify();
          const run = await finishRun({ result: handlerResult, verify, exit: handlerResult?.exit ?? null });
          return { ...handlerResult, runId: id, verify, run };
        }

        if (!transport) throw new NotImplementedError('动作实际执行（transport.apply）', 'M1');

        const result = await transport.apply(plan, { runId: id, signal });
        // 保留 action.apply 事件：它是"动作真的被执行了"这一事实的**最短记录**，
        // 完整输出在 runs/ 里（action.run 事件带引用）。两者互补，不重复存正文。
        this.record('action.apply', {
          actionId: plan.actionId,
          targetId: plan.targetId,
          side: plan.side,
          risk: plan.risk,
          runId: id,
          exit: result?.exit ?? null,
        });
        const verify = await runDeclaredVerify();
        const run = await finishRun({ result, verify, exit: result?.exit ?? null });
        return { ...result, runId: id, verify, run };
      } catch (err) {
        // 取消是可预期结局，不当成"失败"记（但仍要留痕，否则"任务去哪了"无人能答）
        const cancelled = err?.code === 'aborted' || signal?.aborted === true;
        if (cancelled) {
          this.record('action.cancelled', {
            runId: id, actionId: plan.actionId, targetId: plan.targetId,
            reason: err?.code === 'aborted' ? this.redactor.text(err.message) : whyCancelled(signal),
          });
        }
        await finishRun({ error: this.redactor.text(err?.message ?? String(err)), exit: err?.exit ?? null });
        throw err;
      }
    },

    /** 运行记录目录（供工具与文档引用）。 */
    get runsDir() {
      return join(dir, 'runs');
    },

    /**
     * 清理过期日报（技术债 #5）。
     *
     * 保留规则由 core 的 `pruneReports` 决定（近 N 天全留、更早的每月留 1 号），
     * 这里只负责：对**每个目标**跑一遍 + 记审计。
     * **不做"悄悄全删"**：删了哪些、删了几份，都要能从审计里查回来。
     */
    async pruneReports({ keepDays = 90, now = new Date(), targetIds = null } = {}) {
      const ids = targetIds ?? (await this.listTargets()).map((t) => t.id);
      const removed = [];
      for (const targetId of ids) {
        const res = await pruneReportsCore({ root: dir, targetId, keepDays, now });
        for (const p of res?.removed ?? []) removed.push({ targetId, path: p });
      }
      this.record('reports.pruned', { keepDays, targets: ids.length, removedCount: removed.length });
      return { keepDays, targets: ids, removed };
    },

    /** 事后校验某次运行记录是否被改动过（比对审计里的 sha256）。 */
    verifyRunSeal({ runId, sha256 }) {
      return verifyRunSeal({ root: dir, runId, sha256 });
    },

    // ---------- 目标：主机指纹与认证方式 ----------

    /**
     * 固定主机密钥指纹（TOFU 首连）。
     *
     * 注意**指纹变更不走这里静默覆盖** —— 那正是 MITM 的场景。
     * 变更只记录一条告警事件，等用户用显式动作（R3）确认后再接受。
     */
    async pinHostKey(targetId, fingerprint) {
      return withWriteLock(async () => {
        const doc = await store.readTargets();
        const t = doc.targets.find((x) => x.id === targetId);
        if (!t) return null;
        const prev = t.hostKey?.fingerprint ?? null;
        if (prev && prev !== fingerprint) {
          this.record('hostkey.mismatch', { targetId, previous: prev, observed: fingerprint });
          return { changed: true, previous: prev, observed: fingerprint };
        }
        if (!prev) {
          t.hostKey = { ...(t.hostKey ?? {}), algo: t.hostKey?.algo ?? 'unknown', fingerprint, trust: 'pinned', pinnedAt: new Date().toISOString() };
          await store.writeTargets(doc);
          this.record('hostkey.pinned', { targetId, fingerprint });
          return { pinned: true, fingerprint };
        }
        return { unchanged: true, fingerprint };
      });
    },

    /**
     * 切换目标的认证方式。
     *
     * ★ 必须**记住原来的认证方式**：免密启用后 `authRef` 会变成 `{kind:'key'}`，
     * 如果此时丢掉"原来的密码引用"，那么**撤销免密时就不知道该回退到哪个凭据引用** ——
     * 实测会表现为"撤销永远失败：凭据 xxx 未配置"（而 xxx 其实是目标的 id，不是凭据名）。
     * 所以这里把最近一次的**非密钥**认证方式记到 `previousAuthRef`（可覆盖，因此
     * 启用→撤销→再启用 的循环也成立）。
     */
    async switchTargetAuth(targetId, authRef, { rememberPrevious = true } = {}) {
      return withWriteLock(async () => {
        const doc = await store.readTargets();
        const t = doc.targets.find((x) => x.id === targetId);
        if (!t) throw new Error(`目标不存在: ${targetId}`);
        const from = { ...(t.authRef ?? {}) };

        if (rememberPrevious && from.kind && from.kind !== 'key') {
          t.previousAuthRef = { ...from };
        }
        t.authRef = { ...authRef };
        await store.writeTargets(doc); // 写入前会过 assertSecretFree：凭据引用不是凭据本身
        this.record('target.auth.switch', {
          targetId,
          fromKind: from.kind ?? null,
          toKind: authRef.kind,
          ref: authRef.ref,
          rememberedPrevious: t.previousAuthRef?.ref ?? null,
        });
        return t;
      });
    },

    // ---------- 环境画像（facts）----------

    /**
     * 把画像落盘。
     *
     * 为什么必须落盘（M1-③）：facts 是"动作按发行版分流"与"风险提权"的依据。
     * 只放内存的话插件一重启就没了 —— 表现是"明明探测过，更新系统却报无法解析发行版"。
     */
    async persistFacts(targetId, facts) {
      assertSafeId(targetId, 'targetId');
      const file = join(this.dir, 'facts', `${targetId}.json`);
      await writeJsonAtomic(file, {
        schema: 'vmprobe/facts-store/1',
        targetId,
        savedAt: new Date().toISOString(),
        facts,
      });
      this.record('facts.persist', {
        targetId,
        os: facts?.os?.id ?? null,
        arch: facts?.os?.arch ?? null,
        upgradable: facts?.pkg?.upgradable ?? null,
      });
      return file;
    },

    /** 读回落盘的画像（同步，供 planAction 同步取用）。 */
    loadFacts(targetId) {
      try {
        const doc = JSON.parse(readFileSync(join(this.dir, 'facts', `${targetId}.json`), 'utf8'));
        if (doc?.schema !== 'vmprobe/facts-store/1') return null;
        return { ...doc.facts, savedAt: doc.savedAt };
      } catch {
        return null;
      }
    },

    /** 取画像：内存优先，其次落盘（因此插件重启后仍能按发行版分流）。 */
    factsFor(targetId) {
      const mem = factsByTarget.get(targetId);
      if (mem) return mem;
      const disk = this.loadFacts(targetId);
      if (disk) factsByTarget.set(targetId, disk);
      return disk;
    },

    // ---------- 心跳（保活的可观测性）----------

    /**
     * 对一个目标的连接做一次心跳：观察是否还活着、延迟多少。
     *
     * 为什么必须有它：需求里"harness 运行期间 SSH 始终连接"是个**承诺**，
     * 而承诺要么可观测、要么等于没有。心跳把"连接还活着"变成一个有时间的、可查的事实。
     */
    async heartbeat(targetId, options = {}) {
      if (!transport || typeof transport.heartbeat !== 'function') {
        return { ok: false, reason: 'no-transport', at: new Date().toISOString() };
      }
      const result = await transport.heartbeat(targetId, options);
      const prev = heartbeatStats.get(targetId) ?? { consecutiveFailures: 0 };

      // 失败原因的记忆：`no-session` 只是"现在没有会话"，不是断线原因。
      // 会话正是被上一次失败的心跳拆掉的，所以此时要沿用那一次的原因。
      let lastFailure = null;
      if (!result.ok) {
        lastFailure = result.reason === 'no-session'
          ? (heartbeatFailure.get(targetId) ?? null)
          : { reason: result.reason, error: result.error ?? null, at: result.at };
        if (lastFailure) heartbeatFailure.set(targetId, lastFailure);
      } else {
        heartbeatFailure.delete(targetId); // 恢复了就不再挂着旧故障
      }

      const next = {
        at: result.at,
        ok: result.ok,
        latencyMs: result.latencyMs ?? null,
        reason: result.reason ?? null,
        error: result.error ?? null,
        consecutiveFailures: result.ok ? 0 : (prev.consecutiveFailures ?? 0) + 1,
        lastFailure,
      };
      heartbeatStats.set(targetId, next);

      // 只在"状态发生变化"时写审计 —— 成功的心跳每分钟一次，全记会把日志淹掉
      // （与 §7.4 的心跳噪音问题同类）。
      //
      // ⚠️ 这里踩过一次：最初写成 `stateChanged || next.consecutiveFailures % 10 === 0`，
      //    而**成功时 consecutiveFailures 恒为 0、0 % 10 === 0 恒真** → 每次成功都写一条，
      //    "不淹没日志"完全失效。所以成功与失败要分开判：
      //      · 失败：第 1 次（状态刚变坏）与每 10 次（持续失败的心跳摘要）各记一条
      //      · 成功：只在"首次"或"从失败恢复"时记一条
      const justFailed = !result.ok && next.consecutiveFailures === 1;
      const stillFailing = !result.ok && next.consecutiveFailures % 10 === 0;
      const justRecovered = result.ok && prev.ok !== true;
      if (justFailed || stillFailing || justRecovered) {
        this.record(result.ok ? 'transport.heartbeat' : 'transport.heartbeat.failed', {
          targetId,
          ok: result.ok,
          latencyMs: next.latencyMs,
          reason: next.reason,
          consecutiveFailures: next.consecutiveFailures,
          error: next.error,
          // 持续失败时 reason 会退化成 no-session，审计里保留最初的真实原因
          failedReason: next.lastFailure?.reason ?? null,
          failedError: next.lastFailure?.error ?? null,
        });
      }
      return next;
    },

    /** 某目标最近一次心跳（供状态工具展示）。 */
    lastHeartbeat(targetId) {
      return heartbeatStats.get(targetId) ?? null;
    },

    // ---------- 每日报告 ----------

    /** 今天是否已经写过报告。 */
    async hasReportedToday({ targetId, day = dayKey(new Date()) }) {
      return (await readDay({ root: dir, targetId, day })) !== null;
    },

    /**
     * 写一份日报到文件，并把文件 sha256 记入审计链（I11）。
     *
     * 目标不可达时**也要写**（status: 'unreachable'）—— 否则"没有文件"无法区分
     * 「没跑」与「跑了但连不上」。但**没有任何采集能力时不写假报告**。
     */
    async writeDailyReport({ targetId, report, at = new Date() }) {
      const stamped = {
        ...report,
        audit: {
          hash: tailHash(audit.snapshot(), audit.anchor),
          count: audit.length,
          total: audit.total,
        },
      };
      const res = await writeReportFile({ root: dir, targetId, report: stamped, at });

      const digest = sha256Hex(readFileSync(res.path, 'utf8'));
      this.record('report.seal', {
        targetId, day: res.day, runCount: res.runCount, sha256: digest, status: report?.status ?? null,
      });
      return { ...res, sha256: digest };
    },

    /**
     * 校验某天报告是否被改动过。
     *
     * 做法：重算文件 sha256，与审计链里**最后一条**该 (targetId, day) 的封章比对。
     * 注意审计里的封章可能已被轮转出内存窗口，所以这里读的是完整审计序列。
     */
    async verifyReportSeal({ targetId, day }) {
      const path = reportPath(dir, targetId, day);
      if (!existsSync(path)) return { ok: false, reason: '报告文件不存在', path };

      const actual = sha256Hex(readFileSync(path, 'utf8'));
      const seals = readAuditSequence().records
        .filter((r) => r.event === 'report.seal' && r.targetId === targetId && r.day === day);
      const last = seals[seals.length - 1];
      if (!last) return { ok: false, reason: '审计链中找不到该报告的封章', path, actual };

      return {
        ok: last.sha256 === actual,
        path,
        expected: last.sha256,
        actual,
        sealedAt: last.ts,
        reason: last.sha256 === actual ? null : '报告内容与审计封章不一致（文件被改动过）',
      };
    },

    /**
     * 生成并写入某目标的当日报告。
     *
     * 幂等：当天已有报告时默认跳过（`force` 可强制追加一次 run）。
     * 这个幂等性是"重启后自动补跑"能安全实现的前提，也是定时器不怕重复触发的原因。
     */
    async generateDailyReport({ targetId, at = new Date(), force = false }) {
      const target = await this.findTarget(targetId);
      if (!target) throw new Error(`目标不存在: ${targetId}`);

      const day = dayKey(at);
      if (!force && await this.hasReportedToday({ targetId: target.id, day })) {
        return { skipped: true, reason: 'already-reported-today', day, targetId: target.id };
      }

      const canCollect = typeof this.factsProvider === 'function'
        || (transport && typeof transport.probeFacts === 'function');
      if (!canCollect) {
        // **不编造报告**：没有采集能力时不产生文件，只留一条可查的审计
        this.record('report.skipped', { targetId: target.id, day, reason: 'no-facts-source' });
        return { skipped: true, reason: 'no-facts-source', day, targetId: target.id };
      }

      let facts = null;
      let status = 'ok';
      let error = null;
      try {
        facts = await this.collectFacts(target);
        factsByTarget.set(target.id, facts);
        target.lastSeenAt = new Date().toISOString();
      } catch (err) {
        status = 'unreachable';
        // 错误文本必须脱敏后才进报告
        error = redactor.text(err?.message ?? String(err));
      }

      const prev = await latestReport({ root: dir, targetId: target.id });
      const payload = buildDailyReport({
        facts,
        prevDoc: prev?.doc ?? null,
        at,
        status,
        error,
      });
      const res = await this.writeDailyReport({ targetId: target.id, report: payload, at });
      return { skipped: false, day, status, ...res };
    },
  };

  // ── 启动时把"实际生效的策略"记入审计 ────────────────────────────────────
  // 审批阈值是可以放宽的（autoAllowUpTo=R2 就会让更多动作免弹窗）。
  // 这种改动必须**可审计**：事后能回答"当时到底是什么策略在放行"。
  engine.record('config.effective', {
    autoAllowUpTo: policy.autoAllowUpTo,
    prodEscalatesTo: policy.prodEscalatesTo,
    alwaysAskFrom: policy.alwaysAskFrom,
    echoHostnameAt: policy.echoHostnameAt,
    auditReadOnly: policy.auditReadOnly,
    planTtlMs: config.planTtlMs,
    maxAuditBytes: config.maxAuditBytes,
    maxRunBytes: config.maxRunBytes,
    warningCount: configWarnings.length,
  });
  for (const warning of configWarnings) engine.record('config.warning', { warning });

  return engine;
}
