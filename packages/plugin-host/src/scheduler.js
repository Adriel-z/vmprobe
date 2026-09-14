/**
 * 每日报告调度器。
 *
 * ── 为什么不用 `ctx.interval(cb, 86400000)` 直接"每 24 小时跑一次" ──────────
 * 已静态核实 `cordis-plugin-timer` 的 API：`ctx.interval(callback, delay): () => void`
 * 是**固定频率**定时器，句柄注册在当前 fiber 上、插件释放时自动清理。
 *
 * 但固定频率做"每天固定时间"有三个无法回避的问题：
 *   ① **漂移**：从插件加载时刻起算，墙钟到点时刻会一直偏；
 *   ② **重启错位**：中途重启，计时重新开始，可能整天不触发或一天触发两次；
 *   ③ **夏令时**：本地时间加 24 小时的语义在切换日会错。
 *
 * ── 采用的做法：短周期 tick + 幂等判定 ────────────────────────────────────
 * 每 60 秒 tick 一次，判断"今天到点了吗？今天已经生成过了吗？"。
 * 这样做的好处是把"定时"变成**幂等状态判定**：
 *   · 重启后自动补跑当天（因为"今天还没生成"仍然成立）——崩溃恢复是免费的；
 *   · 重复触发无副作用（当天已生成则跳过）；
 *   · 无需管理漂移与夏令时；
 *   · 与"一天一个文件"的存储设计天然吻合（幂等键就是 UTC 日键）。
 *
 * ── 边界行为 ──────────────────────────────────────────────────────────────
 * · **不补造过去的报告**：进程停了三天，那三天的文件就是不存在，
 *   由 `reports.findGaps()` 如实报缺，而不是事后编一份出来。
 * · **没有采集能力就不写文件**：宁可不产生报告，也不产生一份假报告。
 * · 时刻以 **UTC** 表达（`reportAtUtc`），与 UTC 日键保持一致，避免边界歧义。
 */

import { redactText } from '../../core/src/index.js';

const AT_RE = /^([01]\d|2[0-3]):([0-5]\d)$/;

/** 校验并归一化 `HH:MM`（UTC）。 */
export function normalizeAtUtc(value) {
  if (typeof value !== 'string' || !AT_RE.test(value)) {
    throw new Error(`reportAtUtc 必须是 UTC 的 HH:MM，实际 ${JSON.stringify(value)}`);
  }
  return value;
}

/**
 * 启动调度器。
 *
 * @param {object} o
 * @param {object} o.engine createEngine 的返回值
 * @param {object} [o.ctx] CORDIS 上下文（只需 `interval` 与 `logger`）
 * @param {object} [o.config]
 * @param {boolean} [o.config.dailyReport] 是否启用（默认 true）
 * @param {string} [o.config.reportAtUtc] 每天的触发时刻（UTC，默认 '08:00'）
 * @param {number} [o.config.tickMs] tick 间隔（默认 60000）
 * @param {string[]} [o.config.reportTargets] 只报告这些目标（默认全部）
 * @returns {{ run: Function, stop: Function, atUtc: string, scheduled: boolean }}
 */
/**
 * 启动连接心跳。
 *
 * 需求里的"harness 运行期间 SSH 始终连接"是个承诺，而承诺要么可观测、要么等于没有。
 * 心跳做三件事：① 定期在**已有会话**上跑一条极轻的命令（顺带让链路不至于被中间设备静默回收）；
 * ② 测出延迟；③ 失败即把会话标成 detached —— 状态与事实一致，不留"看起来还连着"的假象。
 *
 * 与每日报告共用同一个 timer 服务，但**各自独立**：报告是业务（每天一次），心跳是观测（每分钟）。
 *
 * @param {object} o
 * @param {object} o.engine
 * @param {object} [o.ctx]
 * @param {object} [o.config]
 * @param {boolean} [o.config.heartbeat] 是否启用（默认 true）
 * @param {number} [o.config.heartbeatIntervalMs] 间隔（默认 60000）
 * @param {number} [o.config.heartbeatTimeoutMs] 单次超时（默认 5000）
 */
export function startTransportHeartbeat({ engine, ctx, config = {} }) {
  const enabled = config.heartbeat !== false;
  const intervalMs = Number.isInteger(config.heartbeatIntervalMs) && config.heartbeatIntervalMs > 0
    ? config.heartbeatIntervalMs
    : 60_000;
  const timeoutMs = Number.isInteger(config.heartbeatTimeoutMs) && config.heartbeatTimeoutMs > 0
    ? config.heartbeatTimeoutMs
    : 5_000;

  const log = (level, msg) => ctx?.logger?.[level]?.(`vmprobe: ${msg}`);

  async function tick() {
    if (!enabled) return { skipped: true, reason: 'disabled' };
    if (!engine.transport || typeof engine.transport.heartbeat !== 'function') {
      return { skipped: true, reason: 'no-transport' };
    }
    // 只对**已有会话**的目标心跳：心跳的职责是观察，不该主动拉起连接 ——
    // 否则"心跳成功"会掩盖"其实早就断了、只是刚被拉起来"这件事。
    const ids = typeof engine.transport.activeTargetIds === 'function'
      ? engine.transport.activeTargetIds()
      : [];
    if (!ids.length) return { skipped: true, reason: 'no-active-session' };

    const results = [];
    for (const id of ids) {
      const r = await engine.heartbeat(id, { timeoutMs });
      results.push({ targetId: id, ...r });
      if (!r.ok && r.consecutiveFailures === 1) {
        log('warn', `连接心跳失败（${id}）：${r.reason}${r.error ? ` —— ${String(r.error).slice(0, 120)}` : ''}`);
      }
    }
    return { ran: true, results };
  }

  let dispose = null;
  if (typeof ctx?.interval === 'function') {
    dispose = ctx.interval(() => {
      tick().catch((err) => log('warn', `心跳任务异常：${err?.message ?? err}`));
    }, intervalMs);
  } else {
    log('warn', 'ctx.interval 不可用，连接心跳未启动');
  }

  return {
    tick,
    intervalMs,
    get scheduled() {
      return dispose !== null;
    },
    stop() {
      if (typeof dispose === 'function') dispose();
      dispose = null;
    },
  };
}

export function startDailyReportScheduler({ engine, ctx, config = {} }) {
  const enabled = config.dailyReport !== false;
  const atUtc = normalizeAtUtc(config.reportAtUtc ?? '08:00');
  const tickMs = Number.isInteger(config.tickMs) && config.tickMs > 0 ? config.tickMs : 60_000;
  const only = Array.isArray(config.reportTargets) ? config.reportTargets : null;
  const retentionDays = Number.isInteger(config.reportRetentionDays) && config.reportRetentionDays >= 0
    ? config.reportRetentionDays
    : 90;

  const log = (level, msg) => {
    const text = redactText(`vmprobe: ${msg}`, { registered: [] });
    ctx?.logger?.[level]?.(text);
  };

  /** 单飞：一次只跑一轮，避免 tick 重叠。 */
  let inFlight = false;

  /**
   * 保留策略（技术债 #5）：**每天跑一次**清理，而不是每次 tick 都扫一遍目录。
   *
   * 用"今天清理过了吗"做幂等键 —— 与日报用 UTC 日键是同一套思路：
   * 重启后自动补跑、重复触发无副作用、不需要管理漂移。
   */
  let lastPrunedDay = null;

  async function pruneIfDue(now, results) {
    if (typeof engine.pruneReports !== 'function') return null;
    const day = now.toISOString().slice(0, 10);
    if (lastPrunedDay === day) return null;
    try {
      const res = await engine.pruneReports({ keepDays: retentionDays, now });
      lastPrunedDay = day;
      if (res?.removed?.length) {
        log('info', `已清理 ${res.removed.length} 份过期日报（保留近 ${retentionDays} 天 + 每月 1 号）`);
      }
      results.push({ prune: res });
      return res;
    } catch (err) {
      // 清理失败**不能**影响报告生成，但也不能静默：否则报告会无声膨胀
      const message = engine.redactor?.text ? engine.redactor.text(err?.message ?? String(err)) : String(err);
      log('warn', `日报清理失败：${message}`);
      results.push({ prune: { error: message } });
      return null;
    }
  }

  /**
   * 跑一轮判定 + 生成。
   * @param {Date} [now] 便于测试注入时间
   */
  async function run(now = new Date()) {
    if (!enabled) return { skipped: true, reason: 'disabled' };

    const hhmm = now.toISOString().slice(11, 16);
    // 未到点：什么都不做（这也是"重启后补跑"能成立的原因 —— 只要还没到点就不该生成）
    if (hhmm < atUtc) {
      return { skipped: true, reason: 'before-scheduled-time', atUtc, nowUtc: hhmm };
    }
    if (inFlight) return { skipped: true, reason: 'in-flight' };

    inFlight = true;
    try {
      const targetIds = only ?? (await engine.listTargets()).map((t) => t.id);
      const results = [];
      for (const targetId of targetIds) {
        try {
          const res = await engine.generateDailyReport({ targetId, at: now });
          if (!res.skipped) log('info', `已生成 ${targetId} 的 ${res.day} 日报（status=${res.status}）`);
          results.push(res);
        } catch (err) {
          const message = engine.redactor.text(err?.message ?? String(err));
          log('warn', `生成 ${targetId} 的日报失败：${message}`);
          results.push({ targetId, error: message });
        }
      }
      // 生成之后再清理：先别说"留下今天的"再删
      await pruneIfDue(now, results);
      return { ran: true, atUtc, nowUtc: hhmm, results };
    } finally {
      inFlight = false;
    }
  }

  let dispose = null;
  if (typeof ctx?.interval === 'function') {
    dispose = ctx.interval(() => {
      run().catch((err) => log('warn', `日报定时任务异常：${err?.message ?? err}`));
    }, tickMs);
  } else {
    // 不静默失败：明确告警，否则"定时器没启动"会表现为"报告一直没出现"而无人知晓
    log('warn', 'ctx.interval 不可用，每日报告定时器未启动（inject 是否包含 timer？）');
  }

  return {
    run,
    atUtc,
    tickMs,
    get scheduled() {
      return dispose !== null;
    },
    stop() {
      if (typeof dispose === 'function') dispose();
      dispose = null;
    },
  };
}
