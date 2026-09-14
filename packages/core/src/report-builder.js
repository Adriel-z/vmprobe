/**
 * 每日报告内容生成 —— 纯函数，不依赖传输层与 DSH，因此可完整单测。
 *
 * 设计要点（推演结论）：报告的**价值在于"趋势 + 异常"**，
 * 而不是把 facts 全量倾倒一遍。一份只有 facts 的报告，人不会看第二眼；
 * 「磁盘 / 从 41%→43%（正常）；待更新包 12→19（含 3 个安全更新）」才会被看。
 *
 * 因此这里做三件事：
 *   ① 从 facts 里**抽取少量可比较的指标**（其余细节留在 facts 文件里，不进报告）；
 *   ② 与上一份报告对比，算出差值；
 *   ③ 按规则判定异常（阈值 + 变化幅度），供上层决定是否提示。
 *
 * 缺失一律记 `null`，**绝不填 0** —— 0 会被读成"没有待更新"，即谎报一个更安全的状态。
 */

import { buildTrend } from './reports.js';

/**
 * 从 facts 里抽取可比较指标。
 *
 * 所有字段名都做了容错：facts 由协从端产出，不同发行版/权限下可能缺项。
 * @param {object|null} facts
 * @returns {object} 指标对象（缺失项为 null）
 */
export function extractMetrics(facts) {
  const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);

  const disks = Array.isArray(facts?.hw?.disk) ? facts.hw.disk : [];
  const root = disks.find((d) => d?.mount === '/') ?? disks[0] ?? null;

  const memTotal = num(facts?.hw?.mem?.totalMb);
  const memAvail = num(facts?.hw?.mem?.availMb);
  const memUsedPct = num(facts?.hw?.mem?.usedPct)
    ?? (memTotal && memAvail !== null
      ? Number((((memTotal - memAvail) / memTotal) * 100).toFixed(1))
      : null);

  return {
    diskUsedPct: num(root?.usedPct),
    diskSizeMb: num(root?.sizeMb),
    diskMount: root?.mount ?? null,
    memUsedPct,
    memTotalMb: memTotal,
    load1: num(facts?.load?.load1),
    cpuCores: num(facts?.hw?.cpu?.cores),
    upgradable: num(facts?.pkg?.upgradable),
    securityUpgradable: num(facts?.pkg?.securityUpgradable),
    rebootRequired: facts?.pkg?.rebootRequired === true,
    uptimeSec: num(facts?.load?.uptimeSec),
  };
}

/**
 * 组装一份日报载荷。
 *
 * @param {object} o
 * @param {object|null} o.facts 本次采集的 facts（可为 null，表示未采集）
 * @param {object|null} [o.prevDoc] 上一份报告文档（用于算趋势）
 * @param {Date|string|number} [o.at]
 * @param {'ok'|'unreachable'|'partial'|'not_probed'} [o.status]
 * @param {string|null} [o.error]
 * @returns {object} 可直接交给 `engine.writeDailyReport()` 的载荷
 */
export function buildDailyReport({
  facts,
  prevDoc = null,
  at = new Date(),
  status = 'ok',
  error = null,
}) {
  const iso = (at instanceof Date ? at : new Date(at)).toISOString();
  const metrics = extractMetrics(facts);
  const trend = buildTrend(prevDoc, { status, metrics });

  return {
    status,
    error: error ?? null,
    collectedAt: iso,
    // 环境摘要（人看报告时最需要的那几行）
    env: facts
      ? {
        hostname: facts.host?.hostname ?? null,
        os: facts.os?.id ?? null,
        osVersion: facts.os?.versionId ?? null,
        arch: facts.os?.arch ?? null,
        kernel: facts.host?.kernel ?? null,
        init: facts.init?.system ?? null,
        virt: facts.virt?.type ?? null,
        probeVersion: facts.probeVersion ?? null,
      }
      : null,
    metrics,
    trend,
    // 便于把报告与 facts 文件、run 记录串起来
    source: facts ? 'probe.facts' : 'none',
  };
}

/**
 * 判断一份报告是否值得主动提示（供上层决定要不要打扰用户）。
 *
 * 只挑"需要人处理"的异常，避免把日报变成噪音源。
 */
export function reportNeedsAttention(report) {
  const codes = new Set((report?.trend?.anomalies ?? []).map((a) => a.code));
  const attention = ['unreachable', 'security-pending', 'disk-high', 'disk-jump', 'reboot-required'];
  return attention.filter((c) => codes.has(c));
}
