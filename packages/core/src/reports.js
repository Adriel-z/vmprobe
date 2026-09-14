/**
 * 每日报告文件子系统（对应需求："每天固定时间报告一次，直接以文件形式保存在文件夹，
 * 文件以时间命名，确保每天的独立存放"）。
 *
 * ── 命名与布局 ────────────────────────────────────────────────────────────
 *   <root>/reports/<targetId>/<YYYY>/<YYYY-MM-DD>.json
 *
 * 三项刻意的决定，都来自推演出来的坑：
 *
 * 1. **日键用 UTC，不用本地时间。** 本地时间遇夏令时切换会出现"某天 08:00 不存在"
 *    或"同一天触发两次"，从而撞名或漏天。UTC 日键单调、无歧义。
 *    报告**内部**同时记录本地时间与时区，供人阅读。
 *
 * 2. **文件名里绝不能有冒号。** 朴素做法（RFC3339 时间戳）产生
 *    `2026-09-14T08:00:00Z.json`，而 `:` 在 Windows 上是非法文件名字符 ——
 *    需求明确要求"跨平台可用"，所以用 `2026-09-14.json`。
 *    顺带好处：字典序 = 时间序，列目录即得时间线。
 *
 * 3. **一天多个文件不如一天一个文件、内含多次运行。** 定时报告与手动报告可能同日发生；
 *    按天分文件保证"每天独立存放"，`runs[]` 数组保证不丢掉任何一次。
 *    用临时文件 + rename 原子替换，避免半个文件。
 *
 * ── 缺天怎么处理 ──────────────────────────────────────────────────────────
 * **不补造。** DSH 没运行就是没运行，凭空生成一份"报告"是伪造数据。
 * 缺天用 `findGaps()` 如实算出来，让上层能说"9-12 到 9-14 有 2 天没有报告"。
 *
 * ── 目标不可达怎么处理 ────────────────────────────────────────────────────
 * **照样落文件**，内容记 `{ status: 'unreachable', error }`。
 * 否则"没有文件"既可能是没跑、也可能是跑了但连不上，无法区分。
 */

import { mkdir, readFile, readdir, rename, rm, writeFile, chmod } from 'node:fs/promises';
import { dirname, join } from 'node:path';

import { assertSafeId } from './store.js';

export const REPORT_SCHEMA = 'vmprobe/report/1';

const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * 把时刻规约为 UTC 日键 `YYYY-MM-DD`。
 * @param {Date|string|number} [at]
 */
export function dayKey(at = new Date()) {
  const d = at instanceof Date ? at : new Date(at);
  if (Number.isNaN(d.getTime())) throw new Error(`无法解析时间: ${String(at)}`);
  return d.toISOString().slice(0, 10);
}

/** 校验日键格式（也是防目录穿越的一道闸）。 */
export function assertDayKey(day) {
  if (typeof day !== 'string' || !DAY_RE.test(day)) {
    throw new Error(`日键必须是 YYYY-MM-DD，实际 ${JSON.stringify(day)}`);
  }
  return day;
}

/** 报告目录：按年分片，避免单目录堆积上万条目。 */
export function reportDir(root, targetId, day) {
  assertSafeId(targetId, 'targetId');
  assertDayKey(day);
  return join(root, 'reports', targetId, day.slice(0, 4));
}

/** 日报文件路径。文件名只有数字与连字符 —— Windows / Linux 均合法。 */
export function reportPath(root, targetId, day) {
  return join(reportDir(root, targetId, day), `${assertDayKey(day)}.json`);
}

async function readJsonOrNull(file) {
  try {
    return JSON.parse(await readFile(file, 'utf8'));
  } catch (err) {
    if (err && (err.code === 'ENOENT' || err instanceof SyntaxError)) return null;
    throw err;
  }
}

async function writeJsonAtomic(file, value) {
  await mkdir(dirname(file), { recursive: true });
  const tmp = `${file}.tmp-${process.pid}-${Date.now()}`;
  await writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  await rename(tmp, file);
  try {
    await chmod(file, 0o600);
  } catch {
    /* Windows：忽略 */
  }
}

/**
 * 写入一次报告（同一天多次调用会追加进同一天的 `runs[]`）。
 *
 * @param {object} o
 * @param {string} o.root 存储根目录
 * @param {string} o.targetId 目标 id（会做安全校验）
 * @param {object} o.report 报告主体（`status` 建议为 ok | unreachable | partial）
 * @param {Date|string|number} [o.at] 生成时刻（默认现在）
 * @returns {Promise<{ path: string, day: string, runCount: number }>}
 */
export async function writeReport({ root, targetId, report, at = new Date() }) {
  const day = dayKey(at);
  const path = reportPath(root, targetId, day);
  const iso = (at instanceof Date ? at : new Date(at)).toISOString();

  const existing = await readJsonOrNull(path);
  const doc = existing ?? {
    schema: REPORT_SCHEMA,
    day,
    targetId,
    createdAt: iso,
    runs: [],
  };

  if (doc.schema !== REPORT_SCHEMA) {
    // 不猜、不迁移：版本不符时明确报错，避免把旧结构写坏
    throw new Error(`报告文件 schema 不符（${path} 里是 ${doc.schema}，期望 ${REPORT_SCHEMA}）`);
  }

  doc.runs.push({ at: iso, ...report });
  doc.updatedAt = iso;

  await writeJsonAtomic(path, doc);
  return { path, day, runCount: doc.runs.length };
}

/** 读某一天的报告（不存在返回 null，不抛错）。 */
export async function readDay({ root, targetId, day }) {
  assertDayKey(day);
  return readJsonOrNull(reportPath(root, targetId, day));
}

/** 列出已有报告的日键（升序 = 时间序）。 */
export async function listDays({ root, targetId }) {
  assertSafeId(targetId, 'targetId');
  const base = join(root, 'reports', targetId);
  const days = [];
  let years;
  try {
    years = await readdir(base);
  } catch (err) {
    if (err && err.code === 'ENOENT') return [];
    throw err;
  }
  for (const year of years) {
    if (!/^\d{4}$/.test(year)) continue;
    let files;
    try {
      files = await readdir(join(base, year));
    } catch {
      continue;
    }
    for (const f of files) {
      const m = /^(\d{4}-\d{2}-\d{2})\.json$/.exec(f);
      if (m) days.push(m[1]);
    }
  }
  return days.sort();
}

/** 最近一份报告（含它是哪一天的）。 */
export async function latestReport({ root, targetId }) {
  const days = await listDays({ root, targetId });
  if (!days.length) return null;
  const day = days[days.length - 1];
  return { day, doc: await readDay({ root, targetId, day }) };
}

/**
 * 算出区间内**缺失**的日键。
 *
 * 注意这是"如实报缺"而不是"补造"：返回的是空缺清单，由上层决定怎么呈现。
 * @param {{ root: string, targetId: string, from: string, to: string }} o
 */
export async function findGaps({ root, targetId, from, to }) {
  const start = assertDayKey(from);
  const end = assertDayKey(to);
  if (start > end) throw new Error(`from(${start}) 晚于 to(${end})`);

  const have = new Set(await listDays({ root, targetId }));
  const gaps = [];
  const cur = new Date(`${start}T00:00:00Z`);
  const last = new Date(`${end}T00:00:00Z`);
  while (cur.getTime() <= last.getTime()) {
    const d = dayKey(cur);
    if (!have.has(d)) gaps.push(d);
    cur.setUTCDate(cur.getUTCDate() + 1);
  }
  return gaps;
}

/**
 * 清理历史报告。
 *
 * 策略：近 `keepDays` 天全留；更早的**每月只留 1 号**（保留长期趋势），其余删除。
 * 必须存在上限 —— 一天一个文件、多目标相乘，不清就会无限膨胀。
 *
 * @returns {Promise<{ deleted: string[], kept: number }>}
 */
export async function pruneReports({ root, targetId, keepDays = 90, now = new Date() }) {
  const days = await listDays({ root, targetId });
  const cutoff = new Date(now);
  cutoff.setUTCDate(cutoff.getUTCDate() - keepDays);
  const cutoffDay = dayKey(cutoff);

  const deleted = [];
  let kept = 0;
  for (const day of days) {
    const isRecent = day >= cutoffDay;
    const isMonthlyKeep = day.endsWith('-01');
    if (isRecent || isMonthlyKeep) {
      kept++;
      continue;
    }
    const dir = reportDir(root, targetId, day);
    await rm(join(dir, `${day}.json`), { force: true });
    deleted.push(day);
  }

  // 清掉空的年份目录，避免留下空壳
  const base = join(root, 'reports', targetId);
  try {
    for (const year of await readdir(base)) {
      const p = join(base, year);
      const left = await readdir(p);
      if (left.length === 0) await rm(p, { recursive: true, force: true });
    }
  } catch {
    /* 忽略清理空目录的失败 */
  }

  return { deleted, kept };
}

/**
 * 生成趋势与异常 —— 报告的**价值所在**（不是把 facts 全量倾倒一遍）。
 *
 * @param {object|null} prevDoc 上一次报告（可为 null）
 * @param {object} curDoc 本次报告
 */
export function buildTrend(prevDoc, curDoc) {
  const cur = curDoc?.runs?.[curDoc.runs.length - 1] ?? curDoc;
  const prev = prevDoc ? (prevDoc.runs?.[prevDoc.runs.length - 1] ?? prevDoc) : null;
  const m = (r) => r?.metrics ?? {};
  const c = m(cur);
  const p = m(prev);

  const deltas = {};
  for (const key of ['diskUsedPct', 'upgradable', 'securityUpgradable', 'load1', 'memUsedPct']) {
    if (typeof c[key] === 'number' && typeof p[key] === 'number') {
      deltas[key] = Number((c[key] - p[key]).toFixed(2));
    }
  }

  const anomalies = [];
  if (cur?.status === 'unreachable') anomalies.push({ code: 'unreachable', detail: cur.error ?? '目标不可达' });
  if (typeof c.diskUsedPct === 'number' && c.diskUsedPct >= 85) {
    anomalies.push({ code: 'disk-high', detail: `根分区已用 ${c.diskUsedPct}%` });
  }
  if (typeof deltas.diskUsedPct === 'number' && deltas.diskUsedPct >= 5) {
    anomalies.push({ code: 'disk-jump', detail: `磁盘占用一日增长 ${deltas.diskUsedPct} 个百分点` });
  }
  if (typeof c.securityUpgradable === 'number' && c.securityUpgradable > 0) {
    anomalies.push({ code: 'security-pending', detail: `${c.securityUpgradable} 个安全更新待装` });
  }
  if (c.rebootRequired === true) {
    anomalies.push({ code: 'reboot-required', detail: '系统要求重启' });
  }
  if (prev === null) {
    anomalies.push({ code: 'no-baseline', detail: '首次报告，无对比基线' });
  }

  return { deltas, anomalies, hadBaseline: prev !== null };
}
