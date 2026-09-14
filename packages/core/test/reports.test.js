/**
 * 每日报告文件子系统单测 —— 对应新需求「每天独立存放、以时间命名」。
 *
 * 重点覆盖三类跨平台/长期运行的坑：
 *   · 文件名合法性（Windows 非法字符、字典序 = 时间序）
 *   · 一天多次运行与跨日隔离、缺天如实报出
 *   · 保留策略（否则一天一文件会无限膨胀）
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

import {
  REPORT_SCHEMA,
  assertDayKey,
  buildTrend,
  dayKey,
  findGaps,
  latestReport,
  listDays,
  pruneReports,
  readDay,
  reportPath,
  writeReport,
} from '../src/reports.js';

const newRoot = () => mkdtemp(join(tmpdir(), 'vmprobe-reports-'));

test('日键为 UTC，且单调、无歧义', () => {
  assert.equal(dayKey('2026-09-14T23:59:59Z'), '2026-09-14');
  assert.equal(dayKey('2026-09-15T00:00:00Z'), '2026-09-15');
  // 跨夏令时的本地时间不影响 UTC 日键
  assert.equal(dayKey(new Date('2026-03-08T12:00:00Z')), '2026-03-08');
  assert.throws(() => dayKey('not-a-date'), /无法解析时间/);
});

test('文件名跨平台合法：无 Windows 非法字符，且不含冒号', () => {
  const p = reportPath('/tmp/root', 't_a1b2', '2026-09-14');
  const name = basename(p);
  assert.equal(name, '2026-09-14.json');
  assert.ok(!/[:*?"<>|]/.test(name), '文件名不得含 Windows 非法字符');
  // 反面示例：若直接拿 RFC3339 时间戳命名就会踩坑
  assert.ok(/[:*?"<>|]/.test(basename('2026-09-14T08:00:00Z.json')));
});

test('字典序 = 时间序（列目录即得时间线）', () => {
  const names = ['2026-10-01', '2026-09-30', '2026-09-09'].map((d) => basename(reportPath('/r', 't', d)));
  assert.deepEqual([...names].sort(), ['2026-09-09.json', '2026-09-30.json', '2026-10-01.json']);
});

test('日键与 targetId 双重防穿越', () => {
  assert.throws(() => assertDayKey('2026-9-4'), /YYYY-MM-DD/);
  assert.throws(() => assertDayKey('../etc'), /YYYY-MM-DD/);
  assert.throws(() => reportPath('/r', '../../evil', '2026-09-14'), /targetId 非法/);
  assert.throws(() => reportPath('/r', 'a/b', '2026-09-14'), /targetId 非法/);
  assert.throws(() => reportPath('/r', 'a:b', '2026-09-14'), /targetId 非法/);
});

test('同一天多次运行 → 同一文件、runs 追加（不丢任何一次）', async () => {
  const root = await newRoot();
  try {
    const a = await writeReport({ root, targetId: 't_vm', report: { status: 'ok', n: 1 }, at: '2026-09-14T08:00:00Z' });
    const b = await writeReport({ root, targetId: 't_vm', report: { status: 'ok', n: 2 }, at: '2026-09-14T20:00:00Z' });
    assert.equal(a.path, b.path);
    assert.equal(b.runCount, 2);

    const doc = await readDay({ root, targetId: 't_vm', day: '2026-09-14' });
    assert.equal(doc.schema, REPORT_SCHEMA);
    assert.equal(doc.day, '2026-09-14');
    assert.deepEqual(doc.runs.map((r) => r.n), [1, 2]);
    assert.equal(doc.createdAt, '2026-09-14T08:00:00.000Z');
    assert.equal(doc.updatedAt, '2026-09-14T20:00:00.000Z');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('跨日独立成文件，且无临时文件残留', async () => {
  const root = await newRoot();
  try {
    await writeReport({ root, targetId: 't_vm', report: { status: 'ok' }, at: '2026-09-14T08:00:00Z' });
    await writeReport({ root, targetId: 't_vm', report: { status: 'ok' }, at: '2026-09-15T08:00:00Z' });
    assert.deepEqual(await listDays({ root, targetId: 't_vm' }), ['2026-09-14', '2026-09-15']);
    const files = await readdir(join(root, 'reports', 't_vm', '2026'));
    assert.deepEqual(files, ['2026-09-14.json', '2026-09-15.json']);
    assert.ok(!files.some((f) => f.includes('.tmp-')));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('目标不可达也要落盘并如实标记（否则"没文件"无法区分没跑/连不上）', async () => {
  const root = await newRoot();
  try {
    await writeReport({
      root, targetId: 't_vm',
      report: { status: 'unreachable', error: 'connect timeout' },
      at: '2026-09-14T08:00:00Z',
    });
    const doc = await readDay({ root, targetId: 't_vm', day: '2026-09-14' });
    assert.equal(doc.runs[0].status, 'unreachable');
    assert.equal(doc.runs[0].error, 'connect timeout');
    // 趋势里也应体现为异常
    const trend = buildTrend(null, doc);
    assert.ok(trend.anomalies.some((a) => a.code === 'unreachable'));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('缺天如实报出（不补造）', async () => {
  const root = await newRoot();
  try {
    await writeReport({ root, targetId: 't_vm', report: { status: 'ok' }, at: '2026-09-14T08:00:00Z' });
    await writeReport({ root, targetId: 't_vm', report: { status: 'ok' }, at: '2026-09-17T08:00:00Z' });
    assert.deepEqual(
      await findGaps({ root, targetId: 't_vm', from: '2026-09-14', to: '2026-09-17' }),
      ['2026-09-15', '2026-09-16'],
    );
    assert.deepEqual(await findGaps({ root, targetId: 't_vm', from: '2026-09-14', to: '2026-09-14' }), []);
    // findGaps 是 async：越界应表现为 rejected promise，而不是同步抛出
    await assert.rejects(
      () => findGaps({ root, targetId: 't_vm', from: '2026-09-17', to: '2026-09-14' }),
      /晚于/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('latestReport 取最近一天', async () => {
  const root = await newRoot();
  try {
    assert.equal(await latestReport({ root, targetId: 't_vm' }), null);
    await writeReport({ root, targetId: 't_vm', report: { status: 'ok', n: 1 }, at: '2026-09-01T08:00:00Z' });
    await writeReport({ root, targetId: 't_vm', report: { status: 'ok', n: 2 }, at: '2026-09-09T08:00:00Z' });
    const latest = await latestReport({ root, targetId: 't_vm' });
    assert.equal(latest.day, '2026-09-09');
    assert.equal(latest.doc.runs[0].n, 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('保留策略：窗口内全留，窗口外每月留 1 号，并清空目录', async () => {
  const root = await newRoot();
  try {
    const now = new Date('2026-09-14T00:00:00Z'); // keepDays=30 → 窗口起点 2026-08-15
    for (const d of ['2026-06-01', '2026-06-15', '2026-06-20', '2026-08-20', '2026-09-13']) {
      await writeReport({ root, targetId: 't_vm', report: { status: 'ok' }, at: `${d}T08:00:00Z` });
    }
    const res = await pruneReports({ root, targetId: 't_vm', keepDays: 30, now });
    assert.deepEqual(res.deleted.sort(), ['2026-06-15', '2026-06-20']);
    assert.deepEqual(await listDays({ root, targetId: 't_vm' }), ['2026-06-01', '2026-08-20', '2026-09-13']);
    assert.equal(res.kept, 3);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('schema 不符时拒绝写入，而不是把旧结构写坏', async () => {
  const root = await newRoot();
  try {
    await writeReport({ root, targetId: 't_vm', report: { status: 'ok' }, at: '2026-09-14T08:00:00Z' });
    const p = reportPath(root, 't_vm', '2026-09-14');
    const { writeFile } = await import('node:fs/promises');
    await writeFile(p, JSON.stringify({ schema: 'vmprobe/report/99', runs: [] }), 'utf8');
    await assert.rejects(
      () => writeReport({ root, targetId: 't_vm', report: { status: 'ok' }, at: '2026-09-14T09:00:00Z' }),
      /schema 不符/,
    );
    // 原文件未被破坏
    const raw = JSON.parse(await readFile(p, 'utf8'));
    assert.equal(raw.schema, 'vmprobe/report/99');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('趋势：差值、异常判定、无基线', () => {
  const prev = { runs: [{ status: 'ok', metrics: { diskUsedPct: 41, upgradable: 12, securityUpgradable: 0 } }] };
  const cur = { runs: [{ status: 'ok', metrics: { diskUsedPct: 49, upgradable: 19, securityUpgradable: 3, rebootRequired: true } }] };
  const t = buildTrend(prev, cur);
  assert.equal(t.deltas.diskUsedPct, 8);
  assert.equal(t.deltas.upgradable, 7);
  assert.equal(t.hadBaseline, true);
  const codes = t.anomalies.map((a) => a.code).sort();
  assert.deepEqual(codes, ['disk-jump', 'reboot-required', 'security-pending']);

  const first = buildTrend(null, cur);
  assert.equal(first.hadBaseline, false);
  assert.ok(first.anomalies.some((a) => a.code === 'no-baseline'));

  // 磁盘超阈值也要报
  const high = buildTrend(prev, { runs: [{ status: 'ok', metrics: { diskUsedPct: 91 } }] });
  assert.ok(high.anomalies.some((a) => a.code === 'disk-high'));
});
