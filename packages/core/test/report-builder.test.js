/**
 * 报告内容生成单测 —— 指标抽取 + 趋势/异常。
 *
 * 最要紧的一条：**缺失必须记 null，绝不填 0**。
 * 填 0 会让"未知"看起来像"没有待更新/负载为零"，即谎报一个更安全的状态。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildDailyReport, extractMetrics, reportNeedsAttention } from '../src/report-builder.js';

/** 贴近 agent/bootstrap.sh 实际输出的 facts。 */
const FACTS = {
  schema: 'vmprobe/facts/1',
  probeVersion: 1,
  host: { hostname: 'vm-a', kernel: '6.14.0-11-generic' },
  os: { id: 'ubuntu', idLike: 'debian', versionId: '26.04', arch: 'amd64' },
  init: { system: 'systemd' },
  pkg: { managers: 'apt-get', default: 'apt-get', upgradable: 12, securityUpgradable: 3, rebootRequired: false },
  virt: { type: 'kvm', container: 'none' },
  load: { load1: 0.42, load5: 0.5, load15: 0.6, uptimeSec: 123456 },
  hw: {
    cpu: { cores: 4 },
    mem: { totalMb: 8192, availMb: 6144 },
    disk: [{ mount: '/', sizeMb: 40960, usedPct: 43 }],
  },
  ssh: { port: 22, pubkeyAuth: true, passwordAuth: true },
  caps: { root: true, sudo: true, systemd: true },
};

test('从 facts 抽取指标（含 memUsedPct 的推导）', () => {
  const m = extractMetrics(FACTS);
  assert.equal(m.diskUsedPct, 43);
  assert.equal(m.diskSizeMb, 40960);
  assert.equal(m.diskMount, '/');
  assert.equal(m.memTotalMb, 8192);
  assert.equal(m.memUsedPct, 25, '(8192-6144)/8192 = 25%');
  assert.equal(m.load1, 0.42);
  assert.equal(m.cpuCores, 4);
  assert.equal(m.upgradable, 12);
  assert.equal(m.securityUpgradable, 3);
  assert.equal(m.rebootRequired, false);
  assert.equal(m.uptimeSec, 123456);
});

test('优先使用 facts 自报的 memUsedPct', () => {
  const m = extractMetrics({ ...FACTS, hw: { ...FACTS.hw, mem: { totalMb: 100, availMb: 50, usedPct: 61.5 } } });
  assert.equal(m.memUsedPct, 61.5);
});

test('缺失一律 null，绝不填 0（0 会被读成"没有待更新"）', () => {
  const m = extractMetrics({ probeVersion: 1, pkg: {}, hw: {}, load: {} });
  for (const key of ['diskUsedPct', 'memUsedPct', 'load1', 'upgradable', 'securityUpgradable', 'cpuCores']) {
    assert.equal(m[key], null, `${key} 应为 null 而不是 0`);
  }
  assert.equal(extractMetrics(null).upgradable, null);
  assert.equal(extractMetrics(undefined).diskUsedPct, null);
});

test('取根分区而不是第一个杂项分区', () => {
  const m = extractMetrics({
    hw: { disk: [{ mount: '/boot', usedPct: 12 }, { mount: '/', usedPct: 77 }] },
  });
  assert.equal(m.diskUsedPct, 77);
  assert.equal(m.diskMount, '/');
});

test('组装日报：环境摘要 + 指标 + 趋势', () => {
  const r = buildDailyReport({ facts: FACTS, at: '2026-09-14T08:00:00Z' });
  assert.equal(r.status, 'ok');
  assert.equal(r.source, 'probe.facts');
  assert.equal(r.collectedAt, '2026-09-14T08:00:00.000Z');
  assert.equal(r.env.hostname, 'vm-a');
  assert.equal(r.env.os, 'ubuntu');
  assert.equal(r.env.kernel, '6.14.0-11-generic');
  assert.equal(r.env.probeVersion, 1);
  assert.equal(r.metrics.upgradable, 12);
  // 首次报告没有基线
  assert.equal(r.trend.hadBaseline, false);
  assert.ok(r.trend.anomalies.some((a) => a.code === 'no-baseline'));
  // 有 3 个安全更新 → 应判为需要关注
  assert.ok(r.trend.anomalies.some((a) => a.code === 'security-pending'));
});

test('组装日报：与上一份对比出差值与变化类异常', () => {
  const prev = { runs: [{ status: 'ok', metrics: { diskUsedPct: 41, upgradable: 12, securityUpgradable: 0 } }] };
  const cur = buildDailyReport({
    facts: { ...FACTS, hw: { ...FACTS.hw, disk: [{ mount: '/', usedPct: 49 }] } },
    prevDoc: prev,
    at: '2026-09-14T08:00:00Z',
  });
  assert.equal(cur.trend.hadBaseline, true);
  assert.equal(cur.trend.deltas.diskUsedPct, 8);
  assert.ok(cur.trend.anomalies.some((a) => a.code === 'disk-jump'));
});

test('不可达时仍能组装（status + error），且 env 为 null', () => {
  const r = buildDailyReport({
    facts: null, status: 'unreachable', error: 'connect timeout', at: '2026-09-14T08:00:00Z',
  });
  assert.equal(r.status, 'unreachable');
  assert.equal(r.error, 'connect timeout');
  assert.equal(r.env, null);
  assert.equal(r.source, 'none');
  assert.equal(r.metrics.upgradable, null);
  assert.ok(r.trend.anomalies.some((a) => a.code === 'unreachable'));
});

test('reportNeedsAttention 只挑需要人处理的异常', () => {
  const r = buildDailyReport({ facts: FACTS, at: '2026-09-14T08:00:00Z' });
  assert.ok(reportNeedsAttention(r).includes('security-pending'));
  assert.ok(!reportNeedsAttention(r).includes('no-baseline'), '首次报告无基线不该打扰用户');
  assert.deepEqual(reportNeedsAttention(null), []);
});

test('磁盘高位触发 disk-high', () => {
  const r = buildDailyReport({
    facts: { ...FACTS, hw: { ...FACTS.hw, disk: [{ mount: '/', usedPct: 91 }] } },
    at: '2026-09-14T08:00:00Z',
  });
  assert.ok(reportNeedsAttention(r).includes('disk-high'));
});
