/**
 * plan 新鲜度（TOCTOU 防护）单测 —— 对应推演发现 I7。
 *
 * 要证明的核心命题：**用户批准的那一刻之后，环境若变了，就不能沿用原批准执行**。
 * 两道关分别覆盖两个维度：时间（有效期）与内容（状态指纹）。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { loadCatalog } from '../../catalog/src/index.js';
import { PLAN_TTL_MS, buildPlan, checkFingerprint, checkPlanFreshness } from '../src/plan.js';

const here = dirname(fileURLToPath(import.meta.url));
const { actions } = loadCatalog(join(here, '..', '..', 'catalog', 'actions'));
const TARGET = { id: 't_vm', label: 'vm-a', hostname: '10.0.0.5' };

/** 一次"已实际探测"的 check 结果。 */
const probed = (over = {}) => ({
  probed: true,
  count: 12,
  sizeBytes: 400 * 1048576,
  kernelUpgradePending: false,
  rebootRequired: false,
  note: '第一次探测',
  ...over,
});

const makePlan = (checkResult = probed(), extra = {}) => buildPlan({
  action: actions.get('system.update'),
  target: TARGET,
  distro: 'ubuntu',
  idLike: ['debian'],
  checkResult,
  ...extra,
});

test('未实际探测时没有指纹 —— 表示"无法验证"，而不是"一定新鲜"', () => {
  assert.equal(checkFingerprint({ probed: false, note: 'x' }), null);
  assert.equal(checkFingerprint(null), null);
  assert.equal(checkFingerprint(undefined), null);
  // 只有易变字段也不足以形成指纹
  assert.equal(checkFingerprint({ probed: true, note: 'x', probedAt: 'y' }), null);
});

test('指纹对"影响决策的字段"敏感', () => {
  const a = checkFingerprint(probed());
  assert.equal(a, checkFingerprint(probed()), '相同内容应得到相同指纹');
  assert.notEqual(a, checkFingerprint(probed({ count: 3 })), '待更新数量变化必须改变指纹');
  assert.notEqual(a, checkFingerprint(probed({ kernelUpgradePending: true })), '内核升级标志必须改变指纹');
  assert.notEqual(a, checkFingerprint(probed({ blocked: 'root 权限不足' })));
});

test('指纹忽略易变字段（否则每个计划一生成就过期）', () => {
  const a = checkFingerprint(probed({ note: 'A', probedAt: '2026-01-01', durationMs: 1 }));
  const b = checkFingerprint(probed({ note: 'B', probedAt: '2026-09-14', durationMs: 999 }));
  assert.equal(a, b);
});

test('plan 携带指纹与有效期', () => {
  const plan = makePlan();
  assert.match(plan.stateFingerprint, /^[0-9a-f]{64}$/);
  assert.equal(plan.ttlMs, PLAN_TTL_MS);
  assert.equal(Date.parse(plan.expiresAt) - Date.parse(plan.checkedAt), PLAN_TTL_MS);
});

test('新鲜：环境未变、未过期', () => {
  const plan = makePlan();
  const v = checkPlanFreshness(plan, probed(), { now: Date.parse(plan.checkedAt) + 1000 });
  assert.equal(v.ok, true);
  assert.equal(v.reason, null);
  assert.equal(v.fingerprintChanged, false);
});

test('过期：即使环境没变也必须重新计划', () => {
  const plan = makePlan();
  const v = checkPlanFreshness(plan, probed(), { now: Date.parse(plan.expiresAt) + 1 });
  assert.equal(v.ok, false);
  assert.equal(v.expired, true);
  assert.equal(v.fingerprintChanged, false);
  assert.match(v.reason, /计划已过期/);
});

test('环境已变：指纹不同即拒绝（这正是 TOCTOU 的要害）', () => {
  const plan = makePlan(probed({ count: 12 }));
  const v = checkPlanFreshness(plan, probed({ count: 3 }), { now: Date.parse(plan.checkedAt) + 1000 });
  assert.equal(v.ok, false);
  assert.equal(v.fingerprintChanged, true);
  assert.equal(v.canVerify, true);
  assert.match(v.reason, /环境已变化/);
  assert.match(v.reason, /请重新计划/);
});

test('无法验证（重新探测未返回可比状态）也判为不新鲜 —— fail-closed', () => {
  const plan = makePlan();
  const v = checkPlanFreshness(plan, { probed: false, note: '探测失败' }, { now: Date.parse(plan.checkedAt) + 1000 });
  assert.equal(v.ok, false);
  assert.equal(v.canVerify, false);
  assert.match(v.reason, /无法验证/);
});

test('自定义 ttlMs 生效', () => {
  const plan = makePlan(probed(), { ttlMs: 1000 });
  assert.equal(plan.ttlMs, 1000);
  const v = checkPlanFreshness(plan, probed(), { now: Date.parse(plan.checkedAt) + 1500 });
  assert.equal(v.expired, true);
});
