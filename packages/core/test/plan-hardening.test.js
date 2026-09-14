/**
 * plan 阶段加固单测 —— 对应推演发现 F1 / F2 / F5 / F14。
 *
 * 这四条的共同主题：**计划阶段必须"要么说清要做什么，要么明确阻断"**，
 * 不允许出现"看起来计划成功、实际什么也没做或做了别的事"。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { loadCatalog } from '../../catalog/src/index.js';
import { buildPlan, resolveCommands } from '../src/plan.js';

const here = dirname(fileURLToPath(import.meta.url));
const ACTIONS_DIR = join(here, '..', '..', 'catalog', 'actions');
const { actions } = loadCatalog(ACTIONS_DIR);

const TARGET = { id: 't_vm', label: 'vm-a', hostname: '10.0.0.5' };

test('F1: plan 携带 side，controller 侧动作不产生远端 argv', () => {
  const plan = buildPlan({ action: actions.get('ssh.passwordless.enable'), target: TARGET });
  assert.equal(plan.side, 'controller');
  assert.deepEqual(plan.resolvedArgv, [], 'controller 侧动作不应有远端 argv');

  const agentPlan = buildPlan({
    action: actions.get('system.update'), target: TARGET, distro: 'ubuntu', idLike: ['debian'],
  });
  assert.equal(agentPlan.side, 'agent');
  assert.deepEqual(agentPlan.resolvedArgv[0], ['apt-get', 'update']);
});

test('F14: 无匹配发行版分支 → 阻断（而不是空 argv 假装成功）', () => {
  const noFacts = buildPlan({ action: actions.get('system.update'), target: TARGET });
  assert.equal(noFacts.blocked, true);
  assert.match(noFacts.blockedReason, /无法为发行版/);
  assert.deepEqual(noFacts.resolvedArgv, [], '虽然是空数组，但状态是 blocked，不会被误当成可执行计划');

  // controller 侧动作（probe.facts）**天然没有远端 argv**，不应因此被判 unresolved
  const controllerSide = buildPlan({ action: actions.get('probe.facts'), target: TARGET });
  assert.equal(controllerSide.blocked, false, 'controller 侧动作不该被 unresolved 误伤');
  assert.equal(controllerSide.side, 'controller');
  assert.deepEqual(controllerSide.resolvedArgv, []);
});

test('F14: 不支持的发行版 → 阻断，且原因里带上 ID_LIKE 便于排查', () => {
  const plan = buildPlan({
    action: actions.get('system.update'), target: TARGET, distro: 'gentoo', idLike: ['someother'],
  });
  assert.equal(plan.blocked, true);
  assert.match(plan.blockedReason, /gentoo/);
  assert.match(plan.blockedReason, /ID_LIKE=someother/);
});

test('F2: 未接线的参数 → fail-closed 阻断，且点名是哪些参数', () => {
  const plan = buildPlan({
    action: actions.get('system.update'), target: TARGET, distro: 'arch',
    params: { securityOnly: true },
  });
  assert.equal(plan.blocked, true);
  assert.deepEqual(plan.unwiredParams, ['securityOnly']);
  assert.match(plan.blockedReason, /尚未接线/);

  // 与默认值相同的显式传参不算"未接线"，不应阻断
  const equivalent = buildPlan({
    action: actions.get('system.update'), target: TARGET, distro: 'arch',
    params: { securityOnly: false, exclude: [], dryRun: false },
  });
  assert.equal(equivalent.blocked, false, '等于默认值的传参不该阻断');
  assert.deepEqual(equivalent.unwiredParams, []);
});

test('F5: 参数类型错误 / 未知参数 → 阻断并给出具体原因', () => {
  const plan = buildPlan({
    action: actions.get('system.update'), target: TARGET, distro: 'arch',
    params: { securityOnly: 'yes', 注入键: 1 },
  });
  assert.equal(plan.blocked, true);
  assert.ok(plan.paramErrors.some((e) => /应为布尔值/.test(e)));
  assert.ok(plan.paramErrors.some((e) => /未知参数 "注入键"/.test(e)));
  assert.match(plan.blockedReason, /参数不合法/);
});

test('正常路径不受加固影响：R0 动作免审批且不产生审批文案', () => {
  const plan = buildPlan({ action: actions.get('probe.facts'), target: TARGET });
  assert.equal(plan.risk, 'R0');
  assert.equal(plan.requiresApproval, false);
  assert.equal(plan.approvalReason, '');
  assert.equal(plan.blocked, false);
  assert.deepEqual(plan.paramErrors, []);
});

test('resolveCommands 的 unresolved 标记只会出现在"真没分支"时', () => {
  const onlyDistros = { apply: { debian: { cmd: [['true']] } } };
  assert.equal(resolveCommands(onlyDistros, undefined, []).unresolved, true);
  assert.equal(resolveCommands(onlyDistros, 'debian', []).unresolved, false);
  assert.equal(resolveCommands({ apply: { default: { cmd: [['true']] } } }, 'anything', []).unresolved, false);
});
