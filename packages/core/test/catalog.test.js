/**
 * 动作目录 + plan 联动单测。
 * 重点：跨发行版分流是否真的按 facts 走，以及「未知字段必须报错」这条安全属性。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { loadCatalog, listCatalog, validateAction } from '../../catalog/src/index.js';
import { buildPlan, resolveCommands, summarizePlan } from '../src/plan.js';

const here = dirname(fileURLToPath(import.meta.url));
const ACTIONS_DIR = join(here, '..', '..', 'catalog', 'actions');

const minimal = () => ({
  id: 'demo.action',
  version: 1,
  side: 'agent',
  title: { zh: '演示' },
  summary: '演示用',
  risk: 'R1',
  apply: { default: { cmd: [['true']] } },
});

test('内置目录可加载，且包含设计中的三个动作', async () => {
  const { actions } = await loadCatalog(ACTIONS_DIR);
  assert.ok(actions.has('system.update'));
  assert.ok(actions.has('probe.facts'));
  assert.ok(actions.has('ssh.passwordless.enable'));
  assert.equal(actions.get('ssh.passwordless.enable').side, 'controller');
  assert.equal(actions.get('probe.facts').risk, 'R0');
});

test('未知字段被拒绝（防止 risk 拼错导致静默降级）', () => {
  const bad = { ...minimal(), Risk: 'R3' }; // 大小写拼错
  assert.throws(() => validateAction(bad), /未知字段 "Risk"/);
});

test('risk 非法值被拒绝', () => {
  assert.throws(() => validateAction({ ...minimal(), risk: 'r1' }), /risk 必须是/);
});

test('risk=dynamic 但没有 check → 拒绝（运行时无从判定）', () => {
  assert.throws(() => validateAction({ ...minimal(), risk: 'dynamic' }), /必须声明 check/);
});

test('apply 空分支 / argv 非数组 → 拒绝', () => {
  assert.throws(() => validateAction({ ...minimal(), apply: {} }), /至少有一个发行版分支/);
  assert.throws(
    () => validateAction({ ...minimal(), apply: { default: { cmd: ['apt-get update'] } } }),
    /必须是非空 argv 数组/,
  );
});

test('argv 元素形状受校验：未知字段 / 缺键 / 引用未声明参数都拒载', () => {
  const withCmd = (cmd) => ({ ...minimal(), apply: { default: { cmd: [cmd] } } });

  // $param 未知字段
  assert.throws(
    () => validateAction(withCmd(['x', { $param: 'p', bogus: 1 }])),
    /含未知字段 bogus/,
  );
  // 元素对象既不是 $param 也不是 $when
  assert.throws(() => validateAction(withCmd(['x', { foo: 1 }])), /必须含 \$param 或 \$when/);
  // $when 空 argv（没内容就不该写 $when —— 那会谎报"已接线"）
  assert.throws(() => validateAction(withCmd(['x', { $when: 'f', argv: [] }])), /\$when\.argv 必须是非空数组/);
  // 引用未声明的参数：拼错名字会静默变成"未接线"，所以这里必须拦住
  assert.throws(
    () => validateAction(withCmd(['x', { $param: 'nope' }])),
    /引用了未声明的参数 \$nope/,
  );
  assert.throws(
    () => validateAction({ ...minimal(), params: { type: 'object', properties: {}, additionalProperties: false },
      apply: { default: { cmd: [['echo', '{{nope}}']] } } }),
    /引用了未声明的参数/,
  );
  // 合法形态能通过
  assert.doesNotThrow(() => validateAction({
    ...minimal(),
    params: { type: 'object', properties: { f: { type: 'boolean' }, pkgs: { type: 'array' } }, additionalProperties: false },
    apply: { default: { cmd: [['x', { $when: 'f', argv: ['--yes'] }, { $param: 'pkgs', prefix: '--pkg=' }]] } },
  }));
});

test('弃用的 wiredParams：若声明了却没被 argv 引用 → 直接报错，避免"以为还在起作用"', () => {
  const withCmd = (extra) => ({
    ...minimal(),
    params: { type: 'object', properties: { f: { type: 'boolean' } }, additionalProperties: false },
    ...extra,
  });
  assert.throws(
    () => validateAction({ ...withCmd({ wiredParams: ['f'] }), apply: { default: { cmd: [['x']] } } }),
    /wiredParams 里的 f 并未被任何 argv 引用/,
  );
  assert.doesNotThrow(() => validateAction({
    ...withCmd({ wiredParams: ['f'] }),
    apply: { default: { cmd: [['x', { $when: 'f', argv: ['--yes'] }]] } },
  }));
});

test('跨发行版分流：ubuntu 经 ID_LIKE 落到 debian 分支', () => {
  const action = {
    apply: {
      debian: { cmd: [['apt-get', 'dist-upgrade']] },
      rhel: { cmd: [['dnf', 'upgrade']] },
      arch: { cmd: [['pacman', '-Syu']] },
      default: { cmd: [['true']] },
    },
  };
  assert.equal(resolveCommands(action, 'debian').distroKey, 'debian');
  assert.equal(resolveCommands(action, 'ubuntu', ['debian']).distroKey, 'debian');
  assert.equal(resolveCommands(action, 'fedora', ['rhel']).distroKey, 'rhel');
  assert.equal(resolveCommands(action, 'arch').distroKey, 'arch');
  assert.equal(resolveCommands(action, 'gentoo').distroKey, 'default');
});

test('真实动作 system.update 在五个发行版系上都能解析出 argv', async () => {
  const { actions } = await loadCatalog(ACTIONS_DIR);
  const action = actions.get('system.update');
  const cases = [
    ['ubuntu', ['debian'], 'apt-get'],
    ['debian', [], 'apt-get'],
    ['rocky', ['rhel'], 'dnf'],
    ['opensuse-leap', ['suse'], 'zypper'],
    ['arch', [], 'pacman'],
    ['alpine', [], 'apk'],
  ];
  for (const [distro, idLike, expectBin] of cases) {
    const r = resolveCommands(action, distro, idLike);
    assert.ok(r.cmd.length > 0, `${distro} 应解析出命令`);
    const all = [...r.pre, ...r.cmd].flat();
    assert.ok(all.includes(expectBin), `${distro} 应使用 ${expectBin}，实际 ${all.join(' ')}`);
  }
});

test('plan：只读动作 R0 免审批，且不产生审批文案', async () => {
  const { actions } = await loadCatalog(ACTIONS_DIR);
  const plan = buildPlan({
    action: actions.get('probe.facts'),
    target: { id: 't_1', label: 'vm-a' },
    distro: 'ubuntu',
    idLike: ['debian'],
    checkResult: {},
  });
  assert.equal(plan.risk, 'R0');
  assert.equal(plan.requiresApproval, false);
  assert.equal(plan.approvalReason, '');
  assert.equal(plan.blocked, false);
});

test('plan：含内核升级时 system.update 从 R1 提权到 R2 并给出影响面', async () => {
  const { actions } = await loadCatalog(ACTIONS_DIR);
  const plan = buildPlan({
    action: actions.get('system.update'),
    target: { id: 't_1', label: 'vm-a', hostname: '10.0.0.5' },
    distro: 'ubuntu',
    idLike: ['debian'],
    checkResult: { count: 12, sizeBytes: 432 * 1048576, kernelUpgradePending: true },
  });
  assert.equal(plan.risk, 'R2');
  assert.equal(plan.requiresApproval, true);
  assert.match(plan.impact.summary, /12 项待处理/);
  assert.match(plan.impact.summary, /含内核升级/);
  assert.match(plan.approvalReason, /vm-a/);
  assert.deepEqual(plan.resolvedArgv[0], ['apt-get', 'update']);
  assert.equal(plan.env.DEBIAN_FRONTEND, 'noninteractive');
  assert.equal(plan.noop, false);
});

test('plan：check 报「已是目标态」→ no-op，不必打扰用户', async () => {
  const { actions } = await loadCatalog(ACTIONS_DIR);
  const plan = buildPlan({
    action: actions.get('system.update'),
    target: { label: 'vm-a' },
    distro: 'arch',
    checkResult: { alreadySatisfied: true, count: 0 },
  });
  assert.equal(plan.noop, true);
  assert.match(summarizePlan(plan), /已是目标态/);
});

test('plan：审批策略 never 时 R3 动作被阻断（controller 侧动作）', async () => {
  const { actions } = await loadCatalog(ACTIONS_DIR);
  const plan = buildPlan({
    action: actions.get('ssh.passwordless.enable'),
    target: { label: 'vm-a' },
    approvalPolicy: 'never',
  });
  assert.equal(plan.blocked, true);
  assert.match(plan.blockedReason, /fail-closed/);
});

test('listCatalog 产出稳定排序的摘要', async () => {
  const { actions } = await loadCatalog(ACTIONS_DIR);
  const list = listCatalog(actions);
  assert.deepEqual(
    list.map((a) => a.id),
    ['probe.facts', 'ssh.passwordless.disable', 'ssh.passwordless.enable', 'system.update'],
  );
});
