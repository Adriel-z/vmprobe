/**
 * 参数接线机制单测（M1-②）。
 *
 * 要证明的核心命题：**接线情况由 argv 用法决定，不由作者声明决定。**
 * 于是缺陷 F2 的形态（"声明已接线、实际被静默忽略" → 用户以为只装安全更新、实际全量升级）
 * 在结构上不可能发生：没被 argv 引用的参数一定被 fail-closed 拦下。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { loadCatalog } from '../../catalog/src/index.js';
import { buildPlan, resolveCommands } from '../src/plan.js';

const here = dirname(fileURLToPath(import.meta.url));
const { actions } = loadCatalog(join(here, '..', '..', 'catalog', 'actions'));
const TARGET = { id: 't_vm', label: 'vm-a', hostname: '10.0.0.5' };
const QUERY = { probed: true, count: 3, sizeBytes: 1024 };

const plan = (distro, idLike, params) => buildPlan({
  action: actions.get('system.update'), target: TARGET, distro, idLike, params, checkResult: QUERY,
});

test('$param 替换：数组参数展开成多个命令参数', () => {
  const r = resolveCommands(actions.get('system.update'), 'arch', [], { exclude: ['linux', 'nvidia'] });
  const flat = [...r.pre, ...r.cmd].flat();
  assert.ok(flat.includes('--ignore=linux'));
  assert.ok(flat.includes('--ignore=nvidia'));
  assert.deepEqual(r.consumedParams, ['dryRun', 'exclude']);
});

test('$param 替换：标量参数替换成单个参数', () => {
  const action = { apply: { default: { cmd: [['svc', { $param: 'name' }]] } } };
  const r = resolveCommands(action, undefined, [], { name: 'nginx' });
  assert.deepEqual(r.cmd, [['svc', 'nginx']]);
});

test('$when 条件参数：为真才插入，为假什么也不加', () => {
  const action = { apply: { default: { cmd: [['dnf', { $when: 'sec', argv: ['--security'] }, 'upgrade']] } } };
  assert.deepEqual(resolveCommands(action, undefined, [], { sec: true }).cmd, [['dnf', '--security', 'upgrade']]);
  assert.deepEqual(resolveCommands(action, undefined, [], { sec: false }).cmd, [['dnf', 'upgrade']]);
  // 即使为假，参数也算"被引用过"（否则会被误判成未接线）
  assert.ok(resolveCommands(action, undefined, [], { sec: false }).consumedParams.includes('sec'));
});

test('{{name}} 字符串插值', () => {
  const action = { apply: { default: { cmd: [['echo', '--pkg={{p}}']] } } };
  const r = resolveCommands(action, undefined, [], { p: 'vim' });
  assert.deepEqual(r.cmd, [['echo', '--pkg=vim']]);
});

test('dryRun：替换 cmd 并跳过 pre（预演不该顺带刷新仓库元数据）', () => {
  const normal = resolveCommands(actions.get('system.update'), 'ubuntu', ['debian'], {});
  assert.deepEqual(normal.pre, [['apt-get', 'update']]);
  assert.deepEqual(normal.cmd, [['apt-get', '-y', '-o', 'Dpkg::Options::=--force-confold', 'dist-upgrade']]);
  assert.equal(normal.dryRunApplied, false);

  const dry = resolveCommands(actions.get('system.update'), 'ubuntu', ['debian'], { dryRun: true });
  assert.deepEqual(dry.pre, [], 'pre 必须被跳过');
  assert.deepEqual(dry.cmd, [['apt-get', '-s', '-y', 'dist-upgrade']]);
  assert.equal(dry.dryRunApplied, true);
  assert.ok(dry.consumedParams.includes('dryRun'));
});

test('参数支持是**按发行版区分**的：Debian 不支持 securityOnly/exclude', () => {
  // rhel 支持两个
  const rhel = plan('rocky', ['rhel'], { securityOnly: true, exclude: ['kernel'] });
  assert.equal(rhel.blocked, false);
  const flat = rhel.resolvedArgv.flat();
  assert.ok(flat.includes('--security'));
  assert.ok(flat.includes('--exclude=kernel'));

  // Debian 分支里没有引用它们 → fail-closed，而不是假装支持
  const deb = plan('ubuntu', ['debian'], { securityOnly: true });
  assert.equal(deb.blocked, true);
  assert.deepEqual(deb.unwiredParams, ['securityOnly']);
  assert.match(deb.blockedReason, /尚未接线/);
  assert.match(deb.blockedReason, /debian 分支/, '应说清是在哪个分支没接线');
  assert.match(deb.blockedReason, /已接线的参数：dryRun/, '应列出该分支真正接线的参数');
});

test('SUSE / Arch 的接线各不相同（证明不是"一刀切声明"）', () => {
  const suse = plan('opensuse-leap', ['suse'], { securityOnly: true });
  assert.equal(suse.blocked, false);
  assert.ok(suse.resolvedArgv.flat().includes('--category'));

  const arch = plan('arch', [], { securityOnly: true });
  assert.equal(arch.blocked, true, 'arch 没有安全更新开关，应阻断而非假装');

  const archExclude = plan('arch', [], { exclude: ['linux'] });
  assert.equal(archExclude.blocked, false);
  assert.ok(archExclude.resolvedArgv.flat().includes('--ignore=linux'));
});

test('plan 里带上接线情况，便于审计与解释"为什么被拦下"', () => {
  const p = plan('rocky', ['rhel'], { securityOnly: true });
  assert.ok(Array.isArray(p.consumedParams));
  assert.ok(p.consumedParams.includes('securityOnly'));
  assert.ok(p.consumedParams.includes('exclude')); // 被引用即算接线，即使这次没传
  assert.equal(p.dryRunApplied, false);
});

test('默认值参数不触发阻断（显式传默认值等价于没传）', () => {
  const p = plan('arch', [], { securityOnly: false, exclude: [], dryRun: false });
  assert.equal(p.blocked, false);
  assert.deepEqual(p.unwiredParams, []);
});

test('argv 里放结构体（对象/数组）被拒绝，避免把结构塞进命令行', () => {
  const action = { apply: { default: { cmd: [['echo', { $param: 'obj' }]] } } };
  assert.throws(
    () => resolveCommands(action, undefined, [], { obj: { a: 1 } }),
    /不能用作命令行参数/,
  );
});
