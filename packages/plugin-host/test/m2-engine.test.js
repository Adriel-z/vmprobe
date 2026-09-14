/**
 * M2 引擎行为测试：verify 真执行、运行记录落盘、取消贯通、策略透传、日报清理。
 *
 * 用**假传输层**走真实引擎路径 —— 这样每条断言都能精确定位到"引擎到底做了什么"，
 * 而不必依赖 SSH（真实协议那一层由 `tools/checks/ssh-transport.mjs` 覆盖）。
 *
 * 两条本项目的纪律在测试里同样适用：
 *   · 假传输层**只用来制造受控场景**，不假装成功；
 *   · 断言的是"协议/契约"（谁被调用、写了什么、审计里有什么），不是"看着像成功"。
 */

import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { createEngine, RunCancelledError } from '../src/engine.js';
import { startDailyReportScheduler } from '../src/scheduler.js';

function mktmp() {
  return mkdtempSync(join(tmpdir(), 'vmprobe-m2-'));
}

/**
 * 假传输层。
 * @param {object} o
 * @param {object} [o.applyResult] apply 的返回值
 * @param {object} [o.probeState] runProbe 报告的探测状态
 * @param {Error}  [o.applyError] 让 apply 抛错
 * @param {boolean}[o.honorSignal] 是否像真传输层那样尊重 signal（默认 true）
 */
function fakeTransport({ applyResult = { exit: 0, stdout: 'ok', stderr: '', steps: [] }, probeState = { count: 0 }, applyError = null, honorSignal = true, probeError = null } = {}) {
  const calls = { apply: 0, check: 0, runProbe: 0, signals: [] };
  return {
    calls,
    async check() {
      calls.check += 1;
      return { probed: true, count: 7, sizeBytes: 1024, kernelUpgradePending: false, distro: 'debian', idLike: ['debian'] };
    },
    async apply(plan, { signal } = {}) {
      calls.apply += 1;
      calls.signals.push(signal ?? null);
      if (applyError) throw applyError;
      if (honorSignal && signal?.aborted) {
        throw Object.assign(new Error('命令已被取消'), { code: 'aborted' });
      }
      return { ...applyResult, targetId: plan.targetId };
    },
    async runProbe({ probe, expect, signal }) {
      calls.runProbe += 1;
      if (probeError) throw probeError;
      if (signal?.aborted) throw Object.assign(new Error('探测已被取消'), { code: 'aborted' });
      // 真实传输层会自己做判定；这里用同一套语义（避免测试与实现各写一套规则）
      const { probeSatisfies } = await import('../../transport/src/ssh.js');
      return {
        probed: true, probe, expect, state: probeState, attempts: 1, waitedMs: 5,
        satisfied: probeSatisfies(probeState, expect), note: null,
      };
    },
  };
}

async function newEngine(dir, transport, config = {}) {
  const engine = createEngine({ dir, transport, config });
  await engine.addTarget({ id: 't1', label: 'vm-one', hostname: '10.0.0.7', user: 'ops', authRef: 'vault://t1' });
  return engine;
}

/** 造一个已探测过 facts 的目标（让 system.update 能解析出发行版分支）。 */
async function withFacts(engine) {
  // 用**引擎自己的写入器**落盘，而不是手写 JSON —— 手写会与真实的存储格式漂移
  // （第一版就漏了 schema 字段，于是画像读不回来、所有断言都错在"发行版解析不出来"上）
  await engine.persistFacts('t1', {
    schema: 'vmprobe/facts/1',
    os: { id: 'debian', idLike: ['debian'], versionId: '12' },
    pkg: { upgradable: 7 },
  });
  return engine;
}

// ─────────────────────────────────────────────────────────────────────────────

test('① verify 真正执行：探测达到 expect → satisfied=true，并写进返回值与运行记录', async () => {
  const dir = mktmp();
  try {
    const transport = fakeTransport({ probeState: { count: 0, distro: 'debian' } });
    const engine = await withFacts(await newEngine(dir, transport));
    const plan = await engine.planAction({ targetId: 't1', actionId: 'system.update' });
    const res = await engine.applyPlan(plan);

    assert.equal(transport.calls.runProbe, 1, 'apply 之后必须真的跑一次校验探测');
    assert.equal(res.verify.satisfied, true);
    assert.deepEqual(res.verify.expect, { count: 0 });
    assert.ok(res.runId);
    assert.equal(res.run.relPath, `runs/${res.runId}.log`);

    const text = readFileSync(res.run.path, 'utf8');
    assert.match(text, /校验（verify）/);
    assert.match(text, /达到目标态/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('① verify 未达标 → satisfied=false（执行成功 ≠ 达到目标态），且审计如实记录', async () => {
  const dir = mktmp();
  try {
    const transport = fakeTransport({ probeState: { count: 3, distro: 'debian' } });
    const engine = await withFacts(await newEngine(dir, transport));
    const plan = await engine.planAction({ targetId: 't1', actionId: 'system.update' });
    const res = await engine.applyPlan(plan);

    assert.equal(res.verify.satisfied, false);
    assert.equal(res.exit, 0, '命令本身是成功的 —— 校验失败不改变这一点');

    const events = engine.audit.snapshot();
    const runEvent = events.filter((e) => e.event === 'action.run').pop();
    assert.equal(runEvent.verify.satisfied, false);
    assert.equal(runEvent.verify.probe, 'pkg.upgradable');

    // 运行记录里也要能一眼看到"没达标"
    assert.match(readFileSync(res.run.path, 'utf8'), /★ 未达到目标态/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('① verify 探测本身失败 → satisfied=null 且带 error（不得默认成功）', async () => {
  const dir = mktmp();
  try {
    const transport = fakeTransport({ probeError: new Error('SSH 通道已关闭') });
    const engine = await withFacts(await newEngine(dir, transport));
    const plan = await engine.planAction({ targetId: 't1', actionId: 'system.update' });
    const res = await engine.applyPlan(plan);

    assert.equal(res.verify.probed, false);
    assert.equal(res.verify.satisfied, null);
    assert.match(res.verify.error, /SSH 通道已关闭/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('① dryRun 预演不做目标态校验（并说明原因），而不是报一个误导性的"未达标"', async () => {
  const dir = mktmp();
  try {
    const transport = fakeTransport();
    const engine = await withFacts(await newEngine(dir, transport));
    const plan = await engine.planAction({ targetId: 't1', actionId: 'system.update', params: { dryRun: true } });
    assert.equal(plan.dryRunApplied, true);
    const res = await engine.applyPlan(plan);

    assert.equal(transport.calls.runProbe, 0, '预演不该触发目标态探测');
    assert.equal(res.verify.skipped, true);
    assert.match(res.verify.reason, /dryRun/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('② 运行记录落盘 + 审计只留引用：输出不入审计正文，sha256 可核对', async () => {
  const dir = mktmp();
  try {
    const big = 'x'.repeat(5000);
    const transport = fakeTransport({
      applyResult: { exit: 0, stdout: big, stderr: '', steps: [{ argv: ['apt-get', 'update'], exit: 0, stdout: big, stderr: '' }] },
      probeState: { count: 0 },
    });
    const engine = await withFacts(await newEngine(dir, transport));
    const plan = await engine.planAction({ targetId: 't1', actionId: 'system.update' });
    const res = await engine.applyPlan(plan);

    assert.ok(existsSync(res.run.path), '运行记录文件必须存在');
    const runEvent = engine.audit.snapshot().filter((e) => e.event === 'action.run').pop();
    assert.equal(runEvent.runPath, `runs/${res.runId}.log`);
    assert.equal(runEvent.runSha256, res.run.sha256);
    assert.ok(runEvent.runBytes > 5000);

    // ★ 审计正文里不得出现命令输出（否则审计文件会被输出撑爆）
    assert.ok(!JSON.stringify(runEvent).includes(big), '审计事件里不得包含运行输出正文');

    // 封章可核对；改动即检出
    assert.equal(engine.verifyRunSeal({ runId: res.runId, sha256: res.run.sha256 }).ok, true);
    const { writeFileSync } = await import('node:fs');
    writeFileSync(res.run.path, 'tampered', 'utf8');
    assert.equal(engine.verifyRunSeal({ runId: res.runId, sha256: res.run.sha256 }).ok, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('② 执行失败也要落盘：失败更需要事后复盘', async () => {
  const dir = mktmp();
  try {
    const transport = fakeTransport({ applyError: Object.assign(new Error('远端命令失败（exit 1）'), { exit: 1 }) });
    const engine = await withFacts(await newEngine(dir, transport));
    const plan = await engine.planAction({ targetId: 't1', actionId: 'system.update' });

    await assert.rejects(() => engine.applyPlan(plan), /远端命令失败/);

    const files = (await import('node:fs')).readdirSync(join(dir, 'runs'));
    assert.equal(files.length, 1, '失败也必须留下一条运行记录');
    const text = readFileSync(join(dir, 'runs', files[0]), 'utf8');
    assert.match(text, /错误/);
    assert.match(text, /远端命令失败/);

    const failed = engine.audit.snapshot().filter((e) => e.event === 'action.run.failed');
    assert.equal(failed.length, 1);
    assert.ok(failed[0].runPath, '失败记录同样要带引用');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('② controller 侧动作同样落盘（免密事务的输出也要可事后查看）', async () => {
  const dir = mktmp();
  try {
    const transport = fakeTransport({ probeState: { serviceKeyInstalled: true } });
    const engine = createEngine({
      dir, transport,
      controllerHandlers: new Map([['auth.enablePasswordless', async () => ({ ok: true, authRefAfter: { kind: 'key', ref: 'k' } })]]),
    });
    await engine.addTarget({ id: 't1', label: 'vm', hostname: 'h', user: 'u', authRef: 'vault://t1' });
    const plan = await engine.planAction({ targetId: 't1', actionId: 'ssh.passwordless.enable' });
    const res = await engine.applyPlan(plan);

    assert.equal(res.verify.satisfied, true, '免密事务声明的 verify 应真的跑起来');
    const text = readFileSync(res.run.path, 'utf8');
    assert.match(text, /返回值/);
    assert.match(text, /authRefAfter/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('③ 取消贯通：abort 后 apply 抛 RunCancelledError(code=aborted)，且留下运行记录', async () => {
  const dir = mktmp();
  try {
    const controller = new AbortController();
    const transport = fakeTransport();
    transport.apply = async (plan, { signal } = {}) => {
      // 模拟"命令跑到一半被取消"
      controller.abort(new Error('用户中断'));
      const err = Object.assign(new Error('命令已被取消（用户中断）：apt-get dist-upgrade'), { code: 'aborted' });
      if (signal?.aborted) throw err;
      throw err;
    };
    const engine = await withFacts(await newEngine(dir, transport));
    const plan = await engine.planAction({ targetId: 't1', actionId: 'system.update' });

    await assert.rejects(
      () => engine.applyPlan(plan, { signal: controller.signal }),
      (err) => err.code === 'aborted',
    );

    const cancelled = engine.audit.snapshot().filter((e) => e.event === 'action.cancelled');
    assert.equal(cancelled.length, 1, '取消要单独记事件（与失败区分开）');
    const files = (await import('node:fs')).readdirSync(join(dir, 'runs'));
    assert.equal(files.length, 1, '取消也要留下运行记录');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('③ 已经取消的 signal：连执行都不该开始', async () => {
  const dir = mktmp();
  try {
    const transport = fakeTransport();
    const engine = await withFacts(await newEngine(dir, transport));
    const plan = await engine.planAction({ targetId: 't1', actionId: 'system.update' });
    const controller = new AbortController();
    controller.abort();

    await assert.rejects(() => engine.applyPlan(plan, { signal: controller.signal }), RunCancelledError);
    assert.equal(transport.calls.apply, 0, '取消后不得调用 transport.apply');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ─────────────────────────────────────────────────────────────────────────────

test('④ 技术债 #1：autoAllowUpTo 透传到决策层（不再是无效果的配置）', async () => {
  const dir = mktmp();
  try {
    // 默认策略：R1 免弹窗
    const engineDefault = await newEngine(join(dir, 'a'), fakeTransport());
    const p1 = await engineDefault.planAction({ targetId: 't1', actionId: 'system.update' });
    assert.equal(p1.risk, 'R1');
    assert.equal(p1.requiresApproval, false, '默认 autoAllowUpTo=R1 → R1 免弹');

    // 收紧到 R0：R1 动作必须弹窗
    const engineStrict = await newEngine(join(dir, 'b'), fakeTransport(), { autoAllowUpTo: 'R0' });
    const p2 = await engineStrict.planAction({ targetId: 't1', actionId: 'system.update' });
    assert.equal(p2.requiresApproval, true, 'autoAllowUpTo=R0 时 R1 必须弹窗 —— 这个键现在真的生效');

    // 非法值 → 回退默认 + 明确告警
    const engineBad = await newEngine(join(dir, 'c'), fakeTransport(), { autoAllowUpTo: 'R9' });
    assert.equal(engineBad.policy.autoAllowUpTo, 'R1');
    assert.match(engineBad.configWarnings.join(' '), /autoAllowUpTo.*不是合法风险级/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('④ 未知配置键与更宽松的策略都要说出来（不静默生效）', async () => {
  const dir = mktmp();
  try {
    const engine = await newEngine(join(dir, 'x'), fakeTransport(), {
      reportAtUTC: '08:00',      // 拼错（应为 reportAtUtc）
      allowRawShell: true,       // T3 未实现
      autoAllowUpTo: 'R2',       // 比默认宽松
    });
    const joined = engine.configWarnings.join('\n');
    assert.match(joined, /未知配置键 "reportAtUTC"/);
    assert.match(joined, /allowRawShell=true 已被拒绝/);
    assert.match(joined, /比默认（R1）更宽松/);

    // 三重可见性：审计里也查得到
    const events = engine.audit.snapshot();
    assert.ok(events.some((e) => e.event === 'config.warning'));
    const effective = events.find((e) => e.event === 'config.effective');
    assert.equal(effective.autoAllowUpTo, 'R2');
    assert.equal(effective.warningCount, engine.configWarnings.length);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('④ 技术债 #5：pruneReports 接进调度器，且按"每天一次"幂等', async () => {
  const dir = mktmp();
  try {
    const engine = await newEngine(dir, fakeTransport());
    // 造一份很旧的日报（应被清掉）与一份今天的（应留下）
    // 路径必须与 core 的 reportPath 布局一致：<root>/reports/<targetId>/<YYYY>/<day>.json
    const { mkdirSync, writeFileSync } = await import('node:fs');
    const old = join(dir, 'reports', 't1', '2020');
    mkdirSync(old, { recursive: true });
    writeFileSync(join(old, '2020-01-02.json'), JSON.stringify({ schema: 'vmprobe/report/1', day: '2020-01-02' }), 'utf8');

    let prunes = 0;
    const realPrune = engine.pruneReports.bind(engine);
    engine.pruneReports = async (o) => { prunes += 1; return realPrune(o); };

    const scheduler = startDailyReportScheduler({ engine, config: { reportAtUtc: '08:00', reportRetentionDays: 90 } });
    const at = new Date('2026-09-14T08:30:00Z');

    const first = await scheduler.run(at);
    assert.equal(prunes, 1, '到点后应清理一次');
    assert.ok(first.results.some((r) => r.prune), '清理结果要进 run 的结果里（可观测）');
    assert.ok(!existsSync(join(old, '2020-01-02.json')), '过期日报应被清掉');

    await scheduler.run(new Date('2026-09-14T09:30:00Z'));
    assert.equal(prunes, 1, '★ 同一天不得重复清理（幂等键 = UTC 日键）');

    await scheduler.run(new Date('2026-09-15T08:30:00Z'));
    assert.equal(prunes, 2, '换了一天应再清理一次');
    scheduler.stop();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('④ 清理失败不影响报告生成，但要留痕（不能静默膨胀）', async () => {
  const dir = mktmp();
  try {
    const logs = [];
    const ctx = { logger: { warn: (m) => logs.push(m), info: () => {} }, interval: null };
    const engine = await newEngine(dir, fakeTransport());
    engine.pruneReports = async () => { throw new Error('磁盘只读'); };

    const scheduler = startDailyReportScheduler({ engine, ctx, config: { reportAtUtc: '08:00' } });
    const res = await scheduler.run(new Date('2026-09-14T08:30:00Z'));
    assert.equal(res.ran, true, '清理失败不该让整轮失败');
    assert.match(logs.join('\n'), /日报清理失败：磁盘只读/);
    assert.ok(res.results.some((r) => r.prune?.error), '失败要出现在结果里');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('目录加载器拒绝形状不对的 verify（它决定"怎么判定成功"，写错必须拦下）', async () => {
  const { validateAction } = await import('../../catalog/src/index.js');
  const base = {
    id: 'a.b', version: 1, side: 'agent', title: { zh: 'x' }, summary: 's', risk: 'R1',
    apply: { default: { cmd: [['true']] } },
  };
  assert.doesNotThrow(() => validateAction({ ...base, verify: { probe: 'p', expect: { count: 0 }, maxWaitMs: 10 } }, 'x'));
  assert.throws(() => validateAction({ ...base, verify: { probe: '' } }, 'x'), /probe 必须是非空字符串/);
  assert.throws(() => validateAction({ ...base, verify: { probe: 'p', oops: 1 } }, 'x'), /未知字段 oops/);
  assert.throws(() => validateAction({ ...base, verify: { probe: 'p', maxWaitMs: -1 } }, 'x'), /≥0 的整数/);
  assert.throws(() => validateAction({ ...base, verify: { probe: 'p', expect: { a: { deep: 1 } } } }, 'x'), /只能是标量或标量数组/);
  assert.throws(() => validateAction({ ...base, verify: 'nope' }, 'x'), /必须是对象/);
});
