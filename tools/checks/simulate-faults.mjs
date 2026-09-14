/**
 * 故障推演 / 回归验证 —— 用可执行的模拟逐条"验伤"，而不是靠嘴上推理。
 *
 * 本脚本**不启动 DSH**，全部在进程内进行：真实引擎 + 假传输层 + 真实文件系统。
 * 每条探测点的判据是「**修复后应有的正确行为**」，因此它同时充当回归测试：
 *   · 首轮运行（修复前）：13 条全部报「缺陷已复现」
 *   · 修复后运行：应全部报「未复现」（= 已修复）
 *
 *   node tools/checks/simulate-faults.mjs
 */

import { mkdtemp, rm, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';

import { createEngine } from '../../packages/plugin-host/src/engine.js';
import { createTools } from '../../packages/plugin-host/src/tools.js';
import { startDailyReportScheduler } from '../../packages/plugin-host/src/scheduler.js';
import { loadCatalog } from '../../packages/catalog/src/index.js';
import {
  makeTarget, assertSecretFree, GENESIS, resolveCommands,
  writeReport, readDay, listDays, findGaps, pruneReports, dayKey, reportPath,
} from '../../packages/core/src/index.js';

const results = [];

function record(id, severity, title, isDefect, evidence) {
  results.push({ id, severity, title, isDefect, evidence });
  console.log(`\n[${id}] ${isDefect ? '✖ 缺陷已复现' : '✔ 已修复/未复现'} (${severity})  ${title}`);
  for (const line of evidence) console.log(`      ${line}`);
}

/** 假传输层：记录"到底把什么下发给了远端"。 */
function makeFakeTransport() {
  const sent = [];
  return {
    sent,
    async check() {
      return { probed: true, count: 3, sizeBytes: 1024, kernelUpgradePending: false };
    },
    async apply(plan) {
      sent.push({ actionId: plan.actionId, argv: plan.resolvedArgv, risk: plan.risk, side: plan.side ?? null });
      return { exit: 0, stdout: 'ok' };
    },
  };
}

/** 注册一个 controller 侧处理器，使 canApply 通过 —— 用于单独检验后续护栏。 */
const CONTROLLER_HANDLERS = new Map([
  ['auth.enablePasswordless', async () => ({ exit: 0, note: 'simulated controller handler' })],
]);

const root = await mkdtemp(join(tmpdir(), 'vmprobe-fault-'));
try {
  // =========================================================================
  console.log('\n══════ 第一组：执行路径的正确性 ══════');

  // ---- F1: controller 侧动作不得进传输层 ----
  {
    const transport = makeFakeTransport();
    const engine = createEngine({ dir: join(root, 'f1'), transport });
    await engine.addTarget({ id: 't_sim', label: 'vm-sim', hostname: '10.0.0.9', user: 'ops', authRef: 'vault://sim' });
    const plan = await engine.planAction({ targetId: 't_sim', actionId: 'ssh.passwordless.enable' });
    let err = null;
    try { await engine.applyPlan(plan); } catch (e) { err = e; }

    const bad = transport.sent.length !== 0 || plan.side !== 'controller';
    record('F1', '严重', 'controller 侧动作被送进传输层（plan 未携带 side）', bad, [
      `plan.side = ${plan.side}`,
      `plan.resolvedArgv = ${JSON.stringify(plan.resolvedArgv)}（controller 动作不应有远端 argv）`,
      `传输层收到的下发次数 = ${transport.sent.length}（应为 0）`,
      `applyPlan 的报错 = ${err ? err.message : '（无）'}`,
    ]);
  }

  // ---- F2: 未接线的参数必须 fail-closed，而不是静默忽略 ----
  {
    const engine = createEngine({ dir: join(root, 'f2'), transport: makeFakeTransport() });
    await engine.addTarget({ id: 't_sim', label: 'vm-sim', hostname: '10.0.0.9', user: 'ops', authRef: 'vault://sim' });
    const plan = await engine.planAction({
      targetId: 't_sim', actionId: 'system.update',
      params: { securityOnly: true, exclude: ['linux-*'] },
    });
    const bad = !plan.blocked || !/尚未接线/.test(plan.blockedReason ?? '');
    record('F2', '严重', '未接线的动作参数被静默忽略（"以为只装安全更新、实际全量升级"）', bad, [
      `plan.blocked = ${plan.blocked}`,
      `plan.unwiredParams = ${JSON.stringify(plan.unwiredParams)}`,
      `阻断原因 = ${plan.blockedReason}`,
    ]);
  }

  // ---- F3: R3 的"复述主机名"未实现时必须阻断 ----
  {
    const engine = createEngine({
      dir: join(root, 'f3'),
      transport: makeFakeTransport(),
      controllerHandlers: CONTROLLER_HANDLERS,
    });
    await engine.addTarget({ id: 't_sim', label: 'vm-sim', hostname: '10.0.0.9', user: 'ops', authRef: 'vault://sim' });
    const tools = createTools(engine, { approval: { async request() { return 'allowed-once'; } } });
    const actionTool = tools.find((t) => t.name === 'vmprobe_action');
    const res = await actionTool.execute(
      { target: 'vm-sim', action: 'ssh.passwordless.enable' },
      { callId: 'c3', agent: { id: 'a' }, signal: new AbortController().signal },
    );
    const bad = res.status !== 'blocked' || !/复述目标主机名/.test(res.error ?? '');
    record('F3', '严重', 'R3 要求复述主机名，机制未实现却继续执行（安全护栏静默失效）', bad, [
      `canApply（已注册 controller 处理器）= ${engine.canApply(res.plan)}`,
      `执行结果 status = ${res.status}`,
      `error = ${res.error}`,
    ]);
  }

  // ---- F4: 不应声明 timeoutMs（未观察 exec.signal 时） ----
  {
    const engine = createEngine({ dir: join(root, 'f4'), transport: makeFakeTransport() });
    await engine.addTarget({ id: 't_sim', label: 'vm-sim', hostname: '10.0.0.9', user: 'ops', authRef: 'vault://sim' });
    const tools = createTools(engine, { approval: { async request() { return 'allowed-once'; } } });
    const actionTool = tools.find((t) => t.name === 'vmprobe_action');

    let signalReads = 0;
    const exec = {
      callId: 'c4', agent: { id: 'a' }, arguments: {},
      get signal() { signalReads++; return new AbortController().signal; },
    };
    await actionTool.execute({ target: 'vm-sim', action: 'probe.facts' }, exec);

    // 缺陷特征 = "声明了超时，却不读取消信号"
    const bad = actionTool.timeoutMs !== undefined && signalReads === 0;
    record('F4', '高', '声明 timeoutMs 却不观察 exec.signal（违反 DSH 协作式取消契约）', bad, [
      `工具声明的 timeoutMs = ${actionTool.timeoutMs === undefined ? 'undefined（已移除声明）' : actionTool.timeoutMs}`,
      `exec.signal 被读取次数 = ${signalReads}`,
      '结论：未接真实取消前不声明超时，是诚实的做法；M1 接取消后可恢复声明。',
    ]);
  }

  // ---- F5: 参数必须按动作的 params schema 校验 ----
  {
    const engine = createEngine({ dir: join(root, 'f5'), transport: makeFakeTransport() });
    await engine.addTarget({ id: 't_sim', label: 'vm-sim', hostname: '10.0.0.9', user: 'ops', authRef: 'vault://sim' });
    const plan = await engine.planAction({
      targetId: 't_sim', actionId: 'system.update',
      params: { securityOnly: 'yes', 不存在的参数: 1 },
    });
    const bad = !plan.blocked || plan.paramErrors.length === 0;
    record('F5', '高', '动作参数未按目录里的 params schema 校验，任意键值都被接受', bad, [
      `传入 { securityOnly: "yes", 不存在的参数: 1 }`,
      `plan.blocked = ${plan.blocked}`,
      `plan.paramErrors = ${JSON.stringify(plan.paramErrors)}`,
    ]);
  }

  // ---- F14: 无法解析命令时必须阻断，而不是空 argv 空转 ----
  {
    const engine = createEngine({ dir: join(root, 'f14'), transport: makeFakeTransport() });
    await engine.addTarget({ id: 't_sim', label: 'vm-sim', hostname: '10.0.0.9', user: 'ops', authRef: 'vault://sim' });
    // 没有 facts → 没有 distro → system.update 匹配不到任何分支
    const noFacts = await engine.planAction({ targetId: 't_sim', actionId: 'system.update' });
    // 而 probe.facts 有 default 分支，应当正常成计划
    const withDefault = await engine.planAction({ targetId: 't_sim', actionId: 'probe.facts' });
    const bad = !noFacts.blocked || withDefault.blocked;
    record('F14', '高', '无匹配发行版分支时静默返回空 argv（"计划成功、实执空转"）', bad, [
      `system.update（无 facts）→ blocked=${noFacts.blocked}，argv=${JSON.stringify(noFacts.resolvedArgv)}`,
      `  阻断原因 = ${noFacts.blockedReason}`,
      `probe.facts（有 default 分支）→ blocked=${withDefault.blocked}，argv=${JSON.stringify(withDefault.resolvedArgv)}`,
      '注意后者必须**不被**误伤：unresolved 判定是基于分支匹配的，不是一刀切。',
    ]);
  }

  // =========================================================================
  console.log('\n══════ 第二组：安全与信任边界 ══════');

  // ---- F6: targetId 路径穿越 ----
  {
    let created = null, threw = null;
    try {
      created = makeTarget({ id: '../../../evil', label: 'bad', hostname: 'h', user: 'u', authRef: 'vault://x' });
    } catch (err) { threw = err; }
    const reportsRoot = join(root, 'reports');
    let resolvedPath = null, escapes = false;
    if (created) {
      resolvedPath = resolve(reportsRoot, created.id, '2026-09-14.json');
      escapes = !resolvedPath.startsWith(resolve(reportsRoot));
    }
    const bad = created !== null;
    record('F6', '高', 'targetId 无格式校验 → 报告/运行记录落盘路径穿越', bad, [
      `makeTarget({ id: "../../../evil" }) → ${created ? '被接受（危险）' : '已拒绝'}`,
      `拒绝原因 = ${threw?.message}`,
      `（若被接受）拼出的路径会逃出 reports 根 = ${escapes}`,
    ]);
  }

  // ---- F7: 拒密规则漏检 + 不误伤元数据 ----
  {
    const misses = [];
    for (const key of ['secretKey', 'secret_key', 'accessKey', 'access_key', 'bearer', 'sessionToken', 'pin', 'password', 'passphrase', 'privateKey', 'apiKey', 'token']) {
      let blocked = false;
      try { assertSecretFree({ [key]: 'x' }); } catch { blocked = true; }
      if (!blocked) misses.push(key);
    }
    const falsePositives = [];
    for (const key of ['passwordAuth', 'pubkeyAuth', 'authKind', 'privateKeyPath', 'hostKey', 'keyAlgo', 'authRef', 'fingerprint']) {
      try { assertSecretFree({ [key]: true }); } catch { falsePositives.push(key); }
    }
    const bad = misses.length > 0 || falsePositives.length > 0;
    record('F7', '中', '拒密黑名单漏检（secretKey/accessKey/bearer…），且不能误伤合法元数据', bad, [
      `仍漏检的键名 = ${misses.join(', ') || '（无）'}`,
      `被误伤的合法元数据键 = ${falsePositives.join(', ') || '（无）'}`,
      '规则已改为「元数据键白名单优先 → 再按后缀拒绝」，因此 passwordAuth 这类字段不受影响。',
    ]);
  }

  // ---- F15: 报告文件命名与路径安全（新需求） ----
  {
    const rroot = join(root, 'f15');
    const day = '2026-09-14';
    const p = reportPath(rroot, 't_sim', day);
    // 只检查**文件名**部分：绝对路径里的盘符冒号（C:\）是合法的，不能误判
    const fileName = basename(p);
    const hasIllegalChar = /[:*?"<>|]/.test(fileName);
    const endsWithDay = p.endsWith(join('t_sim', '2026', `${day}.json`));
    let traversalBlocked = false;
    try { reportPath(rroot, '../../evil', day); } catch { traversalBlocked = true; }
    const bad = hasIllegalChar || !endsWithDay || !traversalBlocked;
    record('F15', '中', '报告"以时间命名"必须跨平台合法且不可穿越目录', bad, [
      `生成路径 = ${p.replace(rroot, '<root>')}`,
      `文件名 = "${fileName}"，含 Windows 非法字符 = ${hasIllegalChar}（必须为 false）`,
      `形如 reports/<id>/<年>/<日>.json = ${endsWithDay}`,
      `targetId="../../evil" 被拒绝 = ${traversalBlocked}`,
    ]);
  }

  // =========================================================================
  console.log('\n══════ 第三组：持久化与并发 ══════');

  // ---- F8: 审计必须落盘并可重放 ----
  {
    const dir = join(root, 'f8');
    const e1 = createEngine({ dir });
    await e1.addTarget({ id: 't_a', hostname: 'h', user: 'u', authRef: 'vault://a' });
    const e2 = createEngine({ dir });
    const v = e2.verifyAudit();
    const bad = e2.audit.length === 0 || !v.ok;
    record('F8', '高', '审计哈希链只在内存：重启后归零、历史与链证据丢失', bad, [
      `实例 1 追加后条数 = ${e1.audit.total}`,
      `实例 2（同目录）重放后条数 = ${e2.audit.length}`,
      `实例 2 的链校验 = ok:${v.ok}（历史校验 ok:${v.historyOk}）`,
      `首个 prev 是否仍是 GENESIS = ${e2.audit.snapshot()[0]?.prev === GENESIS}（应为 false，说明接上了历史）`,
    ]);
  }

  // ---- F9: 并发写目标不丢 ----
  {
    const engine = createEngine({ dir: join(root, 'f9') });
    await Promise.all([
      engine.addTarget({ id: 't_x', hostname: 'h1', user: 'u', authRef: 'vault://x' }),
      engine.addTarget({ id: 't_y', hostname: 'h2', user: 'u', authRef: 'vault://y' }),
    ]);
    const stored = await engine.listTargets();
    record('F9', '中', 'addTarget 读-改-写无互斥 → 并发丢写', stored.length < 2, [
      `并发添加 2 个目标，实际落盘 = ${stored.length} 个（${stored.map((t) => t.id).join(', ') || '空'}）`,
    ]);
  }

  // ---- F12: 审计内存必须有上限 ----
  {
    const engine = createEngine({ dir: join(root, 'f12'), maxAuditRecords: 1000 });
    const t0 = process.hrtime.bigint();
    for (let i = 0; i < 6000; i++) engine.record('probe.ping', { i });
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    const v = engine.verifyAudit();
    const bad = engine.audit.length !== 1000 || !v.ok;
    record('F12', '中', '审计数组无上限 → 心跳类记录线性堆积成内存泄漏', bad, [
      `追加 6000 条后：内存窗口 = ${engine.audit.length}（上限 1000），累计 = ${engine.audit.total}，耗时 = ${ms.toFixed(0)}ms`,
      `裁剪后链仍可校验 = ${v.ok}（裁剪条数 ${v.truncated}）`,
      `落盘文件存在 = ${(await stat(engine.auditFile)).size > 0}`,
      '关键点：裁剪窗口后首条 prev 不再是 GENESIS，所以 verifyChain 需要显式锚点，否则会把"裁剪"误报成"篡改"。',
    ]);
  }

  // =========================================================================
  console.log('\n══════ 第四组：契约一致性与跨平台 ══════');

  // ---- F10: 目录声明的命令必须与协从端实际能力一致 ----
  //
  // 原缺陷：目录里写着 `vmprobe probe facts --json`，而协从端脚本里根本没有这个子命令
  // （接上传输层后会直接 command not found）。
  // 现在**从结构上消除了**：facts 采集改成 controller 侧动作（handler + 经 stdin 投递脚本），
  // 目录里不再声明任何"其实不存在"的 CLI。所以这条探针改为守住新不变式：
  //   ① controller 侧动作**不得**带远端 argv（否则又会出现"假命令"）；
  //   ② 若某个 agent 侧动作确实调用了 `vmprobe` 这个二进制，其子命令必须在脚本里真实存在。
  {
    const { actions } = await loadCatalog(new URL('../../packages/catalog/actions', import.meta.url).pathname);
    const boot = await readFile(new URL('../../agent/bootstrap.sh', import.meta.url), 'utf8');
    const bootSubs = [...boot.matchAll(/^\s*(--[a-z]+)\)/gm)].map((m) => m[1]);

    const controllerWithCmd = [];
    const staleCli = [];
    for (const [id, a] of actions) {
      for (const [branch, spec] of Object.entries(a.apply)) {
        if (a.side === 'controller' && spec.cmd !== undefined) controllerWithCmd.push(`${id}.${branch}`);
        if (a.side === 'agent' && spec.cmd) {
          for (const argv of [...(spec.pre ?? []), ...spec.cmd]) {
            if (argv[0] === 'vmprobe') {
              const sub = argv.find((x) => typeof x === 'string' && x.startsWith('--'));
              if (!sub || !bootSubs.includes(sub)) staleCli.push(`${id}: ${argv.join(' ')}`);
            }
          }
        }
      }
    }
    const bad = controllerWithCmd.length > 0 || staleCli.length > 0;
    record('F10', '中', '动作目录声明了协从端不存在的 CLI / controller 动作带着假的远端 argv', bad, [
      `controller 侧动作带 cmd 的条目 = ${controllerWithCmd.join('、') || '（无）'}`,
      `引用了 vmprobe 但子命令不存在的 = ${staleCli.join('、') || '（无）'}`,
      `bootstrap.sh 实际支持的子命令 = ${bootSubs.join(', ')}`,
      `controller 侧动作（应只用 handler）= ${[...actions.values()].filter((a) => a.side === 'controller').map((a) => a.id).join('、')}`,
      'facts 采集现在经 SSH stdin 投递脚本执行（sh -s -- --check），不再承诺任何远端 CLI',
    ]);
  }

  // ---- F11: storageDir 尊重 DSH_HOME ----
  {
    const src = await readFile(new URL('../../packages/plugin-host/src/index.js', import.meta.url), 'utf8');
    const usesHomedir = /homedir\(\)/.test(src);
    const usesDshHome = /process\.env\.DSH_HOME/.test(src);
    record('F11', '低', 'storageDir 默认值硬编码 ~/.dsh，未尊重 DSH_HOME', !usesDshHome, [
      `源码使用 os.homedir() 作为回退 = ${usesHomedir}`,
      `源码引用 process.env.DSH_HOME = ${usesDshHome}`,
    ]);
  }

  // =========================================================================
  console.log('\n══════ 第五组：每日报告文件子系统（新需求的行为验证） ══════');

  {
    const rroot = join(root, 'reports-behavior');
    const targetId = 't_vm';

    // 同一天两次运行 → 同一个文件、runs 追加
    const r1 = await writeReport({ root: rroot, targetId, report: { status: 'ok', metrics: { diskUsedPct: 43, upgradable: 12 } }, at: '2026-09-14T08:00:00Z' });
    const r2 = await writeReport({ root: rroot, targetId, report: { status: 'ok', metrics: { diskUsedPct: 49, upgradable: 19 } }, at: '2026-09-14T20:00:00Z' });
    // 另一天 → 另一个文件
    await writeReport({ root: rroot, targetId, report: { status: 'unreachable', error: 'connect timeout' }, at: '2026-09-15T08:00:00Z' });
    // 缺 2026-09-16
    const days = await listDays({ root: rroot, targetId });
    const gaps = await findGaps({ root: rroot, targetId, from: '2026-09-14', to: '2026-09-17' });
    const day1 = await readDay({ root: rroot, targetId, day: '2026-09-14' });

    const singleFileSameDay = r1.path === r2.path && day1.runs.length === 2;
    const separateDays = days.length === 2 && days[0] === '2026-09-14' && days[1] === '2026-09-15';
    const gapHonest = gaps.includes('2026-09-16') && gaps.includes('2026-09-17');

    // 不可达也要落文件
    const unreachableDay = await readDay({ root: rroot, targetId, day: '2026-09-15' });
    const unreachableRecorded = unreachableDay?.runs[0]?.status === 'unreachable';

    // 目录里没有临时文件残留
    const files = await readdir(join(rroot, 'reports', targetId, '2026'));
    const noTmp = !files.some((f) => f.includes('.tmp-'));

    const bad = !(singleFileSameDay && separateDays && gapHonest && unreachableRecorded && noTmp);
    record('R1', '中', '每日报告：一天一文件、同日追加、跨日独立、缺天如实报、不可达也落盘、无临时残留', bad, [
      `同一天两次 → 同一文件且 runs=${day1?.runs.length} = ${singleFileSameDay}`,
      `跨日独立成文件 = ${separateDays}（${days.join(', ')}）`,
      `缺天如实报出 = ${gapHonest}（缺 ${gaps.join(', ')}）`,
      `不可达仍落盘并标记 = ${unreachableRecorded}`,
      `2026 目录内容 = ${files.join(', ')}（无 .tmp- 残留 = ${noTmp}）`,
    ]);
  }

  {
    // 保留策略：近 N 天全留，更早的每月留 1 号。
    // 日期刻意选在窗口边界两侧足够远的位置，避免边界天数造成歧义
    // （首轮探针就是因为把 86 天前的日期当成了"超窗口"而误报）。
    const rroot = join(root, 'reports-prune');
    const targetId = 't_vm';
    const days = ['2026-06-01', '2026-06-15', '2026-06-20', '2026-08-20', '2026-09-13'];
    for (const d of days) {
      await writeReport({ root: rroot, targetId, report: { status: 'ok' }, at: `${d}T08:00:00Z` });
    }
    const now = new Date('2026-09-14T00:00:00Z');
    const keepDays = 30; // cutoff = 2026-08-15
    const before = await listDays({ root: rroot, targetId });
    const res = await pruneReports({ root: rroot, targetId, keepDays, now });
    const after = await listDays({ root: rroot, targetId });
    const expectKept = ['2026-06-01', '2026-08-20', '2026-09-13'];
    const bad = JSON.stringify(after) !== JSON.stringify(expectKept);
    record('R2', '中', '报告保留策略：近期全留 + 更早的每月留 1 号（否则一天一文件会无限膨胀）', bad, [
      `now=${dayKey(now)}，keepDays=${keepDays} → 窗口起点 ${dayKey(new Date(now.getTime() - keepDays * 86400000))}`,
      `清理前 = ${before.join(', ')}`,
      `删除 = ${res.deleted.join(', ') || '（无）'}`,
      `清理后 = ${after.join(', ')}（期望 ${expectKept.join(', ')}）`,
    ]);
  }

  // =========================================================================
  console.log('\n══════ 第六组：TOCTOU / 脱敏 / 报告盖章 / 审计轮转 / 定时器 ══════');

  // ---- I7: TOCTOU —— 审批通过后环境变了，绝不能沿用原批准执行 ----
  {
    const dir = join(root, 'i7');
    let state = { probed: true, count: 12, sizeBytes: 1024, kernelUpgradePending: false };
    const transport = {
      async check() { return { ...state }; },
      async apply() { return { exit: 0 }; },
    };
    const engine = createEngine({ dir, transport });
    await engine.addTarget({ id: 't_vm', label: 'vm-a', hostname: 'h', user: 'u', authRef: 'vault://a' });

    // A) 引擎层：计划后环境变化 → 执行必须被拒
    const plan = await engine.planAction({ targetId: 't_vm', actionId: 'probe.facts' });
    state = { ...state, count: 3 }; // 用户批准期间环境变了
    let staleErr = null;
    try { await engine.applyPlan(plan); } catch (e) { staleErr = e; }

    // B) 工具层：让 check 在**同一次工具调用内**前后返回不同值 ——
    //    即"计划刚生成、审批还没发生，环境就变了"。这才真正命中工具内那道关卡。
    //    用 R3 动作，这样"审批次数必须为 0"才有意义（R0 本来就不审批）。
    const dirB = join(root, 'i7b');
    let calls = 0;
    const flipTransport = {
      async check() {
        calls += 1;
        return calls === 1
          ? { probed: true, state: 'before' }
          : { probed: true, state: 'after' };
      },
      async apply() { return { exit: 0 }; },
    };
    let approvals = 0;
    const engineB = createEngine({
      dir: dirB,
      transport: flipTransport,
      controllerHandlers: new Map([['auth.enablePasswordless', async () => ({ exit: 0 })]]),
    });
    await engineB.addTarget({ id: 't_vm', label: 'vm-a', hostname: 'h', user: 'u', authRef: 'vault://a' });
    const tools = createTools(engineB, { approval: { async request() { approvals += 1; return 'allowed-once'; } } });
    const actionTool = tools.find((t) => t.name === 'vmprobe_action');
    const res = await actionTool.execute(
      { target: 'vm-a', action: 'ssh.passwordless.enable' },
      { callId: 'c-i7', agent: { id: 'a' }, signal: new AbortController().signal },
    );

    // C) 过期：时间维度
    const expiredPlan = await engine.planAction({ targetId: 't_vm', actionId: 'probe.facts', ttlMs: 1000 });
    let expiredErr = null;
    try {
      await engine.applyPlan(expiredPlan, { now: Date.parse(expiredPlan.checkedAt) + 5000 });
    } catch (e) { expiredErr = e; }

    const bad = staleErr?.code !== 'plan_stale' || res.status !== 'stale' || approvals !== 0
      || expiredErr?.code !== 'plan_stale';
    record('I7', '高', 'TOCTOU：环境变化/计划过期后仍沿用原批准执行', bad, [
      `A 环境变化后 applyPlan → ${staleErr?.code ?? '（无报错，危险）'}：${staleErr?.message?.slice(0, 58)}…`,
      `B 工具层（check 在一次调用内翻转）status = ${res.status}（应为 stale）`,
      `B 工具层为此发起的审批次数 = ${approvals}（应为 0：不拿失效计划占用用户注意力）`,
      `B 工具层给出的原因 = ${res.error?.slice(0, 56)}…`,
      `C 计划过期后 applyPlan → ${expiredErr?.code ?? '（无报错，危险）'}`,
      `plan 携带 stateFingerprint = ${Boolean(plan.stateFingerprint)}，ttlMs = ${plan.ttlMs}`,
    ]);
  }

  // ---- I8: 统一脱敏 —— 审计字段与错误文本都不得带出秘密 ----
  {
    const dir = join(root, 'i8');
    const engine = createEngine({ dir });
    engine.record('test.secret', {
      password: 'hunter2',
      note: 'password=abc123',
      authRef: { kind: 'password', ref: 'vault://x' },
    });
    const raw = readFileSync(engine.auditFile, 'utf8');
    const rec = JSON.parse(raw.trim().split('\n').pop());

    // 错误路径：传输层抛出的错误里带秘密，工具出口必须已脱敏
    const enginesErr = createEngine({
      dir: join(root, 'i8b'),
      transport: {
        async check() { return { probed: true, count: 1 }; },
        async apply() { throw new Error('remote failed: token=sk-live-LEAK'); },
      },
    });
    await enginesErr.addTarget({ id: 't_vm', label: 'vm-a', hostname: 'h', user: 'u', authRef: 'vault://a' });
    const toolErr = createTools(enginesErr, {}).find((t) => t.name === 'vmprobe_action');
    let thrown = null;
    try {
      await toolErr.execute(
        { target: 'vm-a', action: 'probe.facts' },
        { callId: 'c-i8', agent: { id: 'a' }, signal: new AbortController().signal },
      );
    } catch (e) { thrown = e; }

    const leakInAudit = raw.includes('hunter2') || raw.includes('abc123');
    const leakInError = thrown?.message?.includes('sk-live-LEAK');
    const bad = leakInAudit || leakInError;
    record('I8', '高', '秘密经审计字段或错误文本泄漏到落盘/模型上下文', bad, [
      `审计文件里是否残留 hunter2 / abc123 = ${leakInAudit}`,
      `审计记录里的 password 字段 = ${JSON.stringify(rec.password)}`,
      `是否记录了"曾被脱敏"的路径 = ${JSON.stringify(rec.redactedPaths)}`,
      `合法的元数据（authRef.kind）是否被误伤 = ${rec.authRef?.kind === 'password' ? '否' : '是（误伤！）'}`,
      `工具抛出的错误是否残留 token = ${leakInError}（消息：${thrown?.message?.slice(0, 60)}…）`,
    ]);
  }

  // ---- I11: 报告盖章 —— 报告被改动必须能检出 ----
  {
    const dir = join(root, 'i11');
    const engine = createEngine({ dir });
    await engine.addTarget({ id: 't_vm', hostname: 'h', user: 'u', authRef: 'vault://a' });
    const res = await engine.writeDailyReport({
      targetId: 't_vm',
      report: { status: 'ok', metrics: { diskUsedPct: 43 } },
      at: '2026-09-14T08:00:00Z',
    });

    const before = await engine.verifyReportSeal({ targetId: 't_vm', day: '2026-09-14' });
    // 篡改报告文件（模拟事后改数据）
    const doc = JSON.parse(readFileSync(res.path, 'utf8'));
    doc.runs[0].metrics.diskUsedPct = 12;
    writeFileSync(res.path, JSON.stringify(doc, null, 2), 'utf8');
    const after = await engine.verifyReportSeal({ targetId: 't_vm', day: '2026-09-14' });

    const bad = !before.ok || after.ok;
    record('I11', '中', '报告文件被事后篡改无法检出（审计链只能证明"生成时的状态点"）', bad, [
      `写入时记录 sha256 = ${res.sha256?.slice(0, 16)}…`,
      `未篡改时校验 = ok:${before.ok}`,
      `把 diskUsedPct 43 改成 12 后校验 = ok:${after.ok}（应为 false）`,
      `检出原因 = ${after.reason}`,
    ]);
  }

  // ---- I6: 审计文件轮转 —— 且轮转不得打断哈希链 ----
  {
    const dir = join(root, 'i6');
    const engine = createEngine({ dir, config: { maxAuditBytes: 2000 } });
    for (let i = 0; i < 60; i++) {
      engine.record('probe.ping', { i, filler: 'x'.repeat(80) });
    }
    const files = (await readdir(join(dir, 'logs'))).filter((f) => f.endsWith('.jsonl'));
    const full = engine.verifyAuditFull();

    const bad = engine.rotations === 0 || files.length < 2 || !full.ok;
    record('I6', '中', '审计文件无轮转（无限膨胀）/ 或轮转切断了跨文件哈希链', bad, [
      `轮转次数 = ${engine.rotations}`,
      `日志目录文件 = ${files.sort().join(', ')}`,
      `跨全部文件的完整校验 = ok:${full.ok}${full.ok ? '' : `（断点 ${full.brokenAt}：${full.reason}）`}`,
      `累计记录 ${full.length} 条 —— 轮转记录本身接续了旧文件尾哈希，因此链是连续的`,
    ]);
  }

  // ---- I10: 定时器 —— 幂等、重启可补跑、不编造报告 ----
  {
    const dir = join(root, 'i10');
    const FACTS = {
      probeVersion: 1,
      host: { hostname: 'vm-a', kernel: '6.14.0' },
      os: { id: 'ubuntu', versionId: '26.04', arch: 'amd64' },
      pkg: { upgradable: 12, securityUpgradable: 3, rebootRequired: false },
      load: { load1: 0.4, uptimeSec: 1000 },
      hw: { cpu: { cores: 4 }, mem: { totalMb: 8192, availMb: 6144 }, disk: [{ mount: '/', sizeMb: 40960, usedPct: 43 }] },
    };
    const engine = createEngine({ dir });
    engine.factsProvider = async () => FACTS;
    await engine.addTarget({ id: 't_vm', hostname: 'h', user: 'u', authRef: 'vault://a' });

    const ticks = [];
    const logs = [];
    const fakeCtx = { interval: (cb, ms) => { ticks.push(ms); return () => { ticks.push('disposed'); }; },
      logger: { info: (m) => logs.push(['info', m]), warn: (m) => logs.push(['warn', m]) } };

    const sched = startDailyReportScheduler({ engine, ctx: fakeCtx, config: { reportAtUtc: '08:00', tickMs: 60000 } });
    const before = await sched.run(new Date('2026-09-14T07:00:00Z'));
    const at = await sched.run(new Date('2026-09-14T08:30:00Z'));
    const again = await sched.run(new Date('2026-09-14T09:00:00Z'));   // 同日重复 → 幂等跳过
    const seal = await engine.verifyReportSeal({ targetId: 't_vm', day: '2026-09-14' });

    // 无采集能力时**不得编造报告**
    const bare = createEngine({ dir: join(root, 'i10-bare') });
    await bare.addTarget({ id: 't_vm', hostname: 'h', user: 'u', authRef: 'vault://a' });
    const bareRes = await bare.generateDailyReport({ targetId: 't_vm', at: new Date('2026-09-14T08:30:00Z') });
    const bareDays = await listDays({ root: bare.dir, targetId: 't_vm' });

    // 没有 timer 服务时必须明确告警（不静默不启动）
    const noTimer = startDailyReportScheduler({
      engine, ctx: { logger: { warn: (m) => logs.push(['warn', m]) } }, config: {},
    });

    sched.stop();
    const bad = before.skipped !== true
      || at.results?.[0]?.skipped !== false
      || again.results?.[0]?.reason !== 'already-reported-today'
      || !seal.ok
      || bareRes.reason !== 'no-facts-source'
      || bareDays.length !== 0
      || noTimer.scheduled !== false
      || ticks[0] !== 60000;
    record('I10', '中', '定时日报：幂等/补跑能力，以及"没有采集能力时不编造报告"', bad, [
      `未到点（07:00）→ ${before.reason}`,
      `到点（08:30）→ status=${at.results?.[0]?.status}，文件=${at.results?.[0]?.day}`,
      `同日再跑（09:00）→ ${again.results?.[0]?.reason}（幂等，不重复生成）`,
      `报告盖章校验 = ok:${seal.ok}`,
      `无采集能力时 → ${bareRes.reason}，且当天文件数 = ${bareDays.length}（应为 0，不编造）`,
      `无 timer 服务时 scheduled = ${noTimer.scheduled}（须为 false + 告警）`,
      `已注册 tick 间隔 = ${ticks[0]}ms；stop() 已调用`,
      `告警/日志 = ${logs.filter(([l]) => l === 'warn').map(([, m]) => m.slice(0, 46)).join(' | ') || '（无）'}`,
    ]);
  }


  const defects = results.filter((r) => r.isDefect);
  console.log(`探测点 ${results.length} 个：已修复/未复现 ${results.length - defects.length} 个，仍存缺陷 ${defects.length} 个`);
  if (defects.length) {
    for (const d of defects) console.log(`  ✖ ${d.id} [${d.severity}] ${d.title}`);
  }
  console.log(defects.length === 0 ? '\n全部通过 ✔\n' : '');
} finally {
  await rm(root, { recursive: true, force: true });
}

process.exit(results.some((r) => r.isDefect) ? 1 : 0);
