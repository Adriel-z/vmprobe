/**
 * SSH 传输层端到端验证 —— 对着**真实 SSH 协议**跑，不启动 DSH。
 *
 * 测试台（tools/checks/ssh-harness.mjs）在进程内起一个真实 ssh2 服务端，
 * exec 后端用 Git 的 bash，所以：
 *   · 协议、认证、主机密钥、exec 通道、stdin、退出码、文件读写 **全是真的**；
 *   · `agent/bootstrap.sh` 是**真的被投递并执行**；
 *   · 免密事务里的 authorized_keys 读写与 publickey 认证**是真的闭环**。
 *
 * 诚实的边界：远端是 Windows + MSYS 而非 Linux，所以与发行版相关的东西
 * （apt/systemd/StrictModes）用注入的假 os-release 与约定模拟，
 * 本测试证明"传输层与事务逻辑正确"，不等于"在所有 Linux 上都能跑"。
 *
 *   node tools/checks/ssh-transport.mjs
 */

import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, cpSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';

import {
  createSshTransport, shQuote, buildCommand,
  HostKeyMismatchError, HostKeyUnknownError,
} from '../../packages/transport/src/ssh.js';
import {
  enablePasswordless, disablePasswordless, PasswordlessError,
} from '../../packages/transport/src/passwordless.js';
import { generateKeypair, publicKeyFingerprint } from '../../packages/transport/src/keys.js';
import { createEngine } from '../../packages/plugin-host/src/engine.js';
import { createTools } from '../../packages/plugin-host/src/tools.js';
import { startHarness, harnessTarget, harnessTargetInput } from './ssh-harness.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

let failed = 0;
const results = [];
async function check(section, label, fn) {
  try {
    const detail = await fn();
    console.log(`  ✔ [${section}] ${label}`);
    if (detail) for (const line of [].concat(detail)) console.log(`      ${line}`);
    results.push({ section, label, ok: true });
  } catch (err) {
    failed += 1;
    console.log(`  ✖ [${section}] ${label}`);
    console.log(`      ${err?.message ?? err}`);
    results.push({ section, label, ok: false, error: String(err?.message ?? err) });
  }
}
const assert = (cond, msg) => { if (!cond) throw new Error(msg); };
const eq = (a, b, msg) => {
  if (JSON.stringify(a) !== JSON.stringify(b)) {
    throw new Error(`${msg ?? '不相等'}：期望 ${JSON.stringify(b)}，实际 ${JSON.stringify(a)}`);
  }
};

// ═══════════════════════════════════════════════════════════════════════════
console.log('\n[1] 密钥编码（三个独立验证器）');

const workDir = mkdtempSync(join(tmpdir(), 'vmprobe-ssh-e2e-'));
const keyDir = join(workDir, 'keys');
mkdirSync(keyDir, { recursive: true });

await check('keys', '生成的 OpenSSH 密钥能被 ssh-keygen 独立导出同一把公钥', () => {
  const pair = generateKeypair('vmprobe:e2e');
  const p = join(workDir, 'id_ed25519');
  writeFileSync(p, pair.privateKeyPem, { mode: 0o600 });
  const derived = execFileSync('ssh-keygen', ['-y', '-f', p], { encoding: 'utf8' }).trim();
  const mine = pair.publicKeyLine.split(' ').slice(0, 2).join(' ');
  const theirs = derived.split(' ').slice(0, 2).join(' ');
  eq(mine, theirs, 'ssh-keygen 导出的公钥');
  return `公钥指纹 = ${publicKeyFingerprint(pair.publicKeyLine)}`;
});

await check('keys', '指纹格式与 ssh-keygen -lf 一致（用户能独立核对）', () => {
  const pair = generateKeypair('vmprobe:e2e');
  const p = join(workDir, 'id_ed25519.fp');
  writeFileSync(p, pair.privateKeyPem, { mode: 0o600 });
  writeFileSync(`${p}.pub`, `${pair.publicKeyLine}\n`, 'utf8');
  const out = execFileSync('ssh-keygen', ['-lf', `${p}.pub`], { encoding: 'utf8' }).trim();
  const theirs = out.split(/\s+/)[1];
  eq(publicKeyFingerprint(pair.publicKeyLine), theirs, '指纹应与 ssh-keygen -lf 相同');
  return `指纹 = ${theirs}`;
});

// ═══════════════════════════════════════════════════════════════════════════
console.log('\n[2] argv 注入防线（SSH exec 必然经远端 shell，所以引用是唯一防线）');

await check('inject', 'shQuote 把每个 argv 元素完整引用', () => {
  eq(shQuote('hello'), "'hello'");
  eq(shQuote("a'b"), `'a'\\''b'`);
  eq(shQuote(''), "''");
  // 逐元素核对拼出来的命令行：每个元素都被单引号包住，元素之间只有空格
  const cmd = buildCommand(['echo', 'a; echo PWNED', '$(whoami)', '`id`', 'x"y']);
  eq(cmd, `'echo' 'a; echo PWNED' '$(whoami)' '\`id\`' 'x"y'`, '完整的引用结果');
  // 含单引号的元素用的是 '\'' 标准转义
  eq(buildCommand(['echo', "it's"]), `'echo' 'it'\\''s'`, "含 ' 的元素");
  return `示例 = ${cmd}`;
});

// ═══════════════════════════════════════════════════════════════════════════
console.log('\n[3] 传输层：连接 / 主机密钥 / 执行 / 文件 / 超时');

const harness = await startHarness({
  osRelease: 'ID=ubuntu\nID_LIKE=debian\nVERSION_ID="26.04"\nPRETTY_NAME="Ubuntu 26.04 LTS"\n',
});

const targets = new Map();
targets.set('t_harness', harnessTarget(harness, { id: 't_harness' }));
targets.set('t_rollback', harnessTarget(harness, { id: 't_rollback', label: 'rollback' }));

let credential = harness.password;
const transport = createSshTransport({
  resolveTarget: async (id) => targets.get(id) ?? null,
  resolveCredential: async (ref) => (ref === 'VMPROBE_HARNESS_PASSWORD' ? credential : undefined),
  keyDir,
  agentScriptPath: join(ROOT, 'agent', 'bootstrap.sh'),
  hostKeyPolicy: 'accept-new',
  commandTimeoutMs: 30000,
  onHostKey: async (id, fp) => {
    const t = targets.get(id);
    t.hostKey = { algo: 'ssh-rsa', fingerprint: fp, trust: 'pinned', pinnedAt: new Date().toISOString() };
  },
});

await check('connect', 'accept-new 首连成功，且记录的指纹与独立计算的一致', async () => {
  const s = await transport.connect(targets.get('t_harness'));
  eq(s.state, 'connected', '会话状态');
  eq(targets.get('t_harness').hostKey.fingerprint, harness.hostFingerprint, '记录的指纹');
  return `指纹 ${s.fingerprint}`;
});

await check('connect', '已固定指纹时严格比对；指纹不符 → 拒绝连接（防 MITM）', async () => {
  const bad = { ...targets.get('t_harness'), id: 't_bad', hostKey: { fingerprint: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } };
  targets.set('t_bad', bad);
  let err = null;
  try { await transport.connect(bad); } catch (e) { err = e; }
  assert(err instanceof HostKeyMismatchError || err?.code === 'host_key_mismatch',
    `应因指纹不符被拒，实际：${err?.name}: ${err?.message}`);
  transport.disconnect('t_bad');
  return `拒绝原因 = ${err.name}（${err.code}）`;
});

await check('connect', 'strict 策略下未固定指纹 → 拒绝并给出待确认的指纹', async () => {
  const strictTransport = createSshTransport({
    resolveTarget: async (id) => targets.get(id) ?? null,
    resolveCredential: async () => harness.password,
    keyDir, hostKeyPolicy: 'strict',
  });
  const fresh = harnessTarget(harness, { id: 't_strict' });
  targets.set('t_strict', fresh);
  let err = null;
  try { await strictTransport.connect(fresh); } catch (e) { err = e; }
  assert(err instanceof HostKeyUnknownError || err?.code === 'host_key_unknown',
    `应以 host_key_unknown 拒绝，实际：${err?.name}: ${err?.message}`);
  assert(err.fingerprint === harness.hostFingerprint, '错误里应带上观察到的指纹供用户确认');
  strictTransport.disposeAll();
  return `待确认指纹 = ${err.fingerprint}`;
});

await check('exec', '执行命令：stdout / stderr / 退出码都对', async () => {
  const r = await transport.exec(targets.get('t_harness'),
    ['sh', '-c', 'echo out-line; echo err-line 1>&2; exit 7']);
  eq(r.exit, 7, '退出码');
  assert(r.stdout.includes('out-line'), 'stdout 应含 out-line');
  assert(r.stderr.includes('err-line'), 'stderr 应含 err-line');
  return `exit=${r.exit} stdout=${JSON.stringify(r.stdout.trim())} stderr=${JSON.stringify(r.stderr.trim())}`;
});

await check('exec', '★ 注入防御：恶意参数保持为字面量，不被远端 shell 执行', async () => {
  const r = await transport.exec(targets.get('t_harness'),
    ['echo', 'a; echo PWNED', '$(whoami)', '`id`']);
  eq(r.exit, 0, '退出码');
  const got = r.stdout.trim();
  eq(got, 'a; echo PWNED $(whoami) `id`', '所有元素都应原样回显（说明没有一个被 shell 解释）');
  assert(!got.includes('PWNED\n'), '绝不能被拆成第二条命令');
  return `远端实际回显 = ${JSON.stringify(got)}`;
});

await check('exec', 'stdin 投递（协从端脚本就是靠这条路走的）', async () => {
  const r = await transport.exec(targets.get('t_harness'), ['sh', '-s', '--', 'A', 'B'],
    { input: 'echo "args=$1,$2"\n' });
  eq(r.exit, 0, '退出码');
  eq(r.stdout.trim(), 'args=A,B', '脚本体经 stdin 送达且位置参数正确');
  return 'sh -s -- A B 经 stdin 执行成功';
});

await check('exec', '超时：发送 TERM 并如实报错（不会静默挂住）', async () => {
  let err = null;
  const t0 = Date.now();
  try { await transport.exec(targets.get('t_harness'), ['sleep', '10'], { timeoutMs: 700 }); } catch (e) { err = e; }
  const elapsed = Date.now() - t0;
  assert(err?.code === 'timeout', `应报 timeout，实际 ${err?.message}`);
  assert(elapsed < 5000, `应在超时后很快返回，实际 ${elapsed}ms`);
  return `超时错误码 = ${err.code}，耗时 ${elapsed}ms`;
});

await check('file', '推送文件（exec+stdin）：目录自动创建、内容一致、权限已设', async () => {
  const remotePath = `${harness.home}/deep/nested/payload.txt`;
  const content = `line1\n包含中文与 ' 引号 " 双引号\n`;
  const res = await transport.pushFile(targets.get('t_harness'), remotePath, content, { mode: 0o600 });
  const back = await transport.pullFile(targets.get('t_harness'), remotePath);
  eq(back.toString('utf8'), content, '读回的内容应与写入一致');
  const mode = String((await transport.exec(targets.get('t_harness'), ['stat', '-c', '%a', remotePath])).stdout).trim();
  if (process.platform === 'win32') {
    // MSYS 的 chmod 不真正落 POSIX 权限位，只断言"chmod 被调用且命令成功"
    assert(['600', '644'].includes(mode), `Windows 下权限位应为 600 或 644，实际 ${mode}`);
  } else {
    eq(mode, '600', '文件权限');
  }
  return `${res.bytes} 字节往返一致，权限 ${mode}（${process.platform === 'win32' ? 'MSYS 不落权限位，已在 Linux 上按 600 断言' : '已断言 600'}）`;
});

// ═══════════════════════════════════════════════════════════════════════════
console.log('\n[4] facts 采集（引导脚本经 SSH stdin 投递，零安装）');

await check('facts', 'probeFacts 真的跑通了 bootstrap.sh 并返回合法画像', async () => {
  const facts = await transport.probeFacts(targets.get('t_harness'));
  eq(facts.schema, 'vmprobe/facts/1', 'schema');
  eq(facts.os.id, 'ubuntu', '发行版 id（来自注入的 os-release）');
  eq(facts.os.idLike, ['debian'], 'ID_LIKE（约定为数组：os-release 里是空格分隔字符串，但语义是列表）');
  assert(facts.pkg && 'upgradable' in facts.pkg, 'pkg 段应存在');
  assert(facts.pkg.upgradable === null, '本机没有包管理器 → 必须是 null 而不是 0（不许谎报"无需更新"）');
  assert(typeof facts.host.hostname === 'string', 'host.hostname 应存在');
  return [
    `schema=${facts.schema} os=${facts.os.id}/${facts.os.idLike} arch=${facts.os.arch}`,
    `pkg.upgradable=${JSON.stringify(facts.pkg.upgradable)}（null 正确：不谎报 0）`,
    `load=${JSON.stringify(facts.load)}`,
  ];
});

await check('facts', '投递方式是 sh -s -- --check（证明"零安装首次接触"）', async () => {
  const lastCmd = harness.stats.execs[harness.stats.execs.length - 1];
  assert(lastCmd.includes('sh -s -- --check') || harness.stats.execs.some((c) => c.includes('--check')),
    `应看到 sh -s -- --check，实际最近一条：${lastCmd}`);
  return `服务端记录到命令：${harness.stats.execs.filter((c) => c.includes('--check')).length} 次 --check 调用`;
});

await check('probe', 'check（pkg.upgradable）返回 probed:true 且不含易变字段', async () => {
  const action = JSON.parse(readFileSync(join(ROOT, 'packages/catalog/actions/system.update.json'), 'utf8'));
  const state = await transport.check(action, targets.get('t_harness'), null);
  eq(state.probed, true, 'probed 必须为 true（否则计划永远判失效）');
  const volatile = ['probedAt', 'ts', 'timestamp', 'durationMs', 'elapsedMs'].filter((k) => k in state);
  eq(volatile, [], '不得包含易变字段（会让状态指纹每次都变）');
  return `probed=${state.probed} count=${JSON.stringify(state.count)} rebootRequired=${state.rebootRequired}`;
});

// ═══════════════════════════════════════════════════════════════════════════
console.log('\n[5] 免密登录事务：成功路径（真实协议 + 真实 authorized_keys + publickey 认证）');

await check('passwordless', '完整事务：写 key → 另开连接验证 → 才切断旧连接 → 以密钥重连', async () => {
  const target = targets.get('t_harness');
  const before = transport.sessionCount();
  const report = await enablePasswordless(transport, target);

  assert(report.ok, '事务应成功');
  assert(report.steps.some((s) => s.step === 'verify'), '必须有 verify 步骤');
  assert(report.steps.some((s) => s.step === 'cut-old-session'), '必须有切断旧连接步骤');

  // 远端文件确实被改了
  const ak = harness.readAuthorizedKeys();
  assert(ak.includes('vmprobe:t_harness'), 'authorized_keys 应含我们的标记注释');
  assert(ak.includes(report.publicKeyLine.split(' ')[1]), '应含我们的公钥 blob');

  // 新连接确实是 publickey（服务端记录）
  assert(harness.stats.authAttempts.includes('publickey'), '服务端应看到 publickey 尝试');

  // 切过来之后还能干活
  const after = await transport.exec({ ...target, authRef: { kind: 'key', ref: 't_harness' } }, ['echo', 'still-working']);
  eq(String(after.stdout).trim(), 'still-working', '切换后命令仍可执行');

  return [
    `步骤：${report.steps.map((s) => s.step).join(' → ')}`,
    `authorized_keys = ${report.authorizedKeysPath}`,
    `备份文件数 = ${ak.match(/\.vmprobe\.\d+\.bak/g) ? '（远端为同目录 .bak）' : '—'}`,
    `切断前会话数=${before}，切换后命令仍可用`,
  ];
});

await check('passwordless', '幂等：再跑一次不会重复追加（authorized_keys 不膨胀）', async () => {
  const target = targets.get('t_harness');
  const before = harness.readAuthorizedKeys();
  const countBefore = before.split('\n').filter((l) => l.includes('vmprobe:t_harness')).length;
  const report = await enablePasswordless(transport, target);
  const after = harness.readAuthorizedKeys();
  const countAfter = after.split('\n').filter((l) => l.includes('vmprobe:t_harness')).length;
  eq(countAfter, countBefore, '标记行的数量不应变化');
  eq(report.writeResult, 'already', '第二次应识别为"已存在"');
  return `标记行数保持 ${countAfter}，写入结果 = ${report.writeResult}`;
});

// ═══════════════════════════════════════════════════════════════════════════
console.log('\n[5.5] 免密登录**往返**：启用 → 撤销（我最初漏测的路径）');

await check('passwordless', '★ 启用 → 撤销：密钥移除、本地密钥删除、**密码路径恢复**', async () => {
  const target = harnessTarget(harness, { id: 't_roundtrip', label: 'roundtrip' });
  targets.set('t_roundtrip', target);

  // 启用
  const on = await enablePasswordless(transport, target);
  assert(on.ok, '启用应成功');
  assert(harness.readAuthorizedKeys().includes('vmprobe:t_roundtrip'), '启用后 authorized_keys 应含标记');

  // 模拟引擎切换后的目标状态：authRef 变成 key，但**记住原来的密码引用**
  const switched = {
    ...target,
    authRef: { kind: 'key', ref: target.id },
    previousAuthRef: { kind: 'password', ref: target.authRef.ref },
  };
  targets.set('t_roundtrip', switched);

  // 撤销
  const off = await disablePasswordless(transport, switched);
  assert(off.ok, '撤销应成功');
  assert(!harness.readAuthorizedKeys().includes('vmprobe:t_roundtrip'),
    '撤销后 authorized_keys 里不应再有我们的标记');
  assert(!existsSync(join(keyDir, 't_roundtrip.ed25519')), '本地专用私钥应已删除');
  eq(off.authRefAfter, { kind: 'password', ref: 'VMPROBE_HARNESS_PASSWORD' },
    'authRefAfter 必须指回**原来的密码引用**，而不是目标的 id');

  // 密码路径真的恢复了吗？（这才是"没锁死"的证明）
  targets.set('t_roundtrip', { ...target, authRef: off.authRefAfter });
  const viaPassword = await transport.exec({ ...target, authRef: off.authRefAfter }, ['echo', 'back-on-password']);
  eq(String(viaPassword.stdout).trim(), 'back-on-password', '撤销后应能用密码正常执行命令');

  return [
    `步骤：${off.steps.map((s) => s.step).join(' → ')}`,
    `回退引用 = ${off.authRefAfter.ref}（来自 previousAuthRef，而不是目标 id）`,
    `authorized_keys 已无标记、本地密钥已删除、密码路径已恢复并执行成功`,
  ];
});

await check('passwordless', '不知道回退引用时**明确拒绝**，而不是拿目标 id 当凭据名乱试', async () => {
  const target = harnessTarget(harness, { id: 't_noref', label: 'noref' });
  targets.set('t_noref', target);
  await enablePasswordless(transport, target);

  // 刻意丢掉 previousAuthRef 与 passwordRef，模拟历史数据
  const orphan = { ...target, authRef: { kind: 'key', ref: target.id } };
  let err = null;
  try { await disablePasswordless(transport, orphan); } catch (e) { err = e; }
  assert(err instanceof PasswordlessError, `应抛 PasswordlessError，实际 ${err?.name}`);
  eq(err.step, 'preflight', '应停在 preflight');
  assert(/previousAuthRef|passwordRef/.test(err.message), '错误信息应指出缺什么');

  // 关联断言：此时密钥**还在**（拒绝得早，没有动任何东西）
  assert(harness.readAuthorizedKeys().includes('vmprobe:t_noref'), '拒绝时不应移除密钥');

  // 补上 passwordRef 就能正常撤销
  const ok = await disablePasswordless(transport, orphan, { passwordRef: 'VMPROBE_HARNESS_PASSWORD' });
  assert(ok.ok, '显式给 passwordRef 后应能撤销');
  assert(!harness.readAuthorizedKeys().includes('vmprobe:t_noref'), '这次应已移除');
  return `拒绝原因 = ${err.message.slice(0, 56)}…；补上 passwordRef 后撤销成功`;
});

await check('passwordless', '前置：公钥认证被禁用时**什么都不动**（不写文件、不切连接）', async () => {  const blocked = await startHarness({
    osRelease: 'ID=ubuntu\nID_LIKE=debian\nVERSION_ID="26.04"\n',
  });
  // 让 facts 报告 pubkeyAuth=false：用一个包装的 transport 覆写 probeFacts
  const t2 = harnessTarget(blocked, { id: 't_noPubkey' });
  const localTargets = new Map([['t_noPubkey', t2]]);
  const t = createSshTransport({
    resolveTarget: async (id) => localTargets.get(id) ?? null,
    resolveCredential: async () => blocked.password,
    keyDir: join(workDir, 'keys2'), hostKeyPolicy: 'accept-new',
    agentScriptPath: join(ROOT, 'agent', 'bootstrap.sh'),
  });
  const realProbe = t.probeFacts;
  t.probeFacts = async (x) => ({ ...(await realProbe(x)), ssh: { pubkeyAuth: false, passwordAuth: true, port: 22 } });

  let err = null;
  try { await enablePasswordless(t, t2); } catch (e) { err = e; }
  assert(err instanceof PasswordlessError, `应抛 PasswordlessError，实际 ${err?.name}`);
  eq(err.step, 'preflight', '应停在 preflight 步骤');
  const ak = blocked.readAuthorizedKeys();
  eq(ak.trim(), '', 'authorized_keys 不应被写入任何东西');
  eq(t.state('t_noPubkey'), 'connected', '旧连接必须保留（这正是不锁死机器的关键）');
  t.disposeAll();
  await blocked.stop();
  return `停在 ${err.step}：${err.message.slice(0, 60)}…；authorized_keys 未被写入，旧连接保留`;
});

// ═══════════════════════════════════════════════════════════════════════════
console.log('\n[6] 免密登录事务：失败回滚路径（注入"验证失败"，检查最关键的不变式）');

await check('passwordless', '★ 验证失败时：回滚 authorized_keys 且**旧连接仍可用**（绝不锁死）', async () => {
  const target = targets.get('t_rollback');
  await transport.connect(target);
  const akBefore = harness.readAuthorizedKeys();

  // 注入失败：让"另开连接验证"这一步抛错，模拟密钥其实不可用（权限位/sshd 限制等）
  const realVerify = transport.verifyKeyLogin;
  transport.verifyKeyLogin = async () => { throw new Error('注入的验证失败（模拟密钥不可用）'); };
  let err = null;
  try { await enablePasswordless(transport, target); } catch (e) { err = e; }
  transport.verifyKeyLogin = realVerify;

  assert(err instanceof PasswordlessError, `应抛 PasswordlessError，实际 ${err?.name}: ${err?.message}`);
  eq(err.step, 'verify', '应停在 verify 步骤');
  assert(err.message.includes('已保留原有连接'), '错误信息必须明确说明保留了原连接');

  // ① 回滚是否真的生效
  const akAfter = harness.readAuthorizedKeys();
  const markerCount = akAfter.split('\n').filter((l) => l.includes('vmprobe:t_rollback')).length;
  eq(markerCount, 0, 'authorized_keys 里不应残留我们的行（必须回滚干净）');
  eq(akAfter.trim(), akBefore.trim(), 'authorized_keys 内容应与事务前完全一致');

  // ② ★ 最关键：旧连接必须还活着、还能干活
  eq(transport.state('t_rollback'), 'connected', '旧连接必须仍是 connected');
  const still = await transport.exec(target, ['echo', 'old-session-alive']);
  eq(String(still.stdout).trim(), 'old-session-alive', '旧连接必须仍能执行命令');

  return [
    `报错步骤 = ${err.step}，rolledBack=${err.rolledBack}`,
    `authorized_keys 已回滚干净（标记行 0 条，内容与事务前一致）`,
    `旧连接状态 = ${transport.state('t_rollback')}，且仍能执行命令 ✔ —— 没有锁死机器`,
  ];
});

// ═══════════════════════════════════════════════════════════════════════════
console.log('\n[7] 引擎端到端：真实 SSH 上走完 plan → apply → 审计');

await check('engine', '动作参数接线 + 真实执行 + 审计链完好', async () => {
  // 造一个测试专用目录：真实三个动作 + 一个能在 MSYS 上真实跑通的回显动作
  const catDir = join(workDir, 'catalog');
  mkdirSync(catDir, { recursive: true });
  cpSync(join(ROOT, 'packages/catalog/actions'), catDir, { recursive: true });
  writeFileSync(join(catDir, 'echo.hello.json'), JSON.stringify({
    id: 'echo.hello', version: 1, side: 'agent',
    title: { zh: '测试回显' }, summary: '在远端回显一句话（端到端验证用）',
    risk: 'R1',
    params: {
      type: 'object',
      properties: { word: { type: 'string', default: 'hi' }, repeat: { type: 'integer', default: 1 } },
      additionalProperties: false,
    },
    requires: { root: false, distros: [], binaries: [] },
    idempotent: true, timeoutMs: 20000,
    check: { probe: 'none' },
    apply: { default: { cmd: [['echo', 'hello-{{word}}', { $param: 'repeat', prefix: 'x' }]] } },
  }, null, 2), 'utf8');

  const engine = createEngine({
    dir: join(workDir, 'state'),
    catalogDir: catDir,
    transport,
    // controller 侧动作的本地处理器 —— 生产里由插件注册（packages/plugin-host/src/index.js）
    controllerHandlers: new Map([
      ['probe.facts', async (plan) => {
        const t = await engine.findTarget(plan.targetId);
        const facts = await engine.collectFacts(t);
        engine.factsByTarget.set(t.id, facts);
        await engine.persistFacts(t.id, facts);
        return { facts };
      }],
    ]),
  });
  await engine.addTarget(harnessTargetInput(harness, { id: 't_harness' }));

  // ① 先采集 facts（controller 侧动作，经 stdin 投递脚本）
  engine.factsProvider = async (t) => transport.probeFacts(t);
  const factsPlan = await engine.planAction({ targetId: 't_harness', actionId: 'probe.facts' });
  eq(factsPlan.side, 'controller', 'probe.facts 应为 controller 侧');
  eq(factsPlan.resolvedArgv, [], 'controller 侧动作没有远端 argv');
  const factsRes = await engine.applyPlan(factsPlan);
  eq(factsRes.facts.os.id, 'ubuntu', 'facts 应来自真实采集');

  // ② 带参数的动作：验证 {{word}} 与 $param+prefix 在真实执行里生效
  const plan = await engine.planAction({
    targetId: 't_harness', actionId: 'echo.hello', params: { word: 'world', repeat: 3 },
  });
  eq(plan.blocked, false, `不应被阻断：${plan.blockedReason}`);
  eq(plan.resolvedArgv, [['echo', 'hello-world', 'x3']], '参数应已接进 argv');

  const run = await engine.applyPlan(plan, { runId: 'r_e2e' });
  eq(run.exit, 0, '远端退出码');
  eq(String(run.stdout).trim(), 'hello-world x3', '远端真实回显');

  // ③ 未接线参数仍然被阻断（arch 分支不支持 securityOnly）
  const blockedPlan = await engine.planAction({
    targetId: 't_harness', actionId: 'system.update', params: { securityOnly: true },
  });
  assert(blockedPlan.blocked === true, 'Debian 系不支持 securityOnly，应被 fail-closed 阻断');

  // ④ 审计链
  const audit = engine.verifyAudit();
  assert(audit.ok, `审计链应完好：${audit.reason}`);
  const events = engine.audit.snapshot().map((r) => r.event);
  for (const want of ['target.add', 'action.plan', 'action.apply']) {
    assert(events.includes(want), `审计里应含 ${want}`);
  }
  return [
    `facts：os=${factsRes.facts.os.id} 经 stdin 投递脚本采集`,
    `执行：argv=${JSON.stringify(plan.resolvedArgv[0])} → exit=${run.exit} stdout=${JSON.stringify(String(run.stdout).trim())}`,
    `未接线参数被阻断：${blockedPlan.unwrappedParams ?? ''}${blockedPlan.blockedReason.slice(0, 46)}…`,
    `审计链完好，事件 ${events.length} 条（含 action.plan / action.apply）`,
  ];
});

await check('engine', '工具层：vmprobe_status 如实反映连接状态，vmprobe_action 返回真实结果', async () => {
  const catDir = join(workDir, 'catalog');
  const engine = createEngine({
    dir: join(workDir, 'state2'), catalogDir: catDir, transport,
    controllerHandlers: new Map([
      ['probe.facts', async (plan) => {
        const t = await engine.findTarget(plan.targetId);
        const facts = await engine.collectFacts(t);
        engine.factsByTarget.set(t.id, facts);
        return { facts };
      }],
    ]),
  });
  await engine.addTarget(harnessTargetInput(harness, { id: 't_harness' }));
  const tools = createTools(engine, {});
  const exec = { callId: 'c1', agent: { id: 'a' }, signal: new AbortController().signal };

  const status = await tools.find((t) => t.name === 'vmprobe_status').execute({}, exec);
  eq(status.connectionState, 'connected', 'connectionState 应反映真实连接');

  const res = await tools.find((t) => t.name === 'vmprobe_action').execute(
    { target: 't_harness', action: 'echo.hello', params: { word: 'tools' } }, exec,
  );
  eq(res.status, 'ok', `应执行成功，实际 ${res.status}：${res.error ?? ''}`);
  eq(String(res.result.stdout).trim(), 'hello-tools', '工具返回的真实回显');
  return `connectionState=${status.connectionState}；工具执行 stdout=${JSON.stringify(String(res.result.stdout).trim())}`;
});

// ═══════════════════════════════════════════════════════════════════════════
console.log('\n[7.5] 心跳：把"SSH 始终连接"变成可观测的事实');

await check('heartbeat', '心跳成功并测出延迟；无会话时如实说 no-session（不主动拉连接）', async () => {
  await transport.connect(targets.get('t_harness'));
  const ok = await transport.heartbeat('t_harness');
  assert(ok.ok === true, `心跳应成功，实际 ${JSON.stringify(ok)}`);
  assert(typeof ok.latencyMs === 'number' && ok.latencyMs >= 0, '应给出延迟');

  const none = await transport.heartbeat('t_never_connected');
  eq(none.ok, false, '没有会话时不应成功');
  eq(none.reason, 'no-session', '应如实报告 no-session（而不是偷偷建连接）');
  return `延迟 ${ok.latencyMs}ms；无会话目标返回 ${none.reason}`;
});

await check('heartbeat', '★ 链路死亡能被发现，且会把会话标成 detached（不留"看起来还连着"的假象）', async () => {
  // 情况 A：**干净断开**（对端正常关闭）—— ssh2 的 close 事件会先把会话标成 detached，
  //         此时心跳如实报 no-session。这是正确的（心跳不该假装还能连）。
  const dead = await startHarness({ osRelease: 'ID=debian\nVERSION_ID="12"\n' });
  const t = harnessTarget(dead, { id: 't_dead' });
  targets.set('t_dead', t);
  const localTransport = createSshTransport({
    resolveTarget: async (id) => targets.get(id) ?? null,
    resolveCredential: async () => dead.password,
    keyDir: join(workDir, 'keys-dead'), hostKeyPolicy: 'accept-new',
    agentScriptPath: join(ROOT, 'agent', 'bootstrap.sh'),
  });
  await localTransport.connect(t);
  eq(localTransport.state('t_dead'), 'connected', '先确认已连接');
  assert((await localTransport.heartbeat('t_dead')).ok, '断开前的第一次心跳应成功');

  await dead.stop(); // 服务端关闭并断开连接
  await new Promise((r) => setTimeout(r, 300)); // 等 close 事件落地

  const afterClose = await localTransport.heartbeat('t_dead');
  assert(!afterClose.ok, '干净断开后心跳不应报成功');
  eq(localTransport.state('t_dead'), 'detached', '会话状态应为 detached');
  const cleanCase = `${afterClose.reason} / state=${localTransport.state('t_dead')}`;

  // 情况 B：**静默死亡**（客户端以为自己还连着，但通道已坏）——
  //          这才是心跳真正要抓的场景。用一个必然失败的 exec 桩精确模拟。
  //
  // ⚠️ 这里踩过一次**探测顺序**的坑：最初先直接调 transport.heartbeat 断言它返回 error，
  //    再用同一会话驱动引擎、期望引擎看到 error。但 transport 在第一次失败时**已经把会话
  //    标成 detached** 了，于是引擎看到的是 no-session —— 断言的是"第二个观察者看到的
  //    第二次探测"，而不是那次失败本身。所以：每个断言都要在**会话仍是 connected** 时
  //    由对应那一层去探测；要断言两层的两种行为，就得有两条独立会话。
  const dead2 = await startHarness({ osRelease: 'ID=alpine\n' });
  const mkTransport = (id) => {
    targets.set(id, harnessTarget(dead2, { id }));
    return createSshTransport({
      resolveTarget: async (tid) => targets.get(tid) ?? null,
      resolveCredential: async () => dead2.password,
      keyDir: join(workDir, `keys-${id}`), hostKeyPolicy: 'accept-new',
      agentScriptPath: join(ROOT, 'agent', 'bootstrap.sh'),
    });
  };
  const breakClient = (tr, id) => {
    const s = tr.sessions.get(id);
    s.client = { exec: (_cmd, cb) => cb(Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' })) };
    return s;
  };

  // B-1：transport 层 —— 坏通道应被归为 error，并把会话标成 detached
  const lt2 = mkTransport('t_silent');
  await lt2.connect(targets.get('t_silent'));
  assert((await lt2.heartbeat('t_silent')).ok, '桩替换前的第一次心跳应成功');
  breakClient(lt2, 't_silent');
  const silent = await lt2.heartbeat('t_silent');
  assert(!silent.ok, '静默死亡必须被心跳发现');
  eq(silent.reason, 'error', `应归类为 error，实际 ${silent.reason}`);
  eq(lt2.state('t_silent'), 'detached', '★ 静默死亡后状态必须变成 detached（不留假象）');
  eq(silent.consecutiveFailures, undefined,
    'transport 层不该提供 consecutiveFailures（那是引擎层的统计职责）');

  // B-2：引擎层 —— 同一个坏 transport 上，连续失败计数与"最初失败原因"的记忆
  const lt3 = mkTransport('t_silent2');
  await lt3.connect(targets.get('t_silent2'));
  assert((await lt3.heartbeat('t_silent2')).ok, '桩替换前的第一次心跳应成功');
  breakClient(lt3, 't_silent2');

  const silentEngine = createEngine({
    dir: join(workDir, 'state-silent'),
    catalogDir: join(workDir, 'catalog'),
    transport: lt3,
  });
  const e1 = await silentEngine.heartbeat('t_silent2');
  const e2 = await silentEngine.heartbeat('t_silent2');
  eq(e1.consecutiveFailures, 1, '引擎层第 1 次失败应记 1');
  eq(e1.reason, 'error', '★ 第 1 次探测时链路还在（只是坏了），原因就是 error');
  eq(e1.lastFailure?.reason, 'error', '首次失败应记入失败原因');
  eq(e2.consecutiveFailures, 2, '引擎层第 2 次失败应累计到 2');
  // 第 2 次探测时会话已被上一次失败拆掉，transport 只能如实说 no-session ——
  // 但**断线原因不能因此丢失**，否则"它为什么掉了"就永远答不上来。
  eq(e2.reason, 'no-session', '会话已被拆掉后再探测，如实报 no-session');
  eq(e2.lastFailure?.reason, 'error', '★ 最初的真实失败原因必须被记住');
  eq(silentEngine.lastHeartbeat('t_silent2').lastFailure?.reason, 'error', 'lastHeartbeat 同样查得到最初原因');

  // B-3「恢复」不在这里测：要断言"恢复后不残留旧故障"，必须让心跳真正跑在**真实通道**上，
  //   否则只是在验证我自己写的桩（本项目已经栽过这个跟头，见 ISSUES.md §10.4）。
  //   真实恢复路径由下一个用例用**真连接**覆盖（那里先注入失败、再换回真 client）。

  lt2.disposeAll();
  lt3.disposeAll();
  localTransport.disposeAll();
  await dead2.stop();
  return [
    `干净断开：心跳报 ${cleanCase}`,
    `静默死亡：transport 报 reason=${silent.reason} 并把状态变为 detached（这才是心跳的价值所在）`,
    `分层：transport 只报事实，引擎负责计数与原因记忆`
      + `（累计 ${e2.consecutiveFailures} 次，最初原因仍为 ${e2.lastFailure.reason}）`,
  ];
});

await check('heartbeat', '引擎层记录心跳统计，并在状态变化时写审计（不淹没日志）', async () => {
  const catDir = join(workDir, 'catalog');
  const engine = createEngine({ dir: join(workDir, 'state3'), catalogDir: catDir, transport });
  await engine.addTarget(harnessTargetInput(harness, { id: 't_harness' }));
  await transport.connect(targets.get('t_harness'));

  const before = engine.audit.total;
  const r1 = await engine.heartbeat('t_harness');
  assert(r1.ok, '心跳应成功');
  const afterFirst = engine.audit.total;
  assert(afterFirst > before, '首次心跳（状态变化 无→有）应写一条审计');

  const r2 = await engine.heartbeat('t_harness');
  const r3 = await engine.heartbeat('t_harness');
  const afterThird = engine.audit.total;
  eq(afterThird, afterFirst, '连续成功的心跳**不应**每次都写审计（否则日志会被淹没）');

  // 从失败恢复时应该记一条
  const session = transport.sessions.get('t_harness');
  const realClient = session.client;
  session.client = { exec: (_c, cb) => cb(new Error('injected')) };
  const failed = await engine.heartbeat('t_harness');
  const afterFail = engine.audit.total;
  assert(afterFail > afterThird, '首次失败应写一条审计');
  eq(failed.consecutiveFailures, 1, '连续失败计数应为 1');

  const stillFailing = await engine.heartbeat('t_harness');
  eq(engine.audit.total, afterFail, '持续失败的第 2 次不该再写（每 10 次才记一条摘要）');
  eq(stillFailing.consecutiveFailures, 2, '计数应继续累计');

  session.client = realClient;
  session.state = 'connected';
  const recovered = await engine.heartbeat('t_harness');
  assert(recovered.ok, '恢复后应成功');
  assert(engine.audit.total > afterFail, '从失败恢复应写一条审计');
  eq(recovered.consecutiveFailures, 0, '成功应清零连续失败计数');
  eq(recovered.lastFailure, null, '恢复后不应再挂着旧故障（历史在审计里）');

  const last = engine.lastHeartbeat('t_harness');
  eq(last.ok, true, 'lastHeartbeat 应可查询');
  return `成功心跳只记首次；失败记第 1 次、第 2 次不记；恢复时再记一条 —— 日志不会被淹没`;
});

// ═══════════════════════════════════════════════════════════════════════════
console.log('\n[8] M2：verify 真执行 / 运行记录落盘 / 取消贯通（全部走真实 SSH）');

await check('m2', '★ verify 在真实协议上真的跑了，并把结论落进运行记录', async () => {
  const catDir = join(workDir, 'catalog-m2');
  mkdirSync(catDir, { recursive: true });
  cpSync(join(ROOT, 'packages/catalog/actions'), catDir, { recursive: true });

  // 两个测试动作：一个"应该达标"、一个"按声明就不该达标"。
  // 用 probe=none（它真的会去连接一次），因此在真实协议上也是真探测 —— 不是空跑。
  const mkAction = (id, expect) => ({
    id, version: 1, side: 'agent',
    title: { zh: 'M2 校验测试' }, summary: '验证 verify 阶段真的执行',
    risk: 'R1',
    params: { type: 'object', properties: {}, additionalProperties: false },
    requires: { root: false, distros: [], binaries: [] },
    idempotent: true, timeoutMs: 20000,
    check: { probe: 'none' },
    apply: { default: { cmd: [['echo', 'changed']] } },
    verify: { probe: 'none', expect },
  });
  writeFileSync(join(catDir, 'm2.ok.json'), JSON.stringify(mkAction('m2.ok', { reachable: true }), null, 2), 'utf8');
  writeFileSync(join(catDir, 'm2.bad.json'), JSON.stringify(mkAction('m2.bad', { reachable: false }), null, 2), 'utf8');
  // 声明了一个**未实现**的探测：必须如实说"未实现"，不能假装通过
  writeFileSync(join(catDir, 'm2.noprobe.json'), JSON.stringify({
    ...mkAction('m2.noprobe', { whatever: true }),
    verify: { probe: 'not.implemented', expect: { whatever: true } },
  }, null, 2), 'utf8');
  // 预演动作：dryRun 时不该做目标态校验
  writeFileSync(join(catDir, 'm2.dry.json'), JSON.stringify({
    ...mkAction('m2.dry', { reachable: true }),
    params: {
      type: 'object',
      properties: { dryRun: { type: 'boolean', default: false } },
      additionalProperties: false,
    },
    apply: { default: { cmd: [['echo', 'real']], dryRun: [['echo', 'simulated']] } },
  }, null, 2), 'utf8');

  const engine = createEngine({
    dir: join(workDir, 'state-m2'), catalogDir: catDir, transport,
  });
  // 传输层走它自己的目标映射表，引擎侧也有一份 —— 两边都登记，
  // 避免"引擎认为有目标、传输层说没有"这种只在特定路径上暴露的不一致
  targets.set('t_m2', harnessTarget(harness, { id: 't_m2', label: 'm2' }));
  await engine.addTarget(harnessTargetInput(harness, { id: 't_m2' }));

  // ① 达标：apply 成功 → verify 真跑 → satisfied=true
  const okPlan = await engine.planAction({ targetId: 't_m2', actionId: 'm2.ok' });
  eq(okPlan.blocked, false, `不应被阻断：${okPlan.blockedReason}`);
  const ok = await engine.applyPlan(okPlan);
  eq(ok.exit, 0, '远端退出码');
  eq(ok.verify.satisfied, true, '★ verify 应判定为达标');
  eq(ok.verify.probed, true, '探测应真的执行');
  assert(ok.run?.path && existsSync(ok.run.path), '运行记录文件应存在');
  const okText = readFileSync(ok.run.path, 'utf8');
  assert(okText.includes('达到目标态'), '运行记录里应写明校验结论');
  assert(okText.includes('changed'), '运行记录里应含真实远端输出');

  // ② 不达标：命令成功 ≠ 达到目标态
  const badPlan = await engine.planAction({ targetId: 't_m2', actionId: 'm2.bad' });
  const bad = await engine.applyPlan(badPlan);
  eq(bad.exit, 0, '命令本身仍然成功');
  eq(bad.verify.satisfied, false, '★ 声明与实际不符时必须报"未达标"');
  assert(readFileSync(bad.run.path, 'utf8').includes('未达到目标态'), '运行记录里应标出未达标');

  // ③ 未实现的探测：probed=false、satisfied=null（不得默认成功）
  const npPlan = await engine.planAction({ targetId: 't_m2', actionId: 'm2.noprobe' });
  const np = await engine.applyPlan(npPlan);
  eq(np.verify.probed, false, '未实现的探测必须如实报告');
  eq(np.verify.satisfied, null, '无法判定就是 null，不是 true');

  // ④ 预演：跳过目标态校验并说明原因
  const dryPlan = await engine.planAction({ targetId: 't_m2', actionId: 'm2.dry', params: { dryRun: true } });
  eq(dryPlan.dryRunApplied, true, 'dryRun 应生效');
  const dry = await engine.applyPlan(dryPlan);
  eq(dry.verify.skipped, true, '预演不做目标态校验');
  eq(String(dry.stdout).trim(), 'simulated', '预演应跑 dryRun 分支');

  // ⑤ 审计里只有引用与摘要，没有输出正文
  const runEvent = engine.audit.snapshot().filter((e) => e.event === 'action.run').pop();
  assert(String(runEvent.runPath).startsWith('runs/'), `审计应记运行记录引用，实际 ${runEvent.runPath}`);
  assert(!JSON.stringify(runEvent).includes('changed'), '★ 审计正文里不得出现命令输出');
  assert(engine.verifyRunSeal({ runId: ok.runId, sha256: ok.run.sha256 }).ok, '运行记录封章应可核对');

  return [
    `达标：satisfied=${ok.verify.satisfied}（探测 ${ok.verify.probe}，${ok.verify.attempts} 次）`,
    `未达标：satisfied=${bad.verify.satisfied}（命令 exit=${bad.exit} 仍为成功 —— 两件事分开报）`,
    `未实现的探测：probed=${np.verify.probed} satisfied=${np.verify.satisfied}（不假装通过）`,
    `预演：verify.skipped=${dry.verify.skipped}（${dry.verify.reason}）`,
    `运行记录：${ok.run.relPath}（${ok.run.bytes} 字节），审计仅留 sha256=${String(ok.run.sha256).slice(0, 12)}…`,
  ];
});

await check('m2', '★ 取消贯通到真实 SSH：中断后远端命令不再继续，连接仍可用', async () => {
  const cancelTarget = harnessTarget(harness, { id: 't_cancel', label: 'cancel' });
  targets.set('t_cancel', cancelTarget);
  const tr = createSshTransport({
    resolveTarget: async (id) => targets.get(id) ?? null,
    resolveCredential: async () => harness.password,
    keyDir: join(workDir, 'keys-cancel'), hostKeyPolicy: 'accept-new',
    agentScriptPath: join(ROOT, 'agent', 'bootstrap.sh'),
  });
  await tr.connect(cancelTarget);

  // ── 断言窗口必须"跨过命令自身的完成时刻"，否则证明不了任何事 ────────────────
  //
  // ⚠️ 这里踩过一次**假阳性**：最初远端命令写成 `sleep 20; echo done > marker`，
  //    而我在 abort 之后只等 4 秒就断言 marker **不存在** —— 那条命令本来也要 20 秒才写 marker，
  //    所以这个断言**恒真**，与"取消有没有生效"毫无关系。
  //    更糟的是同一次实现里还出过一个**真**错误被这个假断言遮住：
  //    "直接 reject + 异步关通道"会让 close 先到并把结果 resolve 成**成功**（错误码为空）。
  //    现在改成：命令只需 3 秒，abort 后**等够 4.5 秒**再看 —— 这才是有意义的窗口。
  const marker = `/tmp/vmprobe-cancel-${Date.now()}.marker`;
  await tr.exec(cancelTarget, ['rm', '-f', marker]);
  const controller = new AbortController();

  const plan = {
    targetId: cancelTarget.id,
    resolvedArgv: [['sh', '-c', `sleep 3; echo done > ${marker}`]],
    timeoutMs: 60000,
  };

  const startedAt = Date.now();
  const running = tr.apply(plan, { signal: controller.signal });
  setTimeout(() => controller.abort(new Error('用户中断，测试用')), 400);

  let err = null;
  try {
    await running;
  } catch (e) {
    err = e;
  }
  const elapsed = Date.now() - startedAt;

  assert(err !== null, '取消后 apply 必须抛错，而不是假装成功（★ 曾经真的报成成功过）');
  eq(err.code, 'aborted', `错误码应为 aborted，实际 ${err.code}`);
  assert(elapsed < 10000, `取消应迅速返回（实际 ${elapsed}ms），而不是等命令自己跑完`);

  // 等过命令自身的完成时刻（3s），再看它有没有真的被阻止
  await new Promise((r) => setTimeout(r, 4500));
  const checkRes = await tr.exec(cancelTarget, ['sh', '-c', `test -f ${marker} && echo EXISTS || echo ABSENT`]);
  eq(String(checkRes.stdout).trim(), 'ABSENT', '★ 等过命令完成时刻后，远端命令仍不得跑完');

  // 连接本身仍然可用（取消关的是通道，不是连接）
  const after = await tr.exec(cancelTarget, ['echo', 'still-alive']);
  eq(String(after.stdout).trim(), 'still-alive', '取消后连接应仍然可用');

  // 已经取消的 signal：连命令都不该发出去
  const dead = new AbortController();
  dead.abort();
  let preErr = null;
  try {
    await tr.exec(cancelTarget, ['echo', 'should-not-run'], { signal: dead.signal });
  } catch (e) {
    preErr = e;
  }
  eq(preErr?.code, 'aborted', '已取消的 signal 应立刻拒绝');

  tr.disposeAll();
  return [
    `取消：${err.code} 用时 ${elapsed}ms（命令原本要跑 3s）`,
    `等满 4.5s 后标记文件 ${String(checkRes.stdout).trim()} —— 远端命令确实没有跑完`,
    `连接仍可用：${String(after.stdout).trim()}`,
    '已取消的 signal：立刻拒绝，不发出命令',
    '边界：真正让远端停手的是**关闭通道**（sshd 对会话进程组发 SIGHUP）；'
      + 'TERM 请求多数 sshd 会忽略，因此不能依赖它（见 ISSUES §12.6）',
  ];
});

// ═══════════════════════════════════════════════════════════════════════════
await transport.disposeAll();
await harness.stop();
rmSync(workDir, { recursive: true, force: true });

const ok = results.filter((r) => r.ok).length;
console.log(`\n${failed === 0 ? `全部通过 ✔（${ok} 项）` : `失败 ${failed} 项 ✖（通过 ${ok} 项）`}\n`);
process.exit(failed === 0 ? 0 : 1);
