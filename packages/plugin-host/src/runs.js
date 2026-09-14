/**
 * 运行记录（`runs/`）—— 把一次执行的**完整输出**落盘，审计里只留引用。
 *
 * ── 为什么必须落盘（而不是只留在审计事件里）──────────────────────────────
 * 审计链是**防篡改的台账**，不是日志仓库。把 `apt-get` 的几千行输出塞进审计事件有两个后果：
 *   ① 审计文件会被单次输出撑爆（轮转阈值 8 MiB 一下就满）；
 *   ② 哈希链的价值被稀释 —— 它该记"发生了什么"，不是"命令打印了什么"。
 * 所以审计只记 `{runId, path, sha256, bytes}`：**输出可事后查看，且改动可被检出**。
 *
 * ── 三条纪律 ──────────────────────────────────────────────────────────────
 * 1. **写盘前必须脱敏**。命令输出可能包含密码提示回显、token、连接串 ——
 *    与审计同一套 redactor，不另起一套（否则两处规则必然漂移）。
 * 2. **runId 是文件名的一部分，必须校验**。它是外部可影响的标识，
 *    不校验就等于把路径穿越的口子开在日志目录里（F6 同类）。
 * 3. **超限就截断并明说**。宁可在文件里写一行 `[已截断]`，
 *    也不要悄悄丢掉尾部让人以为"输出就这么长"。
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { sha256Hex } from '../../core/src/index.js';

/** 单次运行记录的落盘上限（超出即截断并标注）。 */
export const MAX_RUN_BYTES = 4 * 1024 * 1024;

/** runId 形状：`r_` + 数字/字母/下划线/连字符。**不含**路径分隔符与点。 */
const RUN_ID_RE = /^r_[A-Za-z0-9_-]{1,64}$/;

export class RunIdError extends Error {
  constructor(runId) {
    super(
      `非法的 runId：${JSON.stringify(runId)}。`
      + '它会被用作文件名，必须匹配 ' + RUN_ID_RE.source + '（拒绝路径分隔符与点）。',
    );
    this.name = 'RunIdError';
    this.code = 'invalid_run_id';
  }
}

export function assertSafeRunId(runId) {
  if (typeof runId !== 'string' || !RUN_ID_RE.test(runId)) throw new RunIdError(runId);
  return runId;
}

/** 生成一个 runId：`r_<UTC 紧凑时间>_<6 位随机>`（字典序即时间序）。 */
export function newRunId(now = new Date(), rand = Math.random) {
  const compact = now.toISOString().slice(0, 19).replace(/[-:]/g, '');  // 20260914T120000
  const suffix = Math.floor(rand() * 0xffffff).toString(16).padStart(6, '0');
  return `r_${compact}_${suffix}`;
}

/** 运行记录的绝对路径。 */
export function runPath(root, runId) {
  assertSafeRunId(runId);
  return join(root, 'runs', `${runId}.log`);
}

/**
 * 把一次执行渲染成可读文本。
 *
 * 刻意**不写时间戳以外的任何环境信息**，也**不写凭据** ——
 * `redactor` 会再过一遍（双保险，见 DESIGN §7 的两道脱敏关口）。
 *
 * @param {object} o
 * @param {string} o.runId
 * @param {object} o.plan 计划（含 actionId/targetId/risk/resolvedArgv）
 * @param {object} [o.result] 传输层/处理器的返回值
 * @param {object} [o.verify] 校验结果（M2-①）
 * @param {string} [o.startedAt] ISO 时间
 * @param {string} [o.finishedAt] ISO 时间
 * @param {number|null} [o.exit]
 * @param {object} [o.redactor]
 * @param {string} [o.error] 失败原因（有则一并落盘 —— 失败更需要事后复盘）
 */
export function renderRun({ runId, plan, result = null, verify = null, startedAt = null, finishedAt = null, exit = null, error = null, redactor = null }) {
  const lines = [];
  const put = (s = '') => lines.push(s);
  const safe = (s) => (redactor?.text ? redactor.text(String(s)) : String(s));

  put('================ VMProbe 运行记录 ================');
  put(`runId     : ${runId}`);
  put(`动作      : ${plan?.actionId ?? '?'}（v${plan?.actionVersion ?? '?'}，side=${plan?.side ?? '?'}）`);
  put(`目标      : ${plan?.targetLabel ?? plan?.targetId ?? '?'}（${plan?.targetId ?? '?'}）`);
  put(`风险级    : ${plan?.risk ?? '?'}${plan?.escalatedBy?.length ? `（提权：${plan.escalatedBy.join('、')}）` : ''}`);
  put(`发行版分支: ${plan?.distroKey ?? '?'}`);
  put(`开始      : ${startedAt ?? '?'}`);
  put(`结束      : ${finishedAt ?? '?'}`);
  put(`退出码    : ${exit === null || exit === undefined ? '（无）' : exit}`);

  if (plan?.params && Object.keys(plan.params).length) {
    put(`参数      : ${JSON.stringify(plan.params)}`);
  }

  if (plan?.resolvedArgv?.length) {
    put('');
    put('---------------- 将要执行的命令 ----------------');
    plan.resolvedArgv.forEach((argv, i) => put(`  [${i + 1}] ${argv.join(' ')}`));
  }

  if (error) {
    put('');
    put('---------------- 错误 ----------------');
    put(`  ${safe(error)}`);
  }

  const steps = result?.steps ?? [];
  if (steps.length) {
    put('');
    put('---------------- 逐步输出 ----------------');
    steps.forEach((s, i) => {
      put(`  ── [${i + 1}/${steps.length}] $ ${(s.argv ?? []).join(' ')}`);
      put(`     exit=${s.exit}${s.truncated ? '（输出已按上限截断）' : ''}`);
      for (const line of String(s.stdout ?? '').split('\n')) if (line !== '') put(`     | ${safe(line)}`);
      for (const line of String(s.stderr ?? '').split('\n')) if (line !== '') put(`     ! ${safe(line)}`);
      if (!String(s.stdout ?? '').trim() && !String(s.stderr ?? '').trim()) put('     （无输出）');
    });
  } else if (result && !steps.length) {
    // controller 侧动作或短结果：把返回值如实写下来（脱敏后）
    put('');
    put('---------------- 返回值 ----------------');
    put(safe(JSON.stringify(result, null, 2) ?? 'null'));
  }

  if (verify) {
    put('');
    put('---------------- 校验（verify）----------------');
    put(`  探测      : ${verify.probe ?? '?'}${verify.probed === false ? '（未实现）' : ''}`);
    put(`  判定      : ${verify.satisfied === null || verify.satisfied === undefined
      ? '未判定（动作未声明 expect）'
      : (verify.satisfied ? '达到目标态' : '★ 未达到目标态')}`);
    put(`  期望      : ${verify.expect ? JSON.stringify(verify.expect) : '（未声明）'}`);
    put(`  实际      : ${verify.state ? safe(JSON.stringify(verify.state)) : '（未探测）'}`);
    put(`  轮次/耗时 : ${verify.attempts ?? '?'} 次 / ${verify.waitedMs ?? '?'}ms`);
    if (verify.note) put(`  备注      : ${safe(verify.note)}`);
    if (verify.skipped) put(`  已跳过    : ${safe(verify.reason ?? '')}`);
  }

  put('');
  put('================ 记录结束 ================');

  return lines.join('\n');
}

/**
 * 原子写运行记录，返回引用信息（审计里存这个）。
 *
 * @returns {{path: string, relPath: string, sha256: string, bytes: number, truncated: boolean}}
 */
export function persistRun({ root, runId, text, maxBytes = MAX_RUN_BYTES }) {
  assertSafeRunId(runId);
  const runsDir = join(root, 'runs');
  mkdirSync(runsDir, { recursive: true, mode: 0o700 });

  let body = String(text ?? '');
  let truncated = false;
  const buf = Buffer.from(body, 'utf8');
  if (buf.length > maxBytes) {
    truncated = true;
    // 按字节截断后再按字符切一次，避免把一个多字节字符劈成两半
    const head = buf.subarray(0, maxBytes).toString('utf8');
    body = `${head.replace(/\uFFFD$/, '')}\n\n[输出超过 ${maxBytes} 字节上限，已截断 —— 完整输出请调大 maxRunBytes]\n`;
  }
  if (!body.endsWith('\n')) body += '\n';

  const target = runPath(root, runId);
  const tmp = `${target}.tmp-${process.pid}`;
  writeFileSync(tmp, body, { encoding: 'utf8', mode: 0o600 });
  try { chmodSync(tmp, 0o600); } catch { /* Windows 上可能不支持，忽略 */ }
  renameSync(tmp, target);

  const digest = sha256Hex(readFileSync(target, 'utf8'));
  return {
    path: target,
    relPath: `runs/${runId}.log`,
    sha256: digest,
    bytes: statSync(target).size,
    truncated,
  };
}

/** 校验一份运行记录是否与审计里记的 sha256 一致（事后取证用）。 */
export function verifyRunSeal({ root, runId, sha256 }) {
  const target = runPath(root, runId);
  if (!existsSync(target)) return { ok: false, reason: '文件不存在' };
  const actual = sha256Hex(readFileSync(target, 'utf8'));
  return actual === sha256
    ? { ok: true, sha256: actual }
    : { ok: false, reason: `摘要不符：期望 ${sha256}，实际 ${actual}`, expected: sha256, actual };
}
